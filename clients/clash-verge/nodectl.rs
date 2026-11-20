// SPDX-License-Identifier: GPL-3.0-only
use super::{CmdResult, coded_error, profile::patch_profiles_config_by_profile_index};
use crate::{
    config::{Config, IVerge, PrfItem, PrfOption, profiles_append_item_safe},
    core::timer::Timer,
    feat,
    utils::dirs,
};
use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, Url, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use smartstring::alias::String as SmallString;
use std::{net::IpAddr, path::PathBuf, time::Duration};
use tokio::sync::Mutex;

const PROFILE_PREFIX: &str = "nodectl-";
const SUBSCRIPTION_PATH: &str = "/nodes/sub/mihomo-weighted";
static ENROLLMENT: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapFile {
    nodectl: Bootstrap,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u8,
    origin: String,
    client: String,
    enrollment: String,
    name: String,
}

#[derive(Deserialize, Serialize)]
struct Installation {
    bootstrap: Bootstrap,
    request: String,
    claim: Option<Claim>,
    refreshed_until: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct Claim {
    browser_login: String,
    mihomo: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct Activation {
    state: String,
    expires_at: Option<u64>,
}

fn valid_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn new_request() -> Result<String> {
    let mut data = [0u8; 16];
    getrandom::fill(&mut data).map_err(|_| anyhow::anyhow!("无法生成设备标识。"))?;
    data[6] = (data[6] & 0x0f) | 0x40;
    data[8] = (data[8] & 0x3f) | 0x80;
    let text = data
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    ))
}

impl Bootstrap {
    fn validate(&self) -> Result<Url> {
        ensure!(
            self.version == 1
                && valid_uuid(&self.client)
                && valid_uuid(&self.enrollment)
                && !self.name.is_empty()
                && self.name.len() <= 120
                && !self.name.chars().any(char::is_control),
            "公共配置文件无效或不受此版本支持。"
        );
        let url = https_url(&self.origin)?;
        ensure!(
            url.origin().ascii_serialization() == self.origin,
            "服务地址必须是 HTTPS 源地址。"
        );
        Ok(url)
    }
}

fn https_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("无效的 HTTPS 地址。")?;
    ensure!(
        url.scheme() == "https"
            && url.domain().is_some_and(|host| host.contains('.'))
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "无效的 HTTPS 地址。"
    );
    Ok(url)
}

fn public_ip(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()
                || matches!(a, 0 | 224..)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && matches!(b, 18 | 19)))
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            a & 0xe000 == 0x2000 && !(a == 0x2001 && b == 0x0db8)
        }
    }
}

async fn enrollment_http(origin: &Url) -> Result<Client> {
    let domain = origin.domain().context("服务地址需要域名。")?;
    let port = origin.port_or_known_default().context("无效的服务端口。")?;
    let addresses = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::net::lookup_host((domain, port)),
    )
    .await
    .context("解析服务地址超时。")?
    .context("无法解析服务地址。")?
    .collect::<Vec<_>>();
    ensure!(
        !addresses.is_empty() && addresses.iter().all(|address| public_ip(address.ip())),
        "公共配置文件需要可公开访问的服务地址。"
    );
    Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(domain, &addresses)
        .build()
        .context("无法启动认证客户端。")
}

async fn read_json<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T> {
    let mut result = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("读取服务器响应失败。"))?
    {
        ensure!(result.len() + chunk.len() <= 8192, "服务器返回的数据过大。");
        result.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&result).context("服务器返回了无效的认证响应。")
}

fn record_path(uid: &str) -> Result<PathBuf> {
    ensure!(
        uid.strip_prefix(PROFILE_PREFIX).is_some_and(valid_uuid),
        "无效的 nodectl 配置标识。"
    );
    Ok(dirs::app_home_dir()?.join(format!("{uid}.json")))
}

fn read_record(uid: &str) -> Result<Option<Installation>> {
    match std::fs::read(record_path(uid)?) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("本机登记记录无法读取。")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn save_record(uid: &str, value: &Installation) -> Result<()> {
    use std::io::Write as _;
    let path = record_path(uid)?;
    let temporary = path.with_extension("json.tmp");
    {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
    }
    std::fs::rename(temporary, path)?;
    Ok(())
}

impl Claim {
    fn token(&self) -> Result<&str> {
        let prefix = format!("{SUBSCRIPTION_PATH}?token=");
        let token = self
            .mihomo
            .strip_prefix(&prefix)
            .context("订阅地址无效。")?;
        ensure!(
            token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "设备凭据无效。"
        );
        Ok(token)
    }

    fn validate(&self) -> Result<()> {
        self.token()?;
        let portal = https_url(&self.browser_login)?;
        ensure!(
            portal.path() == "/" && portal.query().is_none(),
            "认证页地址无效。"
        );
        Ok(())
    }
}

pub(super) fn is_bootstrap(data: &str) -> bool {
    data.trim_start().starts_with('{')
        && serde_json::from_str::<serde_json::Value>(data)
            .ok()
            .is_some_and(|value| value.get("nodectl").is_some())
}

async fn confirm_import(origin: &Url) -> bool {
    use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons};
    let (send, receive) = tokio::sync::oneshot::channel();
    crate::core::handle::Handle::app_handle()
        .dialog()
        .message(format!(
            "通过 {} 领取并启用此设备的订阅？",
            origin.origin().ascii_serialization()
        ))
        .title("导入 nodectl 公共配置")
        .buttons(MessageDialogButtons::OkCancelCustom(
            "导入并启用".into(),
            "取消".into(),
        ))
        .show(move |confirmed| {
            let _ = send.send(confirmed);
        });
    receive.await.unwrap_or(false)
}

pub(super) async fn import(data: &str) -> Result<()> {
    ensure!(data.len() <= 4096, "公共配置文件过大。");
    let BootstrapFile { nodectl: bootstrap } =
        serde_json::from_str(data).context("无法读取 nodectl 公共配置文件。")?;
    let origin = bootstrap.validate()?;
    let uid: SmallString = format!("{PROFILE_PREFIX}{}", bootstrap.client).into();
    let _guard = ENROLLMENT.lock().await;
    let mut record = match read_record(&uid)? {
        Some(record) => {
            ensure!(
                record.bootstrap.origin == bootstrap.origin,
                "此客户端此前使用了不同的服务地址。"
            );
            record
        }
        None => {
            if !confirm_import(&origin).await {
                return Ok(());
            }
            let record = Installation {
                bootstrap,
                request: new_request()?,
                claim: None,
                refreshed_until: None,
            };
            save_record(&uid, &record)?;
            record
        }
    };
    issue_claim(&origin, &uid, &mut record).await?;
    sync_profile(&origin, uid, &record).await
}

async fn issue_claim(origin: &Url, uid: &str, record: &mut Installation) -> Result<()> {
    if record.claim.is_none() {
        let http = enrollment_http(&origin).await?;
        let response = http
            .post(origin.join("/nodes/claim/install")?)
            .json(&serde_json::json!({
                "client": record.bootstrap.client, "origin": record.bootstrap.origin,
                "key": record.bootstrap.enrollment, "request": record.request,
            }))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("无法联系 nodectl。请稍后重试同一文件。"))?;
        match response.status().as_u16() {
            200 => {}
            404 => bail!("公共配置文件已失效。请联系管理员。"),
            409 => bail!("此客户端包含无法在线签发的附加入站。请联系管理员。"),
            429 => bail!("领取繁忙。请稍后重试同一文件。"),
            _ => bail!("服务器暂时无法登记设备。请稍后重试同一文件。"),
        }
        let claim: Claim = read_json(response).await?;
        claim.validate()?;
        record.claim = Some(claim);
        save_record(uid, record)?;
    }
    Ok(())
}

async fn sync_profile(origin: &Url, uid: SmallString, record: &Installation) -> Result<()> {
    let claim = record.claim.as_ref().context("缺少本机订阅。")?;
    claim.validate()?;
    let remote: SmallString = origin.join(&claim.mihomo)?.as_str().into();
    let profiles = Config::profiles().await.latest_arc();
    if let Ok(existing) = profiles.get_item(&uid) {
        if existing.url.as_ref() != Some(&remote) {
            crate::config::profiles::profiles_patch_item_safe(
                &uid,
                &PrfItem {
                    url: Some(remote),
                    ..Default::default()
                },
            )
            .await?;
            crate::config::profiles::profiles_save_file_safe().await?;
            feat::update_profile(&uid, None, true)
                .await
                .map_err(|_| anyhow::anyhow!("无法更新本机订阅。可以重试同一配置。"))?;
        }
    } else {
        let name: SmallString = record.bootstrap.name.as_str().into();
        let option = PrfOption {
            with_proxy: Some(false),
            self_proxy: Some(false),
            danger_accept_invalid_certs: Some(false),
            ..Default::default()
        };
        let mut item = PrfItem::from_url(&remote, Some(&name), None, Some(&option))
            .await
            .map_err(|_| anyhow::anyhow!("无法获取本机订阅。请稍后重试同一文件。"))?;
        item.uid = Some(uid.clone());
        item.file = Some(format!("{uid}.yaml").into());
        profiles_append_item_safe(&mut item).await?;
        crate::config::profiles::profiles_save_file_safe().await?;
        let _ = Timer::global().refresh().await;
    }
    let outcome = patch_profiles_config_by_profile_index(uid)
        .await
        .map_err(|_| anyhow::anyhow!("无法启用本机订阅。请稍后重试。"))?;
    ensure!(outcome.is_valid(), "配置校验尚未通过。请稍后重试。");
    Ok(())
}

async fn current_installation() -> Result<Option<(SmallString, Installation)>> {
    let Some(uid) = Config::profiles().await.latest_arc().current.clone() else {
        return Ok(None);
    };
    if !uid.strip_prefix(PROFILE_PREFIX).is_some_and(valid_uuid) {
        return Ok(None);
    }
    Ok(read_record(&uid)?.map(|record| (uid, record)))
}

async fn state() -> Result<Option<String>> {
    let _guard = ENROLLMENT.lock().await;
    let Some((uid, mut record)) = current_installation().await? else {
        return Ok(None);
    };
    let Some(claim) = record.claim.as_ref() else {
        return Ok(Some("enrollment-expired".into()));
    };
    let origin = record.bootstrap.validate()?;
    let response = enrollment_http(&origin)
        .await?
        .get(origin.join("/nodes/claim/status")?)
        .bearer_auth(claim.token()?)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("无法查询认证状态。稍后将自动重试。"))?;
    if response.status().as_u16() == 401 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let state = if record.refreshed_until.is_none() && now >= claim.expires_at {
            "enrollment-expired"
        } else {
            "revoked"
        };
        return Ok(Some(state.into()));
    }
    ensure!(
        response.status().is_success(),
        "认证服务暂时不可用。稍后将自动重试。"
    );
    let activation: Activation = read_json(response).await?;
    if activation.state == "active" && activation.expires_at != record.refreshed_until {
        feat::update_profile(&uid, None, true)
            .await
            .map_err(|_| anyhow::anyhow!("认证成功，配置刷新失败。稍后将自动重试。"))?;
        record.refreshed_until = activation.expires_at;
        save_record(&uid, &record)?;
    }
    Ok(Some(activation.state))
}

#[tauri::command]
#[specta::specta]
pub async fn nodectl_state() -> CmdResult<Option<String>> {
    state()
        .await
        .map_err(|error| coded_error("NODECTL_STATE", error))
}

async fn renew_expired() -> Result<()> {
    let _guard = ENROLLMENT.lock().await;
    let Some((uid, mut record)) = current_installation().await? else {
        return Ok(());
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    ensure!(
        record.refreshed_until.is_none()
            && record
                .claim
                .as_ref()
                .is_none_or(|claim| claim.expires_at <= now),
        "只有尚未激活且已超过有效期的领取可以重试。"
    );
    if record.claim.is_some() {
        record.request = new_request()?;
        record.claim = None;
        save_record(&uid, &record)?;
    }
    let origin = record.bootstrap.validate()?;
    issue_claim(&origin, &uid, &mut record).await?;
    sync_profile(&origin, uid, &record).await
}

#[tauri::command]
#[specta::specta]
pub async fn nodectl_renew_expired() -> CmdResult {
    renew_expired()
        .await
        .map_err(|error| coded_error("NODECTL_RENEW", error))
}

async fn open_login() -> Result<()> {
    let _guard = ENROLLMENT.lock().await;
    let Some((_, record)) = current_installation().await? else {
        return Ok(());
    };
    let claim = record.claim.as_ref().context("缺少本机订阅。")?;
    claim.validate()?;
    let verge = Config::verge().await.latest_arc();
    if !verge.enable_system_proxy.unwrap_or(false) && !verge.enable_tun_mode.unwrap_or(false) {
        feat::patch_verge(
            &IVerge {
                enable_system_proxy: Some(true),
                ..Default::default()
            },
            false,
        )
        .await?;
    }
    open::that_detached(claim.browser_login.as_str())?;
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub async fn nodectl_open_login() -> CmdResult {
    open_login()
        .await
        .map_err(|error| coded_error("NODECTL_LOGIN", error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_public_descriptor_and_isolated_request_ids() -> Result<()> {
        assert_ne!(new_request()?, new_request()?);
        assert!(valid_uuid(&new_request()?));
        assert!(!public_ip("127.0.0.1".parse()?));
        assert!(!public_ip("::ffff:127.0.0.1".parse()?));
        assert!(https_url("https://nodes.example.com/").is_ok());
        assert!(https_url("https://user@nodes.example.com/").is_err());
        assert!(!is_bootstrap("proxies: []"));
        Ok(())
    }
}
