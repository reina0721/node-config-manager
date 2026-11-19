//! Browser leases authorize device profiles independently of release snapshots.
mod gateway;
mod meter;
mod runtime;
#[cfg(test)]
mod tests;

use crate::{
    admin_auth,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use ring::{
    hmac,
    pbkdf2::{self, PBKDF2_HMAC_SHA256},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    num::NonZeroU32,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub use runtime::{launch, prepare, reserved_port, serve};

const DEFAULT_TTL: u64 = 7 * 24 * 60 * 60;
const MAX_USERS: usize = 4096;
const MAX_DEVICES: usize = 512;
const MAX_LIMIT: u16 = 32;
const ITERATIONS: NonZeroU32 = NonZeroU32::new(600_000).unwrap();

#[derive(Clone, Serialize, Deserialize)]
struct Database {
    enabled: bool,
    ttl_seconds: u64,
    health_id: Uuid,
    users: BTreeMap<String, Account>,
    devices: BTreeMap<Uuid, Device>,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: DEFAULT_TTL,
            health_id: Uuid::new_v4(),
            users: BTreeMap::new(),
            devices: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Account {
    salt: [u8; 32],
    password_hash: [u8; 32],
    device_limit: u16,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    groups: BTreeSet<Uuid>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    disabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quota_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ledger: Option<Uuid>,
}

impl Account {
    fn new(password: &str, device_limit: u16) -> Result<Self> {
        ensure!(
            (6..=256).contains(&password.len()),
            "invalid_proxy_password"
        );
        check_limit(device_limit)?;
        let salt: [u8; 32] = rand::random();
        let mut password_hash = [0u8; 32];
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            ITERATIONS,
            &salt,
            password.as_bytes(),
            &mut password_hash,
        );
        Ok(Self {
            salt,
            password_hash,
            device_limit,
            groups: BTreeSet::new(),
            disabled: false,
            expires: None,
            quota_bytes: None,
            ledger: None,
        })
    }
    fn verify(&self, password: &str) -> bool {
        password.len() <= 256
            && pbkdf2::verify(
                PBKDF2_HMAC_SHA256,
                ITERATIONS,
                &self.salt,
                password.as_bytes(),
                &self.password_hash,
            )
            .is_ok()
    }

    fn active(&self, now: u64) -> bool {
        !self.disabled && self.expires.is_none_or(|expiry| expiry > now)
    }

    fn ledger_id(&self) -> Uuid {
        // Existing accounts have a unique salt, even when a username is reused.
        self.ledger
            .unwrap_or_else(|| Uuid::from_slice(&self.salt[..16]).unwrap())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Device {
    username: String,
    label: String,
    transit: Uuid,
    portal: Uuid,
    authenticated: Option<u64>,
    attempts: Vec<u64>,
}

struct Access<'a>(&'a Store);

impl Access<'_> {
    fn dir(&self) -> PathBuf {
        self.0.state_dir.join("proxy-access")
    }
    fn read(&self) -> Result<Option<Database>> {
        let path = self.dir().join("access.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            r => {
                r?;
            }
        }
        store::check_private(&self.dir(), true)?;
        store::check_private(&path, false)?;
        ensure!(
            fs::metadata(&path)?.len() <= 8 * 1024 * 1024,
            "Invalid access database"
        );
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }
    fn write(&self, data: &Database) -> Result<()> {
        store::atomic_write(&self.dir().join("access.json"), &serde_json::to_vec(data)?)
    }
    fn lock(&self) -> Result<fs::File> {
        store::private_dir(&self.0.state_dir)?;
        store::private_dir(&self.dir())?;
        let path = self.dir().join("lock");
        if path.exists() {
            store::check_private(&path, false)?;
        }
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        f.lock_exclusive()?;
        Ok(f)
    }
}

pub fn enabled(store: &Store) -> Result<bool> {
    Ok(Access(store).read()?.is_some_and(|data| data.enabled))
}

pub fn health_id(store: &Store) -> Result<Option<Uuid>> {
    Ok(Access(store)
        .read()?
        .filter(|data| data.enabled)
        .map(|data| data.health_id))
}

fn check_username(username: &str) -> Result<()> {
    ensure!(
        (1..=64).contains(&username.len())
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b)),
        "invalid_proxy_username"
    );
    Ok(())
}

fn check_limit(n: u16) -> Result<()> {
    ensure!((1..=MAX_LIMIT).contains(&n), "invalid_proxy_device_limit");
    Ok(())
}

fn default_limit() -> u16 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    username: String,
    password: String,
    #[serde(default = "default_limit")]
    device_limit: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    username: String,
    #[serde(default = "default_limit")]
    device_limit: u16,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Change {
    Settings {
        enabled: bool,
        ttl_seconds: u64,
    },
    Create {
        users: Vec<Create>,
    },
    Import {
        users: Vec<Import>,
    },
    Delete {
        usernames: Vec<String>,
    },
    Edit {
        username: String,
        device_limit: u16,
        password: Option<String>,
    },
    Policy {
        username: String,
        disabled: bool,
        expires: Option<u64>,
        quota_bytes: Option<u64>,
    },
    GroupMembers {
        group: Uuid,
        usernames: BTreeSet<String>,
    },
    ResetTraffic {
        username: String,
    },
    CreateDevice {
        username: String,
        label: String,
    },
    DeleteDevice {
        device: Uuid,
    },
}

impl Database {
    fn expiry(&self, device: &Device, now: u64) -> Option<u64> {
        let account = self.users.get(&device.username)?;
        if !self.enabled || !account.active(now) {
            return None;
        }
        device
            .authenticated
            .filter(|time| *time <= now)
            .and_then(|time| time.checked_add(self.ttl_seconds))
            .map(|expiry| expiry.min(account.expires.unwrap_or(u64::MAX)))
            .filter(|expiry| *expiry > now)
    }

    fn retain_current_grants(&mut self, now: u64) {
        let ttl = self.ttl_seconds;
        for device in self.devices.values_mut() {
            device.authenticated = device
                .authenticated
                .filter(|time| *time <= now && now - time < ttl);
        }
    }

    fn view(&self, store: &Store, portal: &str) -> Result<Value> {
        let now = admin_auth::now();
        let online = meter::Online::read(store, now);
        let users = self.users.iter().map(|(username, account)| {
            let usage = meter::read(store, account.ledger_id())?;
            let available = account.quota_bytes.is_none_or(|quota| usage.total() < quota);
            Ok(json!({
                "username":username, "device_limit":account.device_limit,
                "groups":account.groups, "disabled":account.disabled, "expires":account.expires,
                "quota_bytes":account.quota_bytes, "traffic":usage,
                "devices":self.devices.iter().filter(|(_, device)| &device.username == username)
                    .map(|(id, device)| {
                        let expires = if available { self.expiry(device, now) } else { None };
                        json!({"id":id,"label":device.label,"expires":expires,
                            "connections": if expires.is_some() { online.get(id).copied().unwrap_or(0) } else { 0 }})
                    })
                    .collect::<Vec<_>>()
            }))
        }).collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"enabled":self.enabled, "ttl_seconds":self.ttl_seconds, "portal":portal, "users":users,
                "extra_profile_formats":["xray-config","links","qr","native"]}),
        )
    }

    fn export(&self) -> Value {
        json!(
            self.users
                .iter()
                .map(|(username, account)| json!({
                    "username":username,"device_limit":account.device_limit
                }))
                .collect::<Vec<_>>()
        )
    }

    fn add_users(&mut self, rows: Vec<(&str, &str, u16)>) -> Result<()> {
        ensure!(!rows.is_empty() && rows.len() <= 50, "invalid_proxy_batch");
        let mut names = BTreeSet::new();
        for (name, password, limit) in &rows {
            check_username(name)?;
            check_limit(*limit)?;
            ensure!(
                (6..=256).contains(&password.len()),
                "invalid_proxy_password"
            );
            ensure!(
                names.insert(*name) && !self.users.contains_key(*name),
                "proxy_user_exists"
            );
        }
        ensure!(
            self.users.len() + rows.len() <= MAX_USERS,
            "invalid_proxy_batch"
        );
        for (name, password, limit) in rows {
            self.users
                .insert(name.into(), Account::new(password, limit)?);
        }
        Ok(())
    }

    fn edit(&mut self, name: &str, limit: u16, password: Option<&str>) -> Result<()> {
        check_limit(limit)?;
        let account = self.users.get_mut(name).context("not_found")?;
        if let Some(password) = password {
            let replacement = Account::new(password, limit)?;
            account.ledger = Some(account.ledger_id());
            account.salt = replacement.salt;
            account.password_hash = replacement.password_hash;
            account.device_limit = limit;
            for device in self.devices.values_mut().filter(|d| d.username == name) {
                device.authenticated = None;
                device.attempts.clear();
            }
        } else {
            account.device_limit = limit;
            let mut devices: Vec<_> = self
                .devices
                .values_mut()
                .filter(|d| d.username == name && d.authenticated.is_some())
                .collect();
            devices.sort_by_key(|d| std::cmp::Reverse(d.authenticated));
            for device in devices.into_iter().skip(usize::from(limit)) {
                device.authenticated = None;
            }
        }
        Ok(())
    }
}

fn portal_url(store: &Store) -> String {
    runtime::installed(store)
        .or_else(|_| store.inputs().map(|(config, _)| config))
        .map(|config| runtime::portal(&config))
        .unwrap_or_default()
}

pub fn list(store: &Store) -> Result<Value> {
    Access(store)
        .read()?
        .unwrap_or_default()
        .view(store, &portal_url(store))
}

pub fn has_account_policies(store: &Store) -> Result<bool> {
    Ok(Access(store).read()?.is_some_and(|db| {
        db.users
            .values()
            .any(|a| a.disabled || a.expires.is_some() || a.quota_bytes.is_some())
    }))
}

pub fn export(store: &Store) -> Result<Value> {
    Ok(Access(store).read()?.unwrap_or_default().export())
}

pub fn change(store: &Store, action: Change, binary: &std::path::Path) -> Result<Value> {
    // Take the lifecycle lock before changing Xray's installed configuration.
    let _host = matches!(
        action,
        Change::Settings { .. } | Change::CreateDevice { .. } | Change::GroupMembers { .. }
    )
    .then(|| store.lock())
    .transpose()?;
    let access = Access(store);
    let lock = access.lock()?;
    let mut data = access.read()?.unwrap_or_default();
    let previous = data.clone();
    data.retain_current_grants(admin_auth::now());
    let mut refresh_xray = false;
    match action {
        Change::Settings {
            enabled,
            ttl_seconds,
        } => {
            ensure!(
                (60..=90 * 86400).contains(&ttl_seconds),
                "invalid_proxy_ttl"
            );
            if enabled != data.enabled {
                if !enabled {
                    ensure!(
                        !crate::catalogue::requires_access(&runtime::installed(store)?),
                        "managed_inbounds_require_proxy_access"
                    );
                    ensure!(
                        data.users
                            .values()
                            .all(|a| !a.disabled && a.expires.is_none() && a.quota_bytes.is_none()),
                        "policies_require_proxy_access"
                    );
                }
                refresh_xray = true;
                runtime::validate(store, binary)?;
                for device in data.devices.values_mut() {
                    device.authenticated = None;
                }
            }
            data.enabled = enabled;
            data.ttl_seconds = ttl_seconds;
        }
        Change::Create { users } => data.add_users(
            users
                .iter()
                .map(|u| (u.username.as_str(), u.password.as_str(), u.device_limit))
                .collect(),
        )?,
        Change::Import { users } => data.add_users(
            users
                .iter()
                .map(|u| (u.username.as_str(), "123456", u.device_limit))
                .collect(),
        )?,
        Change::Delete { usernames } => {
            ensure!(
                !usernames.is_empty() && usernames.len() <= MAX_USERS,
                "invalid_proxy_batch"
            );
            let names: BTreeSet<_> = usernames.into_iter().collect();
            ensure!(
                names.iter().all(|name| data.users.contains_key(name)),
                "not_found"
            );
            data.users.retain(|username, _| !names.contains(username));
            data.devices
                .retain(|_, device| !names.contains(&device.username));
        }
        Change::Edit {
            username,
            device_limit,
            password,
        } => {
            data.edit(&username, device_limit, password.as_deref())?;
        }
        Change::Policy {
            username,
            disabled,
            expires,
            quota_bytes,
        } => {
            ensure!(
                data.enabled || (!disabled && expires.is_none() && quota_bytes.is_none()),
                "policies_require_proxy_access"
            );
            ensure!(quota_bytes != Some(0), "invalid_proxy_quota");
            ensure!(
                expires.is_none_or(|expiry| (1..=253_402_300_799).contains(&expiry)),
                "invalid_proxy_expiry"
            );
            let account = data.users.get_mut(&username).context("not_found")?;
            account.disabled = disabled;
            account.expires = expires;
            account.quota_bytes = quota_bytes;
            for device in data.devices.values_mut().filter(|d| d.username == username) {
                device.authenticated = None;
            }
        }
        Change::GroupMembers { group, usernames } => {
            let config = runtime::installed(store)?;
            ensure!(
                config
                    .management
                    .as_ref()
                    .is_some_and(|m| m.groups.contains_key(&group)),
                "not_found"
            );
            ensure!(
                usernames.iter().all(|name| data.users.contains_key(name)),
                "not_found"
            );
            for (name, account) in &mut data.users {
                let changed = if usernames.contains(name) {
                    account.groups.insert(group)
                } else {
                    account.groups.remove(&group)
                };
                if changed {
                    refresh_xray |= data.enabled;
                    for device in data.devices.values_mut().filter(|d| &d.username == name) {
                        device.authenticated = None;
                    }
                }
            }
            if refresh_xray {
                runtime::validate(store, binary)?;
            }
        }
        Change::ResetTraffic { username } => {
            let account = data.users.get_mut(&username).context("not_found")?;
            account.ledger = Some(Uuid::new_v4());
            for device in data.devices.values_mut().filter(|d| d.username == username) {
                device.authenticated = None;
            }
        }
        Change::CreateDevice { username, label } => {
            ensure!(data.users.contains_key(&username), "not_found");
            ensure!(
                !label.trim().is_empty()
                    && label.len() <= 96
                    && !label.chars().any(char::is_control),
                "invalid_proxy_device"
            );
            ensure!(data.devices.len() < MAX_DEVICES, "invalid_proxy_device");
            data.devices.insert(
                Uuid::new_v4(),
                Device {
                    username,
                    label: label.trim().into(),
                    transit: Uuid::new_v4(),
                    portal: Uuid::new_v4(),
                    authenticated: None,
                    attempts: vec![],
                },
            );
            refresh_xray = data.enabled;
            if refresh_xray {
                runtime::validate(store, binary)?;
            }
        }
        Change::DeleteDevice { device } => {
            data.devices.remove(&device).context("not_found")?;
        }
    }
    let mode_changed = previous.enabled != data.enabled;
    if mode_changed {
        crate::host::command("systemctl", &["stop", "xray"])?;
    }
    let result = (|| {
        // Persist the fail-closed override before recording enablement. The
        // base listener is already stopped if the process loses power here.
        if mode_changed && data.enabled {
            runtime::RelayIdentity::prepare(store)?;
            runtime::install_units(store, binary)?;
        }
        access.write(&data)?;
        if mode_changed {
            runtime::set_mode(data.enabled)?;
        }
        if refresh_xray {
            runtime::restart(store)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        if refresh_xray {
            if mode_changed {
                crate::host::command("systemctl", &["stop", "xray"])?;
                if previous.enabled {
                    runtime::install_units(store, binary)?;
                }
            }
            access.write(&previous)?;
            if mode_changed {
                runtime::set_mode(previous.enabled)?;
            }
            runtime::restart(store).context("Proxy access recovery failed")?;
        }
        return Err(error);
    }
    drop(lock);
    data.view(store, &portal_url(store))
}

pub fn profile(store: &Store, id: Uuid, format: &str) -> Result<String> {
    let _host = store.lock()?;
    let current = store.pointer("current")?.context("not_deployed")?;
    let (config, secrets) = store.verify(&current)?;
    let data = Access(store).read()?.context("not_found")?;
    let device = data.devices.get(&id).context("not_found")?;
    if format == "subscriptions" {
        ensure!(data.enabled && config.distributes(), "not_found");
        let key = crate::share::device_key(store)?;
        let token = subscription_token(&key, id, device);
        let port = config.ports.https;
        let domain = &config.node.domain;
        let origin = if port == 443 {
            format!("https://{domain}")
        } else {
            format!("https://{domain}:{port}")
        };
        return Ok(serde_json::to_string_pretty(&json!({
            "token": token,
            "node_page": format!("{origin}/nodes/"),
            "mihomo": format!("{origin}/nodes/sub/mihomo?token={token}"),
            "mihomo-weighted": format!("{origin}/nodes/sub/mihomo-weighted?token={token}"),
            "xray": format!("{origin}/nodes/sub/xray?token={token}"),
            "browser_login": runtime::portal(&config),
        }))?);
    }
    Ok(String::from_utf8(render_profile(
        store, &config, &secrets, id, format,
    )?)?)
}

fn subscription_token(key: &hmac::Key, id: Uuid, device: &Device) -> String {
    let mut mac = hmac::Context::with_key(key);
    mac.update(b"nodectl-device-subscription-v1");
    mac.update(id.as_bytes());
    mac.update(device.portal.as_bytes());
    let tag = mac.sign();
    format!(
        "{}{suffix}",
        id.simple(),
        suffix = hex::encode(&tag.as_ref()[..16])
    )
}

pub(crate) fn subscription_device(store: &Store, token: &str) -> Result<Option<Uuid>> {
    let mut raw = [0; 32];
    if hex::decode_to_slice(token, &mut raw).is_err() {
        return Ok(None);
    }
    let id = Uuid::from_slice(&raw[..16])?;
    let Some(data) = Access(store).read()?.filter(|data| data.enabled) else {
        return Ok(None);
    };
    let Some(device) = data
        .devices
        .get(&id)
        .filter(|d| data.users.contains_key(&d.username))
    else {
        return Ok(None);
    };
    let Ok(key) = crate::share::device_key(store) else {
        return Ok(None);
    };
    Ok(bool::from(
        subscription_token(&key, id, device)
            .as_bytes()
            .ct_eq(token.as_bytes()),
    )
    .then_some(id))
}

pub(crate) fn render_profile(
    store: &Store,
    config: &crate::config::Config,
    secrets: &crate::config::Secrets,
    id: Uuid,
    format: &str,
) -> Result<Vec<u8>> {
    let data = Access(store).read()?.context("not_found")?;
    let device = data.devices.get(&id).context("not_found")?;
    let account = data.users.get(&device.username).context("not_found")?;
    ensure!(account.active(admin_auth::now()), "not_found");
    let no_groups = BTreeSet::new();
    let groups = if data.enabled {
        &account.groups
    } else {
        &no_groups
    };
    crate::render::device_profiles(
        config,
        secrets,
        id,
        groups,
        format,
        &runtime::portal(config),
    )
}
