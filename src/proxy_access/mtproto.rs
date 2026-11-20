//! A pinned mtg process decodes MTProto and sends only authenticated,
//! per-device Telegram connections through the shared Rust gateway.
use super::{Access, Database, runtime};
use crate::{
    catalogue::{self, Protocol},
    config::{Config, Secrets},
    host,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::TcpListener,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};
use uuid::Uuid;

pub(crate) const BINARY: &str = "/usr/local/bin/nodectl-mtg";
pub(super) const INDEX: &str = "/run/nodectl-proxy-access/mtproto.json";

pub(crate) fn active(c: &Config) -> bool {
    c.management
        .iter()
        .flat_map(|m| m.active_inbounds())
        .any(|(_, i)| i.protocol == Protocol::Mtproto)
}

pub(crate) fn verify_binary() -> Result<()> {
    host::trusted_binary(Path::new(BINARY)).context("mtproto_runtime_missing")?;
    ensure!(
        store::file_digest(Path::new(BINARY))? == crate::artifacts::component_digest("mtg-multi")?,
        "mtproto_runtime_invalid"
    );
    Ok(())
}

fn secret(s: &Secrets, id: Uuid, device: Uuid, name: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, s.reality_private_key.as_bytes());
    let mut mac = ring::hmac::Context::with_key(&key);
    mac.update(b"nodectl/mtproto/device");
    mac.update(id.as_bytes());
    mac.update(device.as_bytes());
    format!(
        "ee{}{}",
        hex::encode(&mac.sign().as_ref()[..16]),
        hex::encode(name)
    )
}

pub(crate) fn link_profiles(
    c: &Config,
    s: &Secrets,
    device: Uuid,
    groups: &std::collections::BTreeSet<Uuid>,
) -> Vec<Value> {
    let Some(catalogue) = &c.management else {
        return Vec::new();
    };
    let now = crate::admin_auth::now();
    catalogue.active_inbounds().filter(|(id, i)| {
        i.protocol == Protocol::Mtproto
            && i.expires.is_none_or(|expires| expires > now)
            && catalogue.granted(groups, *id)
    }).map(|(id, i)| {
        let secret = secret(s, id, device, &c.node.domain);
        json!({"name": format!("{} · {id}", i.remark), "outbound":{
            "protocol":"mtproto","settings":{"address":c.node.domain,"port":i.port,"secret":secret}
        }})
    }).collect()
}

pub(super) fn filenames(id: Uuid) -> (String, String) {
    (
        format!("/run/nodectl-proxy-access/mtg-{id}.toml"),
        format!("/run/nodectl-proxy-access/mtg-{id}.json"),
    )
}

pub(super) fn instances() -> Result<Vec<Uuid>> {
    if !Path::new(INDEX).exists() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_slice(&fs::read(INDEX)?)?)
}

#[derive(Serialize, Deserialize)]
struct Control {
    port: u16,
    token: String,
}

struct Instance {
    id: Uuid,
    config: Vec<u8>,
    relay: Vec<u8>,
}

fn render(
    c: &Config,
    s: &Secrets,
    db: &Database,
    pin: &str,
    controls: &BTreeMap<Uuid, Control>,
) -> Result<Vec<Instance>> {
    let catalogue = c
        .management
        .as_ref()
        .context("No managed MTProto catalogue")?;
    let mut configs = Vec::new();
    for (id, inbound) in catalogue
        .active_inbounds()
        .filter(|(_, i)| i.protocol == Protocol::Mtproto)
    {
        let tag = catalogue::tag(id);
        let mut credentials = BTreeMap::from([(
            "locked-health".to_owned(),
            secret(s, id, db.health_id, &c.node.domain),
        )]);
        let mut aliases = BTreeMap::new();
        for (&profile, device) in &db.devices {
            if db.install_on_inbound(device, catalogue, id) {
                let name = catalogue::device_alias(profile);
                credentials.insert(name.clone(), secret(s, id, profile, &c.node.domain));
                aliases.insert(name, runtime::ingress_id(device.transit, &tag));
            }
        }
        let address = if c.node.ipv6.is_empty() {
            "0.0.0.0"
        } else {
            "[::]"
        };
        // Keep the management listener local and require its per-process
        // bearer credential. The actual Telegram listener retains its address.
        let mut configuration = format!(
            "bind-to = \"{address}:{}\"\nauto-update = false\nprefer-ip = \"only-ipv4\"\n",
            inbound.port
        );
        let control = controls.get(&id);
        if let Some(control) = control {
            configuration.push_str(&format!(
                "api-bind-to = \"127.0.0.1:{}\"\napi-token = \"{}\"\n",
                control.port, control.token
            ));
        }
        configuration.push_str("[secrets]\n");
        for (alias, secret) in credentials {
            configuration.push_str(&format!("\"{alias}\" = \"{secret}\"\n"));
        }
        configs.push(Instance {
            id,
            config: configuration.into_bytes(),
            relay: serde_json::to_vec(&json!({"spki":pin,"devices":aliases,"control":control}))?,
        });
    }
    Ok(configs)
}

pub(super) fn files(
    c: &Config,
    s: &Secrets,
    db: &Database,
    pin: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut controls = BTreeMap::new();
    let mut reserved = Vec::new();
    for (id, _) in c
        .management
        .iter()
        .flat_map(|catalogue| catalogue.active_inbounds())
        .filter(|(_, definition)| definition.protocol == Protocol::Mtproto)
    {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        controls.insert(
            id,
            Control {
                port: listener.local_addr()?.port(),
                token: Uuid::new_v4().simple().to_string(),
            },
        );
        reserved.push(listener);
    }
    let configs = render(c, s, db, pin, &controls)?;
    let index: Vec<_> = configs.iter().map(|instance| instance.id).collect();
    let index = serde_json::to_vec(&index)?;
    let mut files = Vec::new();
    for instance in configs {
        let (config_file, relay_file) = filenames(instance.id);
        files.push((config_file, instance.config));
        files.push((relay_file, instance.relay));
    }
    files.push((INDEX.into(), index));
    Ok(files)
}

pub(super) fn check_args(config: &str) -> [&str; 6] {
    ["access", "--ipv4", "127.0.0.1", "--ipv6", "::1", config]
}

pub(crate) fn check(store: &Store, c: &Config, s: &Secrets) -> Result<()> {
    if !active(c) {
        return Ok(());
    }
    verify_binary()?;
    let db = Access(store)
        .read()?
        .filter(|db| db.enabled)
        .context("managed_inbounds_require_proxy_access")?;
    let pin = runtime::RelayIdentity::load(store)?.spki_pin()?;
    let temp = tempfile::NamedTempFile::new()?;
    for instance in render(c, s, &db, &pin, &BTreeMap::new())? {
        store::atomic_write(temp.path(), &instance.config)?;
        let file = temp.path().to_str().context("Path encoding")?;
        host::command(BINARY, &check_args(file)).context("mtproto_config_invalid")?;
    }
    Ok(())
}

pub(super) fn refresh(c: &Config, s: &Secrets, db: &Database, pin: &str) -> Result<()> {
    let mut controls = BTreeMap::new();
    for id in instances()? {
        let (_, relay) = filenames(id);
        let metadata = fs::symlink_metadata(&relay)?;
        ensure!(
            metadata.file_type().is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "proxy_runtime_unavailable"
        );
        let raw: Value = serde_json::from_slice(&fs::read(&relay)?)?;
        controls.insert(
            id,
            serde_json::from_value::<Control>(raw["control"].clone())
                .context("proxy_runtime_unavailable")?,
        );
    }
    let instances = render(c, s, db, pin, &controls)?;
    ensure!(
        instances.len() == controls.len(),
        "proxy_runtime_unavailable"
    );
    let group = format!("root:{}", c.runtime.nginx_user);
    for instance in instances {
        let control = controls
            .get(&instance.id)
            .context("proxy_runtime_unavailable")?;
        let (config, relay) = filenames(instance.id);
        runtime::write_managed(Path::new(&relay), &instance.relay, &group)?;
        runtime::write_managed(Path::new(&config), &instance.config, &group)?;
        reload(control)?;
    }
    Ok(())
}

fn reload(control: &Control) -> Result<()> {
    ensure!(
        control.port > 1024
            && control.token.len() == 32
            && control.token.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "proxy_runtime_unavailable"
    );
    let url = format!("http://127.0.0.1:{}/reload", control.port);
    let mut child = Command::new("/usr/bin/curl")
        .args([
            "--disable",
            "--config",
            "-",
            "--noproxy",
            "*",
            "--max-time",
            "2",
            "--fail",
            "--silent",
            "--output",
            "/dev/null",
            "--request",
            "POST",
            &url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    writeln!(
        child.stdin.take().context("Missing reload request input")?,
        "header = \"Authorization: Bearer {}\"",
        control.token
    )?;
    ensure!(child.wait()?.success(), "proxy_runtime_update_failed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpStream, process::Child, thread, time::Duration};

    struct Proxy(Child);
    impl Drop for Proxy {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "requires pinned mtg-multi; set NODECTL_ACCESS_TEST_MTG"]
    fn pinned_mtg_reloads_device_secrets_without_restarting() -> Result<()> {
        let binary = std::env::var("NODECTL_ACCESS_TEST_MTG")?;
        let api = TcpListener::bind(("127.0.0.1", 0))?;
        let proxy = TcpListener::bind(("127.0.0.1", 0))?;
        let api_address = api.local_addr()?;
        let address = proxy.local_addr()?;
        drop((api, proxy));

        let control = Control {
            port: api_address.port(),
            token: Uuid::new_v4().simple().to_string(),
        };
        let domain = hex::encode("mtproto-test.invalid");
        let settings = format!(
            "bind-to = \"{address}\"\napi-bind-to = \"{api_address}\"\napi-token = \"{}\"\nauto-update = false\n[secrets]\n",
            control.token,
        );
        let first = format!(
            "{settings}first = \"ee{}{domain}\"\n",
            Uuid::new_v4().simple()
        );
        let second = format!(
            "{first}second = \"ee{}{domain}\"\n",
            Uuid::new_v4().simple()
        );
        let config = tempfile::NamedTempFile::new()?;
        fs::write(config.path(), first)?;
        let mut process = Proxy(
            Command::new(binary)
                .arg("run")
                .arg(config.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        for _ in 0..80 {
            if TcpStream::connect(api_address).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }

        let bad = Control {
            port: control.port,
            token: Uuid::new_v4().simple().to_string(),
        };
        assert!(reload(&bad).is_err());
        fs::write(config.path(), second)?;
        reload(&control)?;
        assert!(process.0.try_wait()?.is_none());
        Ok(())
    }
}
