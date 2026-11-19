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
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
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

struct Instance {
    id: Uuid,
    config: Vec<u8>,
    relay: Vec<u8>,
}

fn render(c: &Config, s: &Secrets, db: &Database, pin: &str) -> Result<Vec<Instance>> {
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
            if db.client_allows(device, id)
                && db
                    .users
                    .get(&device.username)
                    .is_some_and(|account| catalogue.granted(&account.groups, id))
            {
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
        // mtg's access command only parses the config. No background DC list
        // updates, public API or reporting service is enabled in the runtime.
        let mut configuration = format!(
            "bind-to = \"{address}:{}\"\nauto-update = false\nprefer-ip = \"only-ipv4\"\n[secrets]\n",
            inbound.port
        );
        for (alias, secret) in credentials {
            configuration.push_str(&format!("\"{alias}\" = \"{secret}\"\n"));
        }
        configs.push(Instance {
            id,
            config: configuration.into_bytes(),
            relay: serde_json::to_vec(&json!({"spki":pin,"devices":aliases}))?,
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
    let configs = render(c, s, db, pin)?;
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
    for instance in render(c, s, &db, &pin)? {
        store::atomic_write(temp.path(), &instance.config)?;
        let file = temp.path().to_str().context("Path encoding")?;
        host::command(BINARY, &check_args(file)).context("mtproto_config_invalid")?;
    }
    Ok(())
}
