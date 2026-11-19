//! Managed TUIC v5 adapter. User traffic reaches the same metered VLESS relay
//! used by the Xray listeners, with an identity specific to this ingress.
use super::{Access, Database, runtime};
use crate::{
    catalogue::{self, Endpoint, Host, Protocol, Target},
    config::{Config, Secrets},
    host,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::{fs, path::Path};
use uuid::Uuid;

pub(crate) const BINARY: &str = "/usr/local/bin/nodectl-sing-box";
pub(super) const GENERATED: &str = "/run/nodectl-proxy-access/tuic.json";

pub(crate) fn active(config: &Config) -> bool {
    config.management.as_ref().is_some_and(|catalogue| {
        catalogue
            .active_inbounds()
            .any(|(_, inbound)| inbound.protocol == Protocol::Tuic)
    })
}

pub(crate) fn verify_binary() -> Result<()> {
    host::trusted_binary(Path::new(BINARY)).context("tuic_runtime_missing")?;
    ensure!(
        store::file_digest(Path::new(BINARY))? == crate::artifacts::component_digest("sing-box")?,
        "tuic_runtime_invalid"
    );
    Ok(())
}

pub(crate) fn install(store: &Store) -> Result<()> {
    host::linux_root()?;
    let _guard = store.lock()?;
    crate::artifacts::install_component("sing-box", Path::new(BINARY))
}

fn credentials(secrets: &Secrets, inbound: Uuid, device: Uuid) -> (Uuid, String) {
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        secrets.reality_private_key.as_bytes(),
    );
    let mut mac = ring::hmac::Context::with_key(&key);
    mac.update(b"nodectl/tuic-v5/device/");
    mac.update(inbound.as_bytes());
    mac.update(device.as_bytes());
    let digest = mac.sign();
    let id =
        uuid::Builder::from_random_bytes(digest.as_ref()[..16].try_into().unwrap()).into_uuid();
    let password = URL_SAFE_NO_PAD.encode(ring::hmac::sign(&key, digest.as_ref()).as_ref());
    (id, password)
}

pub(crate) fn outbound(
    c: &Config,
    secrets: &Secrets,
    id: Uuid,
    target: Target<'_>,
    host: Option<&Host>,
    endpoint: Option<&Endpoint>,
    device: Uuid,
) -> Value {
    let (user, password) = credentials(secrets, id, device);
    let address = endpoint.map_or(c.node.domain.as_str(), |e| &e.address);
    let port = endpoint.map_or_else(|| target.port(c), |e| e.port);
    let server_name = host
        .filter(|host| !host.sni.is_empty())
        .map_or(c.node.domain.as_str(), |host| &host.sni);
    json!({
        "protocol":"tuic","settings":{"address":address,"port":port,"uuid":user,"password":password},
        "streamSettings":{"security":"tls","network":"tuic","tlsSettings":{"serverName":server_name,"alpn":["h3"]}}
    })
}

pub(crate) fn client(outbound: &Value, socks_port: u16) -> Value {
    let settings = &outbound["settings"];
    json!({
        "log":{"disabled":true},
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],
        "outbounds":[{
            "type":"tuic","tag":"managed","server":settings["address"],"server_port":settings["port"],
            "uuid":settings["uuid"],"password":settings["password"],"udp_relay_mode":"native",
            "tls":{"enabled":true,"server_name":outbound["streamSettings"]["tlsSettings"]["serverName"],"alpn":["h3"]}
        }]
    })
}

type Probe = (String, u16);

pub(super) fn render(
    c: &Config,
    secrets: &Secrets,
    db: &Database,
    probe: &Probe,
    pin: &str,
) -> Result<Value> {
    let catalogue = c.management.as_ref().context("No managed inbounds")?;
    let tls = json!({
        "enabled":true,"alpn":["h3"],"min_version":"1.3",
        "certificate":fs::read_to_string(Path::new(&c.tls.domain_cert_dir).join("fullchain.pem"))?,
        "key":fs::read_to_string(Path::new(&c.tls.domain_cert_dir).join("privkey.pem"))?
    });
    let mut inbounds = Vec::new();
    let mut outbounds = vec![json!({"type":"direct","tag":"health-probe"})];
    let mut rules = Vec::new();
    for (id, inbound) in catalogue
        .active_inbounds()
        .filter(|(_, i)| i.protocol == Protocol::Tuic)
    {
        let tag = catalogue::tag(id);
        let health = |device, name: &str| {
            let (user, password) = credentials(secrets, id, device);
            json!({"name":name,"uuid":user,"password":password})
        };
        let host_id = id.to_string();
        let host_probes = catalogue
            .hosts
            .iter()
            .filter(|(_, host)| host.enabled && host.inbound == host_id)
            .map(|(host, _)| {
                health(
                    catalogue::host_probe_id(db.health_id, *host),
                    &catalogue::host_probe_alias(*host),
                )
            });
        let mut users = vec![health(db.health_id, catalogue::HEALTH_ALIAS)];
        users.extend(host_probes);
        let health_users = users.iter().map(|u| &u["name"]).collect::<Vec<_>>();
        let mut health_rule = json!({
            "inbound":[tag],"auth_user":health_users,"network":"tcp","port":[probe.1],
            "action":"route","outbound":"health-probe"
        });
        if let Ok(ip) = probe.0.parse::<std::net::IpAddr>() {
            health_rule["ip_cidr"] =
                json!([format!("{ip}/{}", if ip.is_ipv6() { 128 } else { 32 })]);
        } else {
            health_rule["domain"] = json!([probe.0]);
        }
        rules.push(health_rule);
        for (device_id, device) in &db.devices {
            if !db.install_on_inbound(device, catalogue, id) {
                continue;
            }
            let name = catalogue::device_alias(*device_id);
            users.push(health(*device_id, &name));
            let relay = format!("{tag}-{name}");
            rules.push(
                json!({"inbound":[tag],"auth_user":[name],"action":"route","outbound":relay}),
            );
            outbounds.push(json!({
                "type":"vless","tag":relay,"server":runtime::GATE.ip().to_string(),
                "server_port":runtime::GATE.port(),"uuid":runtime::ingress_id(device.transit, &tag),
                "packet_encoding":"","tls":{
                    "enabled":true,"min_version":"1.3","certificate_public_key_sha256":[pin]
                }
            }));
        }
        inbounds.push(json!({
            "type":"tuic","tag":tag,"listen":if c.node.ipv6.is_empty() { "0.0.0.0" } else { "::" },
            "listen_port":inbound.port,"users":users,"zero_rtt_handshake":false,"tls":tls
        }));
    }
    rules.push(json!({"action":"reject"}));
    Ok(json!({
        "log":{"disabled":true},"inbounds":inbounds,"outbounds":outbounds,
        "route":{"rules":rules}
    }))
}

pub(crate) fn check_candidate(
    store: &Store,
    c: &Config,
    s: &Secrets,
    reference: &host::Reference,
) -> Result<()> {
    if !active(c) {
        return Ok(());
    }
    verify_binary()?;
    let database = Access(store)
        .read()?
        .filter(|db| db.enabled)
        .context("managed_inbounds_require_proxy_access")?;
    let pin = runtime::RelayIdentity::load(store)?.spki_pin()?;
    let configuration = render(c, s, &database, &host::reference_origin(reference)?, &pin)?;
    let temp = tempfile::NamedTempFile::new()?;
    store::atomic_write(temp.path(), &serde_json::to_vec(&configuration)?)?;
    let filename = temp.path().to_str().context("Path encoding")?;
    host::command(BINARY, &["check", "-c", filename]).context("tuic_config_invalid")?;
    Ok(())
}

pub(super) fn encode_spki(cert: &[u8]) -> Result<String> {
    use sha2::{Digest, Sha256};
    let key = host::run("openssl", &["x509", "-noout", "-pubkey"], Some(cert))?;
    let der = host::run(
        "openssl",
        &["pkey", "-pubin", "-outform", "DER"],
        Some(&key),
    )?;
    Ok(STANDARD.encode(Sha256::digest(der)))
}
