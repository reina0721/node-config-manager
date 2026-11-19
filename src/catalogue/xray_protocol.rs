use super::{Inbound, Protocol, inbound_user, wireguard};
use crate::config::Secrets;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use uuid::Uuid;

const SS_METHOD: &str = "aes-256-gcm";
const SS2022_METHOD: &str = "2022-blake3-aes-128-gcm";

impl Protocol {
    fn core_name(self) -> &'static str {
        match self {
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Shadowsocks | Self::Shadowsocks2022 => "shadowsocks",
            Self::Http => "http",
            Self::Mixed => "mixed",
            Self::Hysteria2 => "hysteria",
            Self::Wireguard => "wireguard",
            _ => "vless",
        }
    }

    fn needs_password_account(self) -> bool {
        matches!(self, Self::Http | Self::Mixed)
    }
}

fn derive(secrets: &Secrets, id: Uuid, device: Uuid, purpose: &[u8]) -> Uuid {
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        secrets.reality_private_key.as_bytes(),
    );
    let mut context = ring::hmac::Context::with_key(&key);
    context.update(purpose);
    context.update(id.as_bytes());
    context.update(device.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&context.sign().as_ref()[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

fn server_psk(secrets: &Secrets, id: Uuid) -> String {
    STANDARD.encode(derive(secrets, id, Uuid::nil(), b"nodectl/ss2022/server").as_bytes())
}

pub(super) fn redactions(secrets: &Secrets, id: Uuid, protocol: Protocol) -> Vec<String> {
    if protocol.core_name() == "vless" {
        return Vec::new();
    }
    let key = derive(secrets, id, Uuid::nil(), b"nodectl/locked/protocol");
    if protocol == Protocol::Wireguard {
        vec![wireguard::key_for_redaction(secrets, id)]
    } else if protocol == Protocol::Shadowsocks2022 {
        vec![STANDARD.encode(key.as_bytes()), server_psk(secrets, id)]
    } else {
        vec![key.to_string()]
    }
}

fn user(protocol: Protocol, key: Uuid, alias: &str) -> Value {
    match protocol {
        Protocol::Vmess => json!({"id":key, "email":alias, "alterId":0}),
        Protocol::Trojan => json!({"password":key, "email":alias}),
        Protocol::Shadowsocks => json!({"method":SS_METHOD, "password":key, "email":alias}),
        Protocol::Shadowsocks2022 => {
            json!({"password":STANDARD.encode(key.as_bytes()), "email":alias})
        }
        Protocol::Hysteria2 => json!({"auth":key, "email":alias}),
        Protocol::Http | Protocol::Mixed => json!({"user":alias, "pass":key}),
        _ => unreachable!("VLESS uses its own settings template"),
    }
}

pub(super) fn configure_inbound(entry: &mut Value, inbound: &Inbound, id: Uuid, secrets: &Secrets) {
    let protocol = inbound.protocol;
    if protocol.core_name() == "vless" {
        return;
    }
    entry["protocol"] = json!(protocol.core_name());
    if protocol.needs_password_account() {
        entry["streamSettings"]["tlsSettings"]["alpn"] = json!(["http/1.1"]);
    }
    let placeholder = derive(secrets, id, Uuid::nil(), b"nodectl/locked/protocol");
    if protocol == Protocol::Wireguard {
        entry["settings"] = wireguard::inbound(secrets, id, placeholder);
        return;
    }
    let identity = user(protocol, placeholder, "nodectl-locked");
    let mut settings = match protocol {
        Protocol::Shadowsocks => json!({"network":"tcp,udp"}),
        Protocol::Shadowsocks2022 => {
            json!({"method":SS2022_METHOD, "password":server_psk(secrets,id), "network":"tcp,udp"})
        }
        Protocol::Mixed => json!({"auth":"password","udp":true}),
        Protocol::Hysteria2 => json!({"version":2}),
        _ => json!({}),
    };
    settings[if protocol.needs_password_account() {
        "accounts"
    } else {
        "clients"
    }] = json!([identity]);
    entry["settings"] = settings;
}

pub(crate) fn replace_accounts(
    entry: &mut Value,
    managed: Option<(Uuid, &Inbound)>,
    secrets: &Secrets,
    accounts: impl IntoIterator<Item = (Uuid, String)>,
) -> Result<()> {
    let protocol = managed.map_or(Protocol::Vless, |(_, inbound)| inbound.protocol);
    ensure!(
        entry["protocol"] == protocol.core_name(),
        "Unexpected managed core protocol"
    );
    if protocol == Protocol::Wireguard {
        let (id, _) = managed.context("Missing WireGuard resource")?;
        let peers = accounts
            .into_iter()
            .map(|(device, alias)| wireguard::peer(secrets, id, device, &alias))
            .collect::<Vec<_>>();
        let mut assigned = std::collections::BTreeSet::new();
        ensure!(
            peers
                .iter()
                .flat_map(|peer| peer["allowedIPs"].as_array().unwrap())
                .all(|address| assigned.insert(address.as_str().unwrap())),
            "Duplicate WireGuard address allocation"
        );
        entry["settings"]["peers"] = json!(peers);
        return Ok(());
    }
    let original = entry["settings"]["clients"][0].clone();
    let accounts = accounts
        .into_iter()
        .map(|(device, alias)| {
            if protocol.core_name() == "vless" {
                let id = managed.map_or(device, |(id, inbound)| inbound_user(id, inbound, device));
                let mut entry = original.clone();
                entry["id"] = json!(id);
                entry["email"] = json!(alias);
                entry
            } else {
                let (id, _) = managed.expect("a custom protocol must have a managed inbound");
                let key = derive(secrets, id, device, b"nodectl/device/protocol");
                user(protocol, key, &alias)
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        !accounts.is_empty(),
        "Managed listener must have a protected health identity"
    );
    entry["settings"][if protocol.needs_password_account() {
        "accounts"
    } else {
        "clients"
    }] = json!(accounts);
    Ok(())
}

pub(super) fn client(
    outbound: &mut Value,
    inbound: &Inbound,
    id: Uuid,
    secrets: &Secrets,
    device: Uuid,
    alias: &str,
) -> Result<()> {
    let protocol = inbound.protocol;
    if protocol.core_name() == "vless" {
        return Ok(());
    }
    let key = derive(secrets, id, device, b"nodectl/device/protocol");
    let server = &outbound["settings"]["vnext"][0];
    let address = server["address"]
        .as_str()
        .context("Missing core endpoint")?;
    let port = server["port"]
        .as_u64()
        .context("Missing core endpoint port")?;
    let settings = match protocol {
        Protocol::Vmess => json!({"address":address,"port":port,"id":key,"security":"auto"}),
        Protocol::Trojan => json!({"address":address,"port":port,"password":key}),
        Protocol::Shadowsocks => {
            json!({"address":address,"port":port,"method":SS_METHOD,"password":key})
        }
        Protocol::Shadowsocks2022 => json!({"address":address,"port":port,"method":SS2022_METHOD,
            "password": format!("{}:{}",server_psk(secrets,id),STANDARD.encode(key.as_bytes()))}),
        Protocol::Http | Protocol::Mixed => {
            json!({"address":address,"port":port,"user":alias,"pass":key})
        }
        Protocol::Hysteria2 => json!({"address":address,"port":port,"version":2}),
        Protocol::Wireguard => wireguard::outbound(secrets, id, device, address, port),
        _ => unreachable!("VLESS uses its own settings template"),
    };
    if protocol == Protocol::Hysteria2 {
        outbound["streamSettings"]["hysteriaSettings"] = json!({"version":2,"auth":key});
    } else if protocol.needs_password_account() {
        outbound["streamSettings"]["tlsSettings"]["alpn"] = json!(["http/1.1"]);
        outbound["streamSettings"]["tlsSettings"]
            .as_object_mut()
            .expect("password proxy requires TLS")
            .remove("fingerprint");
    }
    outbound["settings"] = settings;
    outbound["protocol"] = json!(if protocol == Protocol::Mixed {
        "socks"
    } else {
        protocol.core_name()
    });
    Ok(())
}
