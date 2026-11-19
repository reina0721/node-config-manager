use crate::config::Secrets;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

fn key(secrets: &Secrets, inbound: Uuid, device: Option<Uuid>) -> StaticSecret {
    let seed = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        secrets.reality_private_key.as_bytes(),
    );
    let mut context = ring::hmac::Context::with_key(&seed);
    context.update(b"nodectl/wireguard/");
    context.update(inbound.as_bytes());
    if let Some(device) = device {
        context.update(device.as_bytes());
    }
    let mut raw = [0; 32];
    raw.copy_from_slice(context.sign().as_ref());
    StaticSecret::from(raw)
}

fn public(key: &StaticSecret) -> String {
    STANDARD.encode(PublicKey::from(key).as_bytes())
}

fn tunnel_ips(key: &StaticSecret) -> (Ipv4Addr, Ipv6Addr) {
    let public = PublicKey::from(key);
    let fingerprint = ring::digest::digest(&ring::digest::SHA256, public.as_bytes());
    let raw = fingerprint.as_ref();
    let v4 = Ipv4Addr::new(10, raw[0].max(1), raw[1], raw[2].max(2));
    let mut address = [0; 16];
    address[0] = 0xfd;
    address[1..].copy_from_slice(&raw[3..18]);
    (v4, Ipv6Addr::from(address))
}

pub(super) fn peer(secrets: &Secrets, inbound: Uuid, device: Uuid, alias: &str) -> Value {
    let key = key(secrets, inbound, Some(device));
    let (v4, v6) = tunnel_ips(&key);
    json!({"publicKey":public(&key),"allowedIPs":[format!("{v4}/32"),format!("{v6}/128")],"email":alias})
}

pub(super) fn inbound(secrets: &Secrets, inbound: Uuid, placeholder: Uuid) -> Value {
    json!({
        "secretKey":STANDARD.encode(key(secrets,inbound,None).as_bytes()),
        "address":["10.0.0.1","fd00::1"],
        "mtu":1280,
        "peers":[peer(secrets,inbound,placeholder,"nodectl-locked")]
    })
}

pub(super) fn outbound(
    secrets: &Secrets,
    inbound: Uuid,
    device: Uuid,
    address: &str,
    port: u64,
) -> Value {
    let client = key(secrets, inbound, Some(device));
    let (v4, v6) = tunnel_ips(&client);
    let server = public(&key(secrets, inbound, None));
    let endpoint = if address.parse::<Ipv6Addr>().is_ok() {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    };
    json!({
        "secretKey":STANDARD.encode(client.as_bytes()),"address":[v4.to_string(),v6.to_string()],
        "noKernelTun":true,"mtu":1280,
        "peers":[{"publicKey":server,"endpoint":endpoint,"allowedIPs":["0.0.0.0/0","::/0"]}]
    })
}

pub(super) fn key_for_redaction(secrets: &Secrets, inbound: Uuid) -> String {
    STANDARD.encode(key(secrets, inbound, None).as_bytes())
}
