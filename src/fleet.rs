//! Independent, explicitly scoped peer access over the existing HTTPS endpoint.
use crate::{
    admin_auth, config, host,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    net::IpAddr,
    path::PathBuf,
    process::{Command, Stdio},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Read,
    Manage,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub name: String,
    pub scope: Scope,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub name: String,
    pub hostname: String,
    pub address: IpAddr,
    pub port: u16,
    token: String,
}

#[derive(Deserialize, Serialize)]
struct Peer {
    registration: Register,
    last_seen: u64,
}

#[derive(Deserialize, Serialize)]
struct Permission {
    grant: Grant,
    digest: String,
}

#[derive(Default, Deserialize, Serialize)]
struct Registry {
    grants: BTreeMap<Uuid, Permission>,
    peers: BTreeMap<Uuid, Peer>,
}

fn path(store: &Store) -> PathBuf {
    admin_auth::directory(store).join("fleet.json")
}

fn read(store: &Store) -> Result<Registry> {
    let path = path(store);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Registry::default()),
        metadata => {
            metadata?;
        }
    }
    store::check_private(&path, false)?;
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write(store: &Store, registry: &Registry) -> Result<()> {
    store::atomic_write(&path(store), &serde_json::to_vec(registry)?)
}

fn name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 96 && !value.chars().any(char::is_control)
}

fn valid_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn list(store: &Store) -> Result<Value> {
    let registry = read(store)?;
    let domain = store.inputs().ok().map(|(c, _)| c.node.domain);
    Ok(json!({
        "local":{"id":"local","hostname":domain,"version":env!("CARGO_PKG_VERSION")},
        "peers":registry.peers.iter().map(|(id, peer)| json!({"id":id,
            "name":peer.registration.name,"hostname":peer.registration.hostname,
            "address":peer.registration.address,"port":peer.registration.port,"last_seen":peer.last_seen,
            "stale":admin_auth::now().saturating_sub(peer.last_seen) > 60})).collect::<Vec<_>>(),
        "grants":registry.grants.iter().map(|(id, permission)| json!({"id":id,
            "name":permission.grant.name,"scope":permission.grant.scope})).collect::<Vec<_>>()
    }))
}

pub fn grant(store: &Store, grant: Grant) -> Result<Value> {
    ensure!(name(&grant.name), "bad_request");
    let _guard = store.lock()?;
    let mut registry = read(store)?;
    ensure!(registry.grants.len() < 32, "bad_request");
    let token = admin_auth::random();
    let id = Uuid::new_v4();
    registry.grants.insert(
        id,
        Permission {
            grant,
            digest: store::digest(token.as_bytes()),
        },
    );
    write(store, &registry)?;
    Ok(json!({"id":id,"token":token}))
}

pub fn register(store: &Store, registration: Register) -> Result<Value> {
    ensure!(
        name(&registration.name)
            && config::domain(&registration.hostname)
            && registration.port >= 1024
            && valid_token(&registration.token)
            && !registration.address.is_multicast()
            && !registration.address.is_unspecified()
            && !registration.address.is_loopback(),
        "bad_request"
    );
    if let Ok((config, _)) = store.inputs() {
        ensure!(
            !config.domains().contains(&registration.hostname),
            "bad_request"
        );
    }
    let status = request(&registration, "overview", false, &[])?;
    ensure!(status["version"].as_str().is_some(), "peer_unavailable");
    let _guard = store.lock()?;
    let mut registry = read(store)?;
    ensure!(
        registry.peers.len() < 16
            && !registry
                .peers
                .values()
                .any(|p| p.registration.hostname == registration.hostname
                    && p.registration.port == registration.port),
        "bad_request"
    );
    let id = Uuid::new_v4();
    registry.peers.insert(
        id,
        Peer {
            registration,
            last_seen: admin_auth::now(),
        },
    );
    write(store, &registry)?;
    Ok(json!({"id":id}))
}

pub fn remove(store: &Store, id: Uuid, grant: bool) -> Result<Value> {
    let _guard = store.lock()?;
    let mut registry = read(store)?;
    let found = if grant {
        registry.grants.remove(&id).is_some()
    } else {
        registry.peers.remove(&id).is_some()
    };
    ensure!(found, "not_found");
    write(store, &registry)?;
    Ok(json!({"ok":true}))
}

pub fn has_records(store: &Store) -> Result<bool> {
    let registry = read(store)?;
    Ok(!registry.peers.is_empty() || !registry.grants.is_empty())
}

pub fn allowed(path: &str, post: bool, scope: Scope) -> bool {
    if post {
        matches!(scope, Scope::Manage)
            && matches!(
                path,
                "catalogue/preview"
                    | "routing/match"
                    | "outbounds/test"
                    | "operations"
                    | "config/preview"
                    | "config/check"
                    | "config/apply"
                    | "proxy-access"
            )
    } else {
        matches!(
            path,
            "overview"
                | "config"
                | "nodes"
                | "network"
                | "services"
                | "operations"
                | "versions"
                | "dns"
                | "proxy-access"
                | "proxy-access/export"
                | "xray"
                | "panel"
                | "openapi"
        ) || matches!(scope, Scope::Manage) && path.starts_with("proxy-access/profile/")
            || path.strip_prefix("jobs/").is_some_and(valid_token)
    }
}

pub fn authenticate(store: &Store, header: &str, path: &str, post: bool) -> Result<String> {
    let token = header
        .strip_prefix("Bearer ")
        .filter(|t| valid_token(t))
        .context("unauthorized")?;
    let digest = store::digest(token.as_bytes());
    let registry = read(store)?;
    let (id, permission) = registry
        .grants
        .iter()
        .find(|(_, p)| bool::from(p.digest.as_bytes().ct_eq(digest.as_bytes())))
        .context("unauthorized")?;
    ensure!(
        allowed(path, post, permission.grant.scope),
        "peer_scope_denied"
    );
    Ok(store::digest(format!("fleet:{id}").as_bytes()))
}

pub fn forward(store: &Store, id: Uuid, path: &str, post: bool, body: &[u8]) -> Result<Value> {
    ensure!(allowed(path, post, Scope::Manage), "peer_scope_denied");
    let registry = read(store)?;
    let peer = registry.peers.get(&id).context("not_found")?;
    let result = request(&peer.registration, path, post, body)?;
    if admin_auth::now().saturating_sub(peer.last_seen) >= 15 {
        // Status writes are advisory and must never turn a valid remote response
        // into an ambiguous failure when a local transaction owns the lock.
        if let Ok(_guard) = store.lock()
            && let Ok(mut registry) = read(store)
            && let Some(peer) = registry.peers.get_mut(&id)
        {
            peer.last_seen = admin_auth::now();
            let _ = write(store, &registry);
        }
    }
    Ok(result)
}

fn request(peer: &Register, path: &str, post: bool, body: &[u8]) -> Result<Value> {
    host::trusted_binary(std::path::Path::new("/usr/bin/curl"))?;
    let origin = format!("https://{}:{}", peer.hostname, peer.port);
    let address = if peer.address.is_ipv6() {
        format!("[{}]", peer.address)
    } else {
        peer.address.to_string()
    };
    let resolve = format!("{}:{}:{address}", peer.hostname, peer.port);
    let url = format!("{origin}/admin/api/peer/{path}");
    let mut command = Command::new("/usr/bin/curl");
    command.args([
        "--disable",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--max-time",
        "15",
        "--connect-timeout",
        "5",
        "--max-filesize",
        "4194304",
        "--resolve",
        &resolve,
        "--config",
        "-",
        "--url",
        &url,
    ]);
    let mut payload = None;
    if post {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(body)?;
        command
            .arg("--data-binary")
            .arg(format!("@{}", file.path().display()));
        payload = Some(file);
    }
    let mut child = command
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut headers = child.stdin.take().context("peer_unavailable")?;
    let sent = writeln!(headers, "header = \"Authorization: Bearer {}\"", peer.token)
        .and_then(|()| writeln!(headers, "header = \"Origin: {origin}\""))
        .and_then(|()| writeln!(headers, "header = \"Content-Type: application/json\""));
    drop(headers);
    let response = child.wait_with_output().context("peer_unavailable")?;
    drop(payload);
    sent.context("peer_unavailable")?;
    ensure!(response.status.success(), "peer_unavailable");
    let value: Value = serde_json::from_slice(&response.stdout).context("peer_unavailable")?;
    if let Some(error) = value["error"].as_str() {
        ensure!(
            error.len() < 80 && error.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "peer_unavailable"
        );
        ensure!(error != "unauthorized", "peer_scope_denied");
        anyhow::bail!("{error}");
    }
    Ok(value)
}
