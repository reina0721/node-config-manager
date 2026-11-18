//! Additive configuration stored with the existing managed release.
use crate::config::{self, Config, Secrets};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};
use uuid::Uuid;

pub const LOCAL: &str = "local";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Catalogue {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub inbounds: BTreeMap<Uuid, Inbound>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub hosts: BTreeMap<Uuid, Host>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<Uuid, Group>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub upstreams: BTreeMap<Uuid, crate::egress::Upstream>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<Uuid, crate::egress::Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Xhttp,
    Ws,
    Reality,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Xhttp => "xhttp",
            Self::Ws => "ws",
            Self::Reality => "reality",
        }
    }

    pub fn port(self, c: &Config) -> u16 {
        match self {
            Self::Reality => c.ports.reality,
            _ => c.ports.https,
        }
    }

    pub fn path(self, c: &Config) -> &str {
        match self {
            Self::Xhttp => &c.transport.xhttp.path,
            Self::Ws => &c.transport.ws.path,
            Self::Reality => &c.transport.reality.path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    pub remark: String,
    pub protocol: Protocol,
    pub path: String,
    pub port: u16,
    pub enabled: bool,
}

impl Inbound {
    pub fn port(&self, c: &Config) -> u16 {
        if self.protocol == Protocol::Reality {
            self.port
        } else {
            c.ports.https
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub remark: String,
    pub description: String,
    pub node: String,
    pub inbound: String,
    pub addresses: Vec<String>,
    pub port: u16,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub sni: String,
    pub alpn: Vec<String>,
    pub host_header: String,
    pub path: String,
    pub fingerprint: String,
    pub order: u16,
    pub mihomo_ip_version: IpVersion,
    pub mihomo_udp: bool,
    pub formats: BTreeSet<Format>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IpVersion {
    #[default]
    Dual,
    Ipv4,
    Ipv6,
    Ipv4Prefer,
    Ipv6Prefer,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Xray,
    Mihomo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    #[schemars(with = "BTreeSet<String>")]
    pub inbounds: BTreeSet<Uuid>,
    #[schemars(with = "BTreeSet<String>")]
    pub hosts: BTreeSet<Uuid>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Edit {
    Inbound {
        id: Option<Uuid>,
        value: Option<Inbound>,
    },
    Host {
        id: Option<Uuid>,
        value: Option<Host>,
    },
    Group {
        id: Option<Uuid>,
        value: Option<Group>,
    },
    Upstream {
        id: Option<Uuid>,
        value: Option<crate::egress::Upstream>,
        credential: Option<crate::egress::Credential>,
        clear_credential: Option<bool>,
    },
    Rule {
        id: Option<Uuid>,
        value: Option<crate::egress::Rule>,
    },
}

impl Edit {
    pub fn apply(self, config: &mut Config, secrets: &mut Secrets) -> Result<bool> {
        fn update<T>(
            rows: &mut BTreeMap<Uuid, T>,
            id: Option<Uuid>,
            value: Option<T>,
        ) -> Result<Uuid> {
            if let Some(id) = id {
                ensure!(rows.contains_key(&id), "not_found");
            }
            if let Some(value) = value {
                let id = id.unwrap_or_else(Uuid::new_v4);
                rows.insert(id, value);
                Ok(id)
            } else {
                let id = id.context("not_found")?;
                rows.remove(&id);
                Ok(id)
            }
        }
        let management = config.management.get_or_insert_with(Catalogue::default);
        let mut credential_change = false;
        match self {
            Self::Inbound { id, value } => {
                update(&mut management.inbounds, id, value)?;
            }
            Self::Host { id, value } => {
                update(&mut management.hosts, id, value)?;
            }
            Self::Group { id, value } => {
                update(&mut management.groups, id, value)?;
            }
            Self::Rule { id, value } => {
                update(&mut management.rules, id, value)?;
            }
            Self::Upstream {
                id,
                value,
                credential,
                clear_credential,
            } => {
                let deleted = value.is_none();
                let clear = clear_credential.unwrap_or(false);
                ensure!(credential.is_none() || (!deleted && !clear), "bad_request");
                let id = update(&mut management.upstreams, id, value)?;
                if deleted || clear {
                    credential_change = secrets.upstreams.remove(&id).is_some();
                }
                if let Some(credential) = credential {
                    secrets.upstreams.insert(id, credential);
                    credential_change = true;
                }
            }
        }
        if *management == Catalogue::default() {
            config.management = None;
        }
        Ok(credential_change)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    Builtin(Protocol),
    Managed(Uuid, &'a Inbound),
}

impl Target<'_> {
    pub fn protocol(self) -> Protocol {
        match self {
            Self::Builtin(p) => p,
            Self::Managed(_, inbound) => inbound.protocol,
        }
    }

    pub fn port(self, c: &Config) -> u16 {
        match self {
            Self::Builtin(p) => p.port(c),
            Self::Managed(_, inbound) => inbound.port(c),
        }
    }

    pub fn enabled(self) -> bool {
        match self {
            Self::Builtin(_) => true,
            Self::Managed(_, inbound) => inbound.enabled,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
}

pub fn endpoint(input: &str, fallback: u16) -> Result<Endpoint> {
    ensure!(
        input.trim() == input && !input.is_empty(),
        "Invalid host address"
    );
    let (address, port) = if let Ok(socket) = input.parse::<SocketAddr>() {
        (socket.ip().to_string(), socket.port())
    } else if let Ok(ip) = input
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(input)
        .parse::<IpAddr>()
    {
        (ip.to_string(), fallback)
    } else if let Some((domain, port)) = input.rsplit_once(':') {
        ensure!(config::domain(domain), "Invalid host address");
        (domain.into(), port.parse()?)
    } else {
        ensure!(config::domain(input), "Invalid host address");
        (input.into(), fallback)
    };
    ensure!(
        port != 0
            && !address
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified() || ip.is_multicast()),
        "Invalid host endpoint"
    );
    Ok(Endpoint { address, port })
}

impl Catalogue {
    pub fn target(&self, id: &str) -> Option<Target<'_>> {
        match id {
            "xhttp" => Some(Target::Builtin(Protocol::Xhttp)),
            "ws" => Some(Target::Builtin(Protocol::Ws)),
            "reality" => Some(Target::Builtin(Protocol::Reality)),
            _ => {
                let parsed = Uuid::parse_str(id).ok()?;
                (parsed.to_string() == id)
                    .then(|| {
                        self.inbounds
                            .get(&parsed)
                            .map(|node| Target::Managed(parsed, node))
                    })
                    .flatten()
            }
        }
    }

    pub fn granted(&self, groups: &BTreeSet<Uuid>, inbound: Uuid) -> bool {
        groups
            .iter()
            .filter_map(|id| self.groups.get(id))
            .any(|g| g.enabled && g.inbounds.contains(&inbound))
    }

    pub fn host_granted(&self, groups: &BTreeSet<Uuid>, host: Uuid) -> bool {
        groups
            .iter()
            .filter_map(|id| self.groups.get(id))
            .any(|g| g.enabled && g.hosts.contains(&host))
    }

    pub fn active_inbounds(&self) -> impl Iterator<Item = (Uuid, &Inbound)> {
        self.inbounds
            .iter()
            .filter(|(_, inbound)| inbound.enabled)
            .map(|(&id, inbound)| (id, inbound))
    }
}

fn label(input: &str, max: usize) -> bool {
    input.len() <= max && !input.chars().any(char::is_control)
}

pub fn validate(c: &Config) -> Result<()> {
    let Some(catalogue) = &c.management else {
        return Ok(());
    };
    ensure!(
        catalogue.inbounds.len() <= 32
            && catalogue.hosts.len() <= 128
            && catalogue.groups.len() <= 128,
        "Management catalogue limit exceeded"
    );
    let reserved = [
        "/nodes/",
        "/librespeed/",
        "/downloads/",
        "/admin/",
        "/.well-known/",
    ];
    let mut ports = BTreeSet::from([
        c.ports.http,
        c.ports.https,
        c.ports.reality,
        22,
        9080,
        9443,
        19081,
        19443,
    ]);
    if let Some(web) = &c.web_services {
        ports.extend([web.librespeed_port, web.openlist_port]);
    }
    let mut paths: Vec<&str> = vec![
        &c.transport.xhttp.path,
        &c.transport.ws.path,
        &c.transport.reality.path,
    ];
    for (&id, inbound) in &catalogue.inbounds {
        ensure!(
            !id.is_nil() && label(&inbound.remark, 120) && !inbound.remark.trim().is_empty(),
            "Invalid inbound remark or identifier"
        );
        ensure!(
            config::route(&inbound.path, inbound.protocol != Protocol::Ws)
                && inbound.path.len() <= 256,
            "Invalid managed transport path"
        );
        ensure!(
            !paths
                .iter()
                .copied()
                .chain(reserved)
                .chain(c.website.reserved_paths.iter().map(String::as_str))
                .any(|path| config::overlap(path, &inbound.path)),
            "Managed transport path conflicts with another route"
        );
        paths.push(&inbound.path);
        if inbound.protocol == Protocol::Reality {
            ensure!(
                inbound.port >= 1024 && ports.insert(inbound.port),
                "Managed REALITY port conflicts with an existing listener"
            );
        } else {
            ensure!(
                inbound.port == 0,
                "XHTTP and WebSocket inherit the HTTPS port"
            );
        }
    }
    for (&id, host) in &catalogue.hosts {
        ensure!(
            !id.is_nil()
                && label(&host.remark, 120)
                && !host.remark.trim().is_empty()
                && label(&host.description, 512)
                && host.tags.len() <= 16
                && host
                    .tags
                    .iter()
                    .all(|tag| !tag.is_empty() && label(tag, 64)),
            "Invalid host metadata"
        );
        ensure!(host.node == LOCAL, "Host node is unavailable");
        let target = catalogue
            .target(&host.inbound)
            .context("Host inbound is unavailable")?;
        ensure!(
            !host.enabled || target.enabled(),
            "An enabled host needs an enabled inbound"
        );
        ensure!(
            !host.addresses.is_empty() && host.addresses.len() <= 8 && !host.formats.is_empty(),
            "Invalid host address or export list"
        );
        let fallback = if host.port == 0 {
            target.port(c)
        } else {
            host.port
        };
        let mut addresses = BTreeSet::new();
        for address in &host.addresses {
            ensure!(
                addresses.insert(endpoint(address, fallback)?),
                "Duplicate host endpoint"
            );
        }
        ensure!(
            host.sni.is_empty() || c.domains().contains(&host.sni),
            "Host SNI must use a managed certificate name"
        );
        ensure!(
            host.host_header.is_empty() || c.domains().contains(&host.host_header),
            "Host header must use a managed server name"
        );
        ensure!(
            host.path.is_empty()
                || (host.path.len() <= 256
                    && config::route(&host.path, target.protocol() != Protocol::Ws)),
            "Invalid host transport path"
        );
        ensure!(
            ["", "chrome", "ios", "firefox", "qq"].contains(&host.fingerprint.as_str()),
            "Invalid host fingerprint"
        );
        ensure!(
            host.alpn.len() <= 2
                && host.alpn.iter().all(|a| match target.protocol() {
                    Protocol::Ws => a == "http/1.1",
                    Protocol::Xhttp => a == "h2" || a == "http/1.1",
                    Protocol::Reality => false,
                }),
            "Invalid host ALPN"
        );
        ensure!(
            host.host_header.is_empty() || target.protocol() != Protocol::Reality,
            "REALITY has no HTTP host override"
        );
    }
    let mut names = BTreeSet::new();
    for (&id, group) in &catalogue.groups {
        ensure!(
            !id.is_nil()
                && label(&group.name, 120)
                && !group.name.trim().is_empty()
                && names.insert(group.name.trim())
                && label(&group.description, 512),
            "Invalid or duplicate group name"
        );
        ensure!(
            group
                .inbounds
                .iter()
                .all(|id| catalogue.inbounds.contains_key(id)),
            "Group references an unknown inbound"
        );
        ensure!(
            group
                .hosts
                .iter()
                .all(|id| catalogue.hosts.contains_key(id)),
            "Group references an unknown host"
        );
    }
    Ok(())
}

pub fn requires_access(c: &Config) -> bool {
    c.management.as_ref().is_some_and(|m| {
        m.active_inbounds().next().is_some() || m.hosts.values().any(|host| host.enabled)
    }) || crate::egress::needs_ingress(c)
}

pub fn tag(id: Uuid) -> String {
    format!("managed-{}", id.simple())
}
pub fn ipv6_tag(id: Uuid) -> String {
    format!("{}-ipv6", tag(id))
}
pub fn socket(id: Uuid) -> String {
    format!("/tmp/nodectl-{}.socket", id.simple())
}

pub fn host_probe_id(key: Uuid, host: Uuid) -> Uuid {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.as_bytes());
    let digest = ring::hmac::sign(&key, host.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_ref()[..16]);
    uuid::Builder::from_random_bytes(id).into_uuid()
}

pub fn nginx(c: &Config, template: &str, vars: &BTreeMap<&str, String>) -> Result<String> {
    let mut routes = crate::render::template(template, vars)?;
    let Some(catalogue) = &c.management else {
        return Ok(routes);
    };
    let (xhttp, ws) = template
        .split_once("        location = {{ WS_PATH }}")
        .context("Missing WebSocket route template")?;
    let ws = format!("        location = {{{{ WS_PATH }}}}{ws}");
    for (id, inbound) in catalogue.active_inbounds() {
        let (route, path_var, socket_var) = match inbound.protocol {
            Protocol::Xhttp => (xhttp, "XHTTP_PATH", "XHTTP_SOCKET"),
            Protocol::Ws => (ws.as_str(), "WS_PATH", "WS_SOCKET"),
            Protocol::Reality => continue,
        };
        routes.push_str(&crate::render::template(
            route,
            &BTreeMap::from([(path_var, inbound.path.clone()), (socket_var, socket(id))]),
        )?);
    }
    Ok(routes)
}

// Derive distinct managed listener identities with purpose-separated tags.
pub fn listener_secrets(s: &Secrets, id: Uuid) -> Secrets {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, s.reality_private_key.as_bytes());
    let sign = |purpose: &[u8]| {
        let mut context = ring::hmac::Context::with_key(&key);
        context.update(purpose);
        context.update(id.as_bytes());
        context.sign()
    };
    let mut derived = s.clone();
    derived.reality_private_key = URL_SAFE_NO_PAD.encode(sign(b"nodectl/managed/reality").as_ref());
    derived.reality_short_id = hex::encode(&sign(b"nodectl/managed/short").as_ref()[..8]);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&sign(b"nodectl/managed/locked-health-placeholder").as_ref()[..16]);
    let placeholder = uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string();
    derived.xhttp_uuid = placeholder.clone();
    derived.ws_uuid = placeholder.clone();
    derived.reality_uuid = placeholder;
    derived
}

pub fn redactions(c: &Config, s: &Secrets) -> Vec<String> {
    c.management
        .iter()
        .flat_map(|m| m.inbounds.keys())
        .flat_map(|&id| {
            let d = listener_secrets(s, id);
            [d.reality_private_key, d.reality_short_id, d.reality_uuid]
        })
        .collect()
}

pub fn augment_xray(c: &Config, s: &Secrets, rendered: &mut Value) {
    let Some(catalogue) = &c.management else {
        return;
    };
    let active: Vec<_> = catalogue.active_inbounds().collect();
    if active.is_empty() {
        return;
    }
    let templates = rendered["inbounds"]
        .as_array()
        .expect("renderer inbounds")
        .clone();
    let inbounds = rendered["inbounds"]
        .as_array_mut()
        .expect("renderer inbounds");
    let mut locked = Vec::new();
    for (id, inbound) in active {
        for (index, template) in templates.iter().enumerate() {
            let kind = match template["tag"].as_str() {
                Some("vless-xhttp") => Protocol::Xhttp,
                Some("vless-ws") => Protocol::Ws,
                _ => Protocol::Reality,
            };
            if kind != inbound.protocol {
                continue;
            }
            let mut entry = template.clone();
            let tag = if index == 3 { ipv6_tag(id) } else { tag(id) };
            let derived = listener_secrets(s, id);
            entry["tag"] = json!(tag);
            locked.push(tag);
            entry["settings"]["clients"][0]["id"] = json!(derived.reality_uuid);
            if kind == Protocol::Reality {
                entry["port"] = json!(inbound.port);
                entry["streamSettings"]["realitySettings"]["privateKey"] =
                    json!(derived.reality_private_key);
                entry["streamSettings"]["realitySettings"]["shortIds"] =
                    json!([derived.reality_short_id]);
            } else {
                entry["listen"] = json!(format!("{},0660", socket(id)));
            }
            let path_key = if kind == Protocol::Ws {
                "wsSettings"
            } else {
                "xhttpSettings"
            };
            entry["streamSettings"][path_key]["path"] = json!(inbound.path);
            inbounds.push(entry);
        }
    }
    if !rendered["routing"].is_object() {
        rendered["routing"] = json!({"rules":[]});
    }
    // The verification configuration must not accept extra traffic without the relay.
    rendered["routing"]["rules"]
        .as_array_mut()
        .expect("renderer routing")
        .insert(
            0,
            json!({"type":"field", "inboundTag":locked, "outboundTag":"block"}),
        );
}

pub fn client_outbound(
    c: &Config,
    s: &Secrets,
    target: Target<'_>,
    host: Option<&Host>,
    endpoint: Option<&Endpoint>,
    user: Uuid,
) -> Result<Value> {
    let protocol = target.protocol();
    let mut identity = match target {
        Target::Builtin(_) => s.clone(),
        Target::Managed(id, _) => listener_secrets(s, id),
    };
    identity.xhttp_uuid = user.to_string();
    identity.ws_uuid = user.to_string();
    identity.reality_uuid = user.to_string();
    let fingerprint = host
        .filter(|h| !h.fingerprint.is_empty())
        .map_or("chrome", |h| &h.fingerprint);
    let mut outbound = crate::render::outbound(c, &identity, protocol.name(), fingerprint)?;
    let server = &mut outbound["settings"]["vnext"][0];
    server["port"] = json!(endpoint.map_or_else(|| target.port(c), |e| e.port));
    if let Some(endpoint) = endpoint {
        server["address"] = json!(endpoint.address);
    }
    let stream = &mut outbound["streamSettings"];
    let settings = if protocol == Protocol::Ws {
        "wsSettings"
    } else {
        "xhttpSettings"
    };
    let path = match target {
        Target::Builtin(p) => p.path(c),
        Target::Managed(_, inbound) => &inbound.path,
    };
    stream[settings]["path"] = json!(
        host.filter(|h| !h.path.is_empty())
            .map_or(path, |h| h.path.as_str())
    );
    if let Some(host) = host {
        let security = if protocol == Protocol::Reality {
            "realitySettings"
        } else {
            "tlsSettings"
        };
        if !host.sni.is_empty() {
            stream[security]["serverName"] = json!(host.sni);
        }
        if !host.alpn.is_empty() {
            stream[security]["alpn"] = json!(host.alpn);
        }
        if !host.host_header.is_empty() {
            if protocol == Protocol::Ws {
                stream[settings]["headers"]["Host"] = json!(host.host_header);
            } else {
                stream[settings]["host"] = json!(host.host_header);
            }
        }
    }
    Ok(outbound)
}

pub struct ClientEntry<'a> {
    pub name: String,
    pub outbound: Value,
    pub host: Option<&'a Host>,
}

pub fn client_entries<'a>(
    c: &'a Config,
    s: &Secrets,
    user: Uuid,
    groups: &BTreeSet<Uuid>,
    format: Format,
) -> Result<Vec<ClientEntry<'a>>> {
    let Some(catalogue) = &c.management else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    for (id, inbound) in catalogue.active_inbounds() {
        if catalogue.granted(groups, id) {
            let name = format!("{} · {id}", inbound.remark);
            let mut outbound =
                client_outbound(c, s, Target::Managed(id, inbound), None, None, user)?;
            outbound["tag"] = json!(name);
            entries.push(ClientEntry {
                name,
                outbound,
                host: None,
            });
        }
    }
    let mut hosts: Vec<_> = catalogue
        .hosts
        .iter()
        .filter(|(id, host)| {
            host.enabled && host.formats.contains(&format) && catalogue.host_granted(groups, **id)
        })
        .collect();
    hosts.sort_by_key(|(id, host)| (host.order, **id));
    for (id, host) in hosts {
        let target = catalogue
            .target(&host.inbound)
            .context("Unknown host inbound")?;
        if matches!(target, Target::Managed(inbound, _) if !catalogue.granted(groups, inbound)) {
            continue;
        }
        let fallback = if host.port == 0 {
            target.port(c)
        } else {
            host.port
        };
        for (index, address) in host.addresses.iter().enumerate() {
            let endpoint = endpoint(address, fallback)?;
            let name = format!("{} · {id}/{}", host.remark, index + 1);
            let mut outbound = client_outbound(c, s, target, Some(host), Some(&endpoint), user)?;
            outbound["tag"] = json!(name);
            entries.push(ClientEntry {
                name,
                outbound,
                host: Some(host),
            });
        }
    }
    Ok(entries)
}
