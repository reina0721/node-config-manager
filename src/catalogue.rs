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

mod wireguard;
mod xray_protocol;
pub(crate) use xray_protocol::replace_accounts;

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
    // Stored identifiers from historical snapshots.
    Xhttp,
    Ws,
    Reality,
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    #[serde(rename = "shadowsocks-2022")]
    Shadowsocks2022,
    Http,
    Mixed,
    Hysteria2,
    Wireguard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Raw,
    Xhttp,
    Ws,
    Hysteria,
    Grpc,
    Httpupgrade,
    Mkcp,
    Wireguard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Listener {
    SharedHttps,
    Dedicated,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum VlessFlow {
    None,
    Vision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Stack {
    pub transport: Transport,
    pub security: Security,
    pub listener: Listener,
}

const SHARED_XHTTP: Stack = Stack {
    transport: Transport::Xhttp,
    security: Security::Tls,
    listener: Listener::SharedHttps,
};
const SHARED_WS: Stack = Stack {
    transport: Transport::Ws,
    ..SHARED_XHTTP
};
const XHTTP_REALITY: Stack = Stack {
    transport: Transport::Xhttp,
    security: Security::Reality,
    listener: Listener::Dedicated,
};
const RAW_REALITY: Stack = Stack {
    transport: Transport::Raw,
    ..XHTTP_REALITY
};
const RAW_TLS: Stack = Stack {
    security: Security::Tls,
    ..RAW_REALITY
};
const FALLBACK_TLS: Stack = Stack {
    listener: Listener::Fallback,
    ..RAW_TLS
};
const GRPC_TLS: Stack = Stack {
    transport: Transport::Grpc,
    ..RAW_TLS
};
const UPGRADE_TLS: Stack = Stack {
    transport: Transport::Httpupgrade,
    ..RAW_TLS
};
const MKCP: Stack = Stack {
    transport: Transport::Mkcp,
    security: Security::None,
    ..RAW_TLS
};
const VLESS_STACKS: &[Stack] = &[
    SHARED_XHTTP,
    SHARED_WS,
    XHTTP_REALITY,
    RAW_TLS,
    RAW_REALITY,
    GRPC_TLS,
    UPGRADE_TLS,
];
const STREAM_STACKS: &[Stack] = &[RAW_TLS, SHARED_WS, GRPC_TLS, UPGRADE_TLS, MKCP];
const SS_STACKS: &[Stack] = &[Stack {
    security: Security::None,
    ..RAW_TLS
}];
const WIREGUARD_STACKS: &[Stack] = &[Stack {
    transport: Transport::Wireguard,
    security: Security::None,
    ..RAW_TLS
}];
const HYSTERIA_STACKS: &[Stack] = &[Stack {
    transport: Transport::Hysteria,
    ..RAW_TLS
}];

pub fn inbound_capabilities() -> Value {
    json!({
        "combinations":Protocol::MANAGED.into_iter().flat_map(|protocol| {
            protocol.stacks().iter().map(move |stack| json!({
                "protocol":protocol,
                "transport":stack.transport,
                "security":stack.security,
                "listener":stack.listener,
                "runtime":"xray",
                "formats":if matches!(stack.transport, Transport::Mkcp | Transport::Wireguard) { vec!["xray"] } else { vec!["xray","mihomo"] }
            }))
        }).collect::<Vec<_>>()
    })
}

impl Stack {
    fn http_path(self) -> bool {
        matches!(
            self.transport,
            Transport::Xhttp | Transport::Ws | Transport::Httpupgrade
        )
    }

    fn uses_udp_socket(self) -> bool {
        matches!(
            self.transport,
            Transport::Hysteria | Transport::Mkcp | Transport::Wireguard
        )
    }

    fn owns_tls(self) -> bool {
        self.listener == Listener::Dedicated && self.security == Security::Tls
    }

    fn template(self) -> &'static str {
        match self.listener {
            Listener::Dedicated | Listener::Fallback => "reality",
            Listener::SharedHttps if self.transport == Transport::Ws => "ws",
            Listener::SharedHttps => "xhttp",
        }
    }
}

impl Protocol {
    const MANAGED: [Self; 9] = [
        Self::Vless,
        Self::Vmess,
        Self::Trojan,
        Self::Shadowsocks,
        Self::Shadowsocks2022,
        Self::Http,
        Self::Mixed,
        Self::Hysteria2,
        Self::Wireguard,
    ];

    fn stacks(self) -> &'static [Stack] {
        match self {
            Self::Vless => VLESS_STACKS,
            Self::Vmess => STREAM_STACKS,
            Self::Trojan => &[RAW_TLS, GRPC_TLS, FALLBACK_TLS],
            Self::Http | Self::Mixed => &[RAW_TLS],
            Self::Shadowsocks | Self::Shadowsocks2022 => SS_STACKS,
            Self::Hysteria2 => HYSTERIA_STACKS,
            Self::Wireguard => WIREGUARD_STACKS,
            _ => &[],
        }
    }

    fn legacy(self) -> Option<Stack> {
        match self {
            Self::Xhttp => Some(SHARED_XHTTP),
            Self::Ws => Some(SHARED_WS),
            Self::Reality => Some(XHTTP_REALITY),
            _ => None,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener: Option<Listener>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_mode: Option<XhttpMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<VlessFlow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless_encryption: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub fallback_parent: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

impl Inbound {
    fn checked_stack(&self) -> Option<Stack> {
        match (self.transport, self.security, self.listener) {
            (None, None, None) => self.protocol.legacy(),
            (Some(transport), Some(security), Some(listener)) => {
                let stack = Stack {
                    transport,
                    security,
                    listener,
                };
                self.protocol.stacks().contains(&stack).then_some(stack)
            }
            _ => None,
        }
    }

    pub fn stack(&self) -> Stack {
        self.checked_stack().expect("validated inbound transport")
    }

    fn supports(&self, format: Format) -> bool {
        !matches!(
            self.stack().transport,
            Transport::Mkcp | Transport::Wireguard
        ) || format == Format::Xray
    }

    pub fn dedicated(&self) -> bool {
        self.stack().listener == Listener::Dedicated
    }

    pub(crate) fn uses_nginx(&self) -> bool {
        self.stack().listener == Listener::SharedHttps
    }

    pub(crate) fn owns_tls(&self) -> bool {
        self.stack().owns_tls()
    }

    pub(crate) fn tcp_listener(&self) -> bool {
        self.dedicated() && !self.stack().uses_udp_socket()
    }

    pub(crate) fn udp_listener(&self) -> bool {
        self.stack().uses_udp_socket()
            || matches!(
                self.protocol,
                Protocol::Shadowsocks | Protocol::Shadowsocks2022 | Protocol::Mixed
            )
    }

    pub fn port(&self, c: &Config) -> u16 {
        match self.stack().listener {
            Listener::Dedicated => self.port,
            Listener::SharedHttps => c.ports.https,
            Listener::Fallback => c
                .management
                .as_ref()
                .and_then(|m| {
                    self.fallback_parent
                        .and_then(|parent| m.inbounds.get(&parent))
                })
                .map_or(0, |parent| parent.port),
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

impl<'a> Target<'a> {
    pub fn stack(self) -> Stack {
        match self {
            Self::Builtin(protocol) => protocol.legacy().expect("built-in transport"),
            Self::Managed(_, inbound) => inbound.stack(),
        }
    }

    pub fn port(self, c: &Config) -> u16 {
        match self {
            Self::Builtin(Protocol::Reality) => c.ports.reality,
            Self::Builtin(_) => c.ports.https,
            Self::Managed(_, inbound) => inbound.port(c),
        }
    }

    fn path(self, c: &'a Config) -> &'a str {
        match self {
            Self::Builtin(Protocol::Ws) => &c.transport.ws.path,
            Self::Builtin(Protocol::Reality) => &c.transport.reality.path,
            Self::Builtin(_) => &c.transport.xhttp.path,
            Self::Managed(_, inbound) => &inbound.path,
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

fn service_name(input: &str) -> bool {
    (1..=128).contains(&input.len())
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
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
    let mut fallback_parents = BTreeSet::new();
    for (&id, inbound) in &catalogue.inbounds {
        ensure!(
            !id.is_nil() && label(&inbound.remark, 120) && !inbound.remark.trim().is_empty(),
            "invalid_inbound_remark"
        );
        let stack = inbound.checked_stack().context("invalid_inbound_stack")?;
        ensure!(
            inbound
                .expires
                .is_none_or(|time| (1..=253_402_300_799).contains(&time)),
            "invalid_inbound_expiry"
        );
        ensure!(
            inbound.xhttp_mode.is_none()
                || (inbound.protocol == Protocol::Vless && stack.transport == Transport::Xhttp),
            "invalid_xhttp_mode"
        );
        ensure!(
            inbound.flow.is_none()
                || (inbound.protocol == Protocol::Vless && stack.transport == Transport::Raw),
            "invalid_vless_flow"
        );
        if let Some(encryption) = inbound.vless_encryption {
            ensure!(
                inbound.protocol == Protocol::Vless
                    && stack == RAW_TLS
                    && (!encryption || c.encrypted()),
                "invalid_vless_encryption"
            );
        }
        if stack.listener == Listener::Fallback {
            let parent_id = inbound.fallback_parent.context("invalid_fallback_parent")?;
            let parent = catalogue
                .inbounds
                .get(&parent_id)
                .context("invalid_fallback_parent")?;
            ensure!(
                parent.protocol == Protocol::Vless
                    && parent.checked_stack() == Some(RAW_TLS)
                    && !parent.vless_encryption.unwrap_or(c.encrypted())
                    && (!inbound.enabled || parent.enabled)
                    && fallback_parents.insert(parent_id),
                "invalid_fallback_parent"
            );
        } else {
            ensure!(inbound.fallback_parent.is_none(), "invalid_fallback_parent");
        }
        if stack.transport == Transport::Grpc {
            ensure!(service_name(&inbound.path), "invalid_inbound_path");
        } else if !stack.http_path() {
            ensure!(inbound.path.is_empty(), "invalid_inbound_path");
        } else {
            let root = stack.listener == Listener::Dedicated
                && inbound.protocol == Protocol::Vless
                && inbound.path == "/";
            ensure!(
                root || (config::route(&inbound.path, stack.transport == Transport::Xhttp)
                    && inbound.path.len() <= 256),
                "invalid_inbound_path"
            );
            // Only shared Nginx locations compete with website and sibling paths.
            // Keep the historical validation for previously stored entries.
            if stack.listener == Listener::SharedHttps || inbound.protocol != Protocol::Vless {
                ensure!(
                    !paths
                        .iter()
                        .copied()
                        .chain(reserved)
                        .chain(c.website.reserved_paths.iter().map(String::as_str))
                        .any(|path| config::overlap(path, &inbound.path)),
                    "inbound_path_conflict"
                );
                paths.push(&inbound.path);
            }
        }
        if stack.listener == Listener::Dedicated {
            ensure!(inbound.port >= 1024, "invalid_inbound_port");
            ensure!(ports.insert(inbound.port), "inbound_port_conflict");
        } else {
            ensure!(inbound.port == 0, "invalid_inbound_port");
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
        let stack = target.stack();
        ensure!(
            host.path.is_empty()
                || (stack.transport == Transport::Grpc && service_name(&host.path))
                || (stack.http_path()
                    && host.path.len() <= 256
                    && ((host.path == "/" && stack.listener == Listener::Dedicated)
                        || config::route(&host.path, stack.transport == Transport::Xhttp))),
            "invalid_host_path"
        );
        ensure!(
            ["", "chrome", "ios", "firefox", "qq"].contains(&host.fingerprint.as_str()),
            "Invalid host fingerprint"
        );
        ensure!(
            host.alpn.len() <= 2
                && host.alpn.iter().all(|a| {
                    stack.security == Security::Tls
                        && match stack.transport {
                            Transport::Hysteria => a == "h3",
                            Transport::Grpc => a == "h2",
                            Transport::Ws | Transport::Httpupgrade => a == "http/1.1",
                            _ => a == "http/1.1" || a == "h2",
                        }
                }),
            "Invalid host ALPN"
        );
        ensure!(
            host.host_header.is_empty() || (stack.security == Security::Tls && stack.http_path()),
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

pub(crate) fn device_alias(id: Uuid) -> String {
    format!("device-{}", crate::store::digest(id.as_bytes()))
}

pub(crate) const HEALTH_ALIAS: &str = "nodectl-proxy-health";

pub(crate) fn host_probe_alias(id: Uuid) -> String {
    format!("nodectl-managed-host-check-{id}")
}

pub(crate) fn inbound_user(id: Uuid, inbound: &Inbound, device: Uuid) -> Uuid {
    if inbound.protocol != Protocol::Vless {
        return device;
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, device.as_bytes());
    let mut context = ring::hmac::Context::with_key(&key);
    context.update(b"nodectl/device/inbound");
    context.update(id.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&context.sign().as_ref()[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
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
        if !inbound.uses_nginx() {
            continue;
        }
        let (route, path_var, socket_var) = if inbound.stack().transport == Transport::Ws {
            (ws.as_str(), "WS_PATH", "WS_SOCKET")
        } else {
            (xhttp, "XHTTP_PATH", "XHTTP_SOCKET")
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
        .flat_map(|m| &m.inbounds)
        .flat_map(|(&id, inbound)| {
            let d = listener_secrets(s, id);
            [d.reality_private_key, d.reality_short_id, d.reality_uuid]
                .into_iter()
                .chain(xray_protocol::redactions(s, id, inbound.protocol))
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
        let stack = inbound.stack();
        let selected_tag = format!("vless-{}", stack.template());
        let selected_ipv6 = format!("{selected_tag}-ipv6");
        let derived = listener_secrets(s, id);
        for template in &templates {
            let tag = match template["tag"].as_str() {
                Some(name) if name == selected_tag => tag(id),
                Some(name) if name == selected_ipv6 && inbound.dedicated() => ipv6_tag(id),
                _ => continue,
            };
            let mut entry = template.clone();
            entry["tag"] = json!(tag);
            locked.push(tag);
            entry["settings"]["clients"][0]["id"] = json!(derived.reality_uuid);
            if inbound.dedicated() {
                entry["port"] = json!(inbound.port);
                if stack.security == Security::Reality {
                    entry["streamSettings"]["realitySettings"]["privateKey"] =
                        json!(derived.reality_private_key);
                    entry["streamSettings"]["realitySettings"]["shortIds"] =
                        json!([derived.reality_short_id]);
                }
            } else {
                entry["listen"] = json!(format!("{},0660", socket(id)));
                entry.as_object_mut().expect("core inbound").remove("port");
            }
            let stream = &mut entry["streamSettings"];
            match stack.transport {
                Transport::Raw
                | Transport::Hysteria
                | Transport::Grpc
                | Transport::Httpupgrade
                | Transport::Mkcp
                | Transport::Wireguard => {
                    stream["network"] = json!(stack.transport);
                    stream.as_object_mut().unwrap().remove("xhttpSettings");
                    if stack.security != Security::Reality {
                        stream.as_object_mut().unwrap().remove("realitySettings");
                        stream.as_object_mut().unwrap().remove("security");
                    }
                    if stack.owns_tls() {
                        stream["security"] = json!("tls");
                        stream["tlsSettings"] = json!({
                            "minVersion":"1.3",
                            "certificates":[{
                                "certificateFile":format!("{}/fullchain.pem",c.tls.domain_cert_dir),
                                "keyFile":format!("{}/privkey.pem",c.tls.domain_cert_dir)
                            }]
                        });
                    }
                    direct_transport(stream, stack.transport, &inbound.path);
                    if matches!(stack.transport, Transport::Grpc | Transport::Httpupgrade) {
                        entry["settings"]["clients"][0]
                            .as_object_mut()
                            .unwrap()
                            .remove("flow");
                    }
                }
                Transport::Xhttp => stream["xhttpSettings"]["path"] = json!(inbound.path),
                Transport::Ws => stream["wsSettings"]["path"] = json!(inbound.path),
            }
            if let Some(mode) = inbound.xhttp_mode {
                entry["streamSettings"]["xhttpSettings"]["mode"] = json!(mode);
            }
            apply_flow(
                &mut entry["settings"]["clients"][0],
                inbound.flow,
                "xtls-rprx-vision",
            );
            if inbound.vless_encryption == Some(false) {
                entry["settings"]["decryption"] = json!("none");
                if inbound.flow.is_none() {
                    apply_flow(
                        &mut entry["settings"]["clients"][0],
                        Some(VlessFlow::None),
                        "",
                    );
                }
            }
            if let Some((child, _)) = catalogue
                .active_inbounds()
                .find(|(_, child)| child.fallback_parent == Some(id))
            {
                entry["settings"]["fallbacks"] = json!([{"dest":socket(child),"xver":0}]);
                entry["streamSettings"]["tlsSettings"]["alpn"] = json!(["http/1.1"]);
            }
            xray_protocol::configure_inbound(&mut entry, inbound, id, s);
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

fn apply_flow(user: &mut Value, flow: Option<VlessFlow>, vision: &str) {
    match flow {
        Some(VlessFlow::Vision) => user["flow"] = json!(vision),
        Some(VlessFlow::None) => {
            user.as_object_mut().expect("VLESS user").remove("flow");
        }
        None => {}
    }
}

fn direct_transport(stream: &mut Value, transport: Transport, path: &str) {
    match transport {
        Transport::Grpc => {
            stream["tlsSettings"]["alpn"] = json!(["h2"]);
            stream["grpcSettings"] = json!({"serviceName":path});
        }
        Transport::Httpupgrade => {
            stream["tlsSettings"]["alpn"] = json!(["http/1.1"]);
            stream["httpupgradeSettings"] = json!({"path":path});
        }
        Transport::Hysteria => {
            stream["tlsSettings"]["alpn"] = json!(["h3"]);
            stream["hysteriaSettings"] = json!({"version":2});
        }
        Transport::Mkcp => {
            stream["kcpSettings"] = json!({});
        }
        Transport::Wireguard => {
            stream["network"] = json!("raw");
        }
        _ => {}
    }
}

pub(crate) fn materialize_tls(c: &Config, xray: &mut Value) -> Result<()> {
    let tags: BTreeSet<_> = c
        .management
        .iter()
        .flat_map(|m| m.active_inbounds())
        .filter(|(_, inbound)| inbound.owns_tls())
        .flat_map(|(id, _)| [tag(id), ipv6_tag(id)])
        .collect();
    if tags.is_empty() {
        return Ok(());
    }
    let certificate = std::fs::read_to_string(format!("{}/fullchain.pem", c.tls.domain_cert_dir))
        .context("managed_tls_certificate")?;
    let key = std::fs::read_to_string(format!("{}/privkey.pem", c.tls.domain_cert_dir))
        .context("managed_tls_certificate")?;
    for entry in xray["inbounds"]
        .as_array_mut()
        .context("Missing Xray inbounds")?
    {
        if entry["tag"].as_str().is_some_and(|tag| tags.contains(tag)) {
            entry["streamSettings"]["tlsSettings"]["certificates"] = json!([{"certificate":certificate.lines().collect::<Vec<_>>(),"key":key.lines().collect::<Vec<_>>()}]);
        }
    }
    Ok(())
}

pub fn client_outbound(
    c: &Config,
    s: &Secrets,
    target: Target<'_>,
    host: Option<&Host>,
    endpoint: Option<&Endpoint>,
    user: Uuid,
    alias: &str,
) -> Result<Value> {
    let stack = target.stack();
    let user = match target {
        Target::Builtin(_) => user,
        Target::Managed(id, inbound) => inbound_user(id, inbound, user),
    };
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
    let mut outbound = crate::render::outbound(c, &identity, stack.template(), fingerprint)?;
    let server = &mut outbound["settings"]["vnext"][0];
    server["port"] = json!(endpoint.map_or_else(|| target.port(c), |e| e.port));
    if let Some(endpoint) = endpoint {
        server["address"] = json!(endpoint.address);
    }
    let stream = &mut outbound["streamSettings"];
    let settings = match stack.transport {
        Transport::Raw
        | Transport::Hysteria
        | Transport::Grpc
        | Transport::Httpupgrade
        | Transport::Mkcp
        | Transport::Wireguard => {
            stream["network"] = json!(stack.transport);
            stream.as_object_mut().unwrap().remove("xhttpSettings");
            if stack.security != Security::Reality {
                stream.as_object_mut().unwrap().remove("realitySettings");
                stream.as_object_mut().unwrap().remove("security");
            }
            if stack.security == Security::Tls && stack.listener != Listener::SharedHttps {
                stream["security"] = json!("tls");
                stream["tlsSettings"] = json!({
                    "serverName":c.node.domain, "fingerprint":fingerprint,
                    "useSystemCA":true, "minVersion":"1.3"
                });
            }
            let path = host
                .filter(|h| !h.path.is_empty())
                .map_or_else(|| target.path(c), |h| h.path.as_str());
            direct_transport(stream, stack.transport, path);
            if stack.transport == Transport::Httpupgrade
                && let Some(host) = host.filter(|h| !h.host_header.is_empty())
            {
                stream["httpupgradeSettings"]["host"] = json!(host.host_header);
            }
            None
        }
        Transport::Xhttp => Some("xhttpSettings"),
        Transport::Ws => Some("wsSettings"),
    };
    if let Some(settings) = settings {
        stream[settings]["path"] = json!(
            host.filter(|h| !h.path.is_empty())
                .map_or_else(|| target.path(c), |h| h.path.as_str())
        );
    }
    if let Some(host) = host {
        let security = if stack.security == Security::Reality {
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
        if let Some(settings) = settings.filter(|_| !host.host_header.is_empty()) {
            if stack.transport == Transport::Ws {
                stream[settings]["headers"]["Host"] = json!(host.host_header);
            } else {
                stream[settings]["host"] = json!(host.host_header);
            }
        }
    }
    if matches!(stack.transport, Transport::Grpc | Transport::Httpupgrade) {
        outbound["settings"]["vnext"][0]["users"][0]
            .as_object_mut()
            .unwrap()
            .remove("flow");
    }
    if let Target::Managed(id, inbound) = target {
        if let Some(mode) = inbound.xhttp_mode {
            outbound["streamSettings"]["xhttpSettings"]["mode"] = json!(mode);
        }
        apply_flow(
            &mut outbound["settings"]["vnext"][0]["users"][0],
            inbound.flow,
            "xtls-rprx-vision-udp443",
        );
        if inbound.vless_encryption == Some(false) {
            let user = &mut outbound["settings"]["vnext"][0]["users"][0];
            user["encryption"] = json!("none");
            if inbound.flow.is_none() {
                apply_flow(user, Some(VlessFlow::None), "");
            }
        }
        xray_protocol::client(&mut outbound, inbound, id, s, user, alias)?;
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
    let alias = device_alias(user);
    let now = crate::admin_auth::now();
    for (id, inbound) in catalogue.active_inbounds() {
        if inbound.supports(format)
            && inbound.expires.is_none_or(|expires| expires > now)
            && catalogue.granted(groups, id)
        {
            let name = format!("{} · {id}", inbound.remark);
            let mut outbound =
                client_outbound(c, s, Target::Managed(id, inbound), None, None, user, &alias)?;
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
        if matches!(target, Target::Managed(id, inbound)
            if !inbound.supports(format)
            || !inbound.expires.is_none_or(|expires| expires > now)
            || !catalogue.granted(groups, id))
        {
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
            let mut outbound =
                client_outbound(c, s, target, Some(host), Some(&endpoint), user, &alias)?;
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
