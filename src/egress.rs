//! Typed post-authentication routes and upstreams.
use crate::{
    catalogue,
    config::{self, Config, Secrets},
};
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Socks5,
    HttpsConnect,
    Vless,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub enabled: bool,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub server_name: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Credential {
    Password { username: String, password: String },
    Vless { id: String },
}

impl Credential {
    pub fn sensitive(&self) -> Vec<&str> {
        match self {
            Self::Password { username, password } => vec![username, password],
            Self::Vless { id } => vec![id],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub order: u16,
    pub enabled: bool,
    pub inbounds: BTreeSet<String>,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
    pub port_min: Option<u16>,
    pub port_max: Option<u16>,
    pub network: Option<Network>,
    pub outbound: String,
}

pub fn validate(config: &Config, secrets: &Secrets) -> Result<()> {
    let Some(management) = &config.management else {
        ensure!(secrets.upstreams.is_empty(), "Unknown upstream credential");
        return Ok(());
    };
    ensure!(
        management.upstreams.len() <= 32 && management.rules.len() <= 128,
        "Egress limit exceeded"
    );
    ensure!(
        secrets
            .upstreams
            .keys()
            .all(|id| management.upstreams.contains_key(id)),
        "Unknown upstream credential"
    );
    let valid_name = |name: &str| {
        !name.trim().is_empty() && name.len() <= 120 && !name.chars().any(char::is_control)
    };
    for (id, upstream) in &management.upstreams {
        ensure!(
            !id.is_nil() && valid_name(&upstream.name),
            "Invalid upstream name"
        );
        ensure!(
            upstream.port > 0
                && (config::domain(&upstream.address)
                    || upstream
                        .address
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| !ip.is_multicast() && !ip.is_unspecified())),
            "Invalid upstream address"
        );
        ensure!(
            if upstream.protocol == Protocol::Socks5 {
                upstream.server_name.is_empty()
            } else {
                config::domain(&upstream.server_name)
            },
            "TLS upstream needs a verified server name"
        );
        match (upstream.protocol, secrets.upstreams.get(id)) {
            (Protocol::Vless, Some(Credential::Vless { id })) => {
                ensure!(
                    Uuid::parse_str(id).is_ok_and(|id| !id.is_nil()),
                    "Invalid VLESS upstream credential"
                );
            }
            (Protocol::Vless, None) if !upstream.enabled => {}
            (
                Protocol::Socks5 | Protocol::HttpsConnect,
                Some(Credential::Password { username, password }),
            ) => {
                ensure!(
                    !username.is_empty()
                        && !password.is_empty()
                        && username.len() <= 128
                        && password.len() <= 128
                        && !username.contains(':')
                        && !username.chars().any(char::is_control)
                        && !password.chars().any(char::is_control),
                    "Invalid upstream credential"
                );
            }
            (Protocol::Socks5 | Protocol::HttpsConnect, None) => {}
            _ => anyhow::bail!("Invalid credential for upstream protocol"),
        }
    }
    let mut order = BTreeSet::new();
    for (&id, rule) in &management.rules {
        ensure!(
            !id.is_nil() && valid_name(&rule.name) && order.insert(rule.order),
            "Invalid or duplicate routing rule order"
        );
        ensure!(
            rule.inbounds
                .iter()
                .all(|id| management.target(id).is_some()),
            "Rule references an unknown inbound"
        );
        ensure!(
            rule.domains.len() <= 32 && rule.domains.iter().all(|d| config::domain(d)),
            "Invalid routing domain"
        );
        ensure!(
            rule.ips.len() <= 32 && rule.ips.iter().all(|ip| read_cidr(ip).is_some()),
            "Invalid routing IP or CIDR"
        );
        ensure!(
            match (rule.port_min, rule.port_max) {
                (Some(a), Some(b)) => a > 0 && a <= b,
                (None, None) => true,
                _ => false,
            },
            "Specify both ends of a valid port range"
        );
        ensure!(
            matches!(rule.outbound.as_str(), "direct" | "block" | "cn-warp")
                || Uuid::parse_str(&rule.outbound)
                    .is_ok_and(|id| id.to_string() == rule.outbound
                        && management.upstreams.contains_key(&id)),
            "Rule references an unknown outbound"
        );
    }
    Ok(())
}

fn read_cidr(value: &str) -> Option<(IpAddr, u32)> {
    if let Some((ip, prefix)) = value.split_once('/') {
        let ip: IpAddr = ip.parse().ok()?;
        let prefix: u32 = prefix.parse().ok()?;
        (prefix <= if ip.is_ipv4() { 32 } else { 128 }).then_some((ip, prefix))
    } else {
        let ip: IpAddr = value.parse().ok()?;
        Some((ip, if ip.is_ipv4() { 32 } else { 128 }))
    }
}

fn covers(range: (IpAddr, u32), target: IpAddr) -> bool {
    let (ip, prefix) = range;
    match (ip, target) {
        (IpAddr::V4(range), IpAddr::V4(target)) => {
            prefix == 0 || (u32::from(range) ^ u32::from(target)) >> (32 - prefix) == 0
        }
        (IpAddr::V6(range), IpAddr::V6(target)) => {
            prefix == 0 || (u128::from(range) ^ u128::from(target)) >> (128 - prefix) == 0
        }
        _ => false,
    }
}

fn sorted(management: &catalogue::Catalogue) -> Vec<(Uuid, &Rule)> {
    let mut rules: Vec<_> = management
        .rules
        .iter()
        .filter(|(_, r)| r.enabled)
        .map(|(&id, rule)| (id, rule))
        .collect();
    rules.sort_by_key(|(_, rule)| rule.order);
    rules
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    inbound: String,
    domain: Option<String>,
    ip: Option<IpAddr>,
    port: u16,
    network: Network,
}

pub fn preview(c: &Config, destination: Destination) -> Result<Value> {
    ensure!(
        destination.port > 0
            && destination
                .domain
                .as_ref()
                .is_none_or(|domain| config::domain(domain)),
        "bad_request"
    );
    let fallback = catalogue::Catalogue::default();
    let management = c.management.as_ref().unwrap_or(&fallback);
    ensure!(
        management.target(&destination.inbound).is_some(),
        "bad_request"
    );
    let matched = sorted(management).into_iter().find(|(_, rule)| {
        (rule.inbounds.is_empty() || rule.inbounds.contains(&destination.inbound))
            && rule
                .network
                .is_none_or(|network| network == destination.network)
            && rule
                .port_min
                .zip(rule.port_max)
                .is_none_or(|(a, b)| (a..=b).contains(&destination.port))
            && (rule.domains.is_empty()
                || destination.domain.as_ref().is_some_and(|domain| {
                    rule.domains.iter().any(|entry| {
                        domain == entry
                            || domain
                                .strip_suffix(entry)
                                .is_some_and(|prefix| prefix.ends_with('.'))
                    })
                }))
            && (rule.ips.is_empty()
                || destination.ip.is_some_and(|ip| {
                    rule.ips
                        .iter()
                        .any(|entry| read_cidr(entry).is_some_and(|range| covers(range, ip)))
                }))
    });
    Ok(if let Some((id, rule)) = matched {
        json!({"rule":id,"outbound":effective(c, &rule.outbound),"cn_precedence":c.routes_cn()})
    } else {
        json!({"rule":null,"outbound":"direct","cn_precedence":c.routes_cn()})
    })
}

fn tag(id: Uuid) -> String {
    format!("upstream-{}", id.simple())
}

fn effective(c: &Config, target: &str) -> String {
    match target {
        "direct" | "block" => target.into(),
        "cn-warp" if c.routes_cn() => target.into(),
        _ => Uuid::parse_str(target)
            .ok()
            .filter(|id| {
                c.management
                    .as_ref()
                    .and_then(|m| m.upstreams.get(id))
                    .is_some_and(|upstream| upstream.enabled)
            })
            .map_or_else(|| "block".into(), tag),
    }
}

pub fn upstream(id: Uuid, node: &Upstream, credential: Option<&Credential>) -> Result<Value> {
    let mut server = json!({"address":node.address,"port":node.port});
    let mut result = json!({"tag":tag(id)});
    if node.protocol != Protocol::Socks5 {
        result["streamSettings"] = json!({"network":"tcp","security":"tls","tlsSettings":{
            "serverName":node.server_name,"allowInsecure":false,"minVersion":"1.3"
        }});
    }
    match node.protocol {
        Protocol::Socks5 | Protocol::HttpsConnect => {
            if let Some(Credential::Password { username, password }) = credential {
                server["users"] = json!([{"user":username,"pass":password}]);
            }
            result["protocol"] = json!(if node.protocol == Protocol::Socks5 {
                "socks"
            } else {
                "http"
            });
            result["settings"] = json!({"servers":[server]});
        }
        Protocol::Vless => {
            let Some(Credential::Vless { id }) = credential else {
                anyhow::bail!("Missing VLESS upstream credential");
            };
            server["users"] = json!([{"id":id,"encryption":"none"}]);
            result["protocol"] = json!("vless");
            result["settings"] = json!({"vnext":[server]});
        }
    }
    Ok(result)
}

pub fn append_outbounds(c: &Config, s: &Secrets, rendered: &mut Value) -> Result<()> {
    if let Some(management) = &c.management {
        let outbounds = rendered["outbounds"]
            .as_array_mut()
            .context("Missing outbounds")?;
        for (&id, node) in &management.upstreams {
            if node.enabled {
                outbounds.push(upstream(id, node, s.upstreams.get(&id))?);
            }
        }
    }
    Ok(())
}

pub fn routing(c: &Config, ingress_tags: &[(String, String)]) -> Vec<Value> {
    c.management.as_ref().map_or_else(Vec::new, |m| {
        sorted(m).into_iter().filter_map(|(_, rule)| {
            let tags: Vec<_> = ingress_tags.iter()
                .filter(|(id, _)| rule.inbounds.is_empty() || rule.inbounds.contains(id))
                .map(|(_, tag)| tag).collect();
            if tags.is_empty() { return None; }
            let mut filter = json!({"type":"field","inboundTag":tags,"outboundTag":effective(c, &rule.outbound)});
            if !rule.domains.is_empty() { filter["domain"] = json!(rule.domains.iter().map(|d| format!("domain:{d}")).collect::<Vec<_>>()); }
            if !rule.ips.is_empty() { filter["ip"] = json!(rule.ips); }
            if let Some((min, max)) = rule.port_min.zip(rule.port_max) { filter["port"] = json!(format!("{min}-{max}")); }
            if let Some(network) = rule.network { filter["network"] = json!(network); }
            Some(filter)
        }).collect()
    })
}

pub fn needs_ingress(c: &Config) -> bool {
    c.management
        .as_ref()
        .is_some_and(|m| m.rules.values().any(|rule| rule.enabled))
}
