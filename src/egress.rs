//! Typed post-authentication routes and upstreams.
use crate::{
    catalogue,
    config::{self, Config, Secrets},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Socks5,
    Socks5Tls,
    HttpsConnect,
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    #[serde(rename = "shadowsocks-2022")]
    Shadowsocks2022,
    Hysteria2,
    RoundRobin,
}

impl Protocol {
    fn tls(self) -> bool {
        !matches!(
            self,
            Self::Socks5 | Self::Shadowsocks | Self::Shadowsocks2022
        )
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub via: Option<Uuid>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[schemars(with = "BTreeSet<String>")]
    pub members: BTreeSet<Uuid>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Credential {
    Password { username: String, password: String },
    Vless { id: String },
    Vmess { id: String },
    Secret { secret: String },
}

impl Credential {
    pub fn sensitive(&self) -> Vec<&str> {
        match self {
            Self::Password { username, password } => vec![username, password],
            Self::Vless { id } | Self::Vmess { id } => vec![id],
            Self::Secret { secret } => vec![secret],
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
        if upstream.protocol == Protocol::RoundRobin {
            ensure!(
                upstream.via.is_none()
                    && upstream.address.is_empty()
                    && upstream.port == 0
                    && upstream.server_name.is_empty()
                    && !secrets.upstreams.contains_key(id)
                    && (!upstream.enabled || upstream.members.len() >= 2)
                    && upstream.members.iter().all(|member| {
                        management.upstreams.get(member).is_some_and(|candidate| {
                            candidate.protocol != Protocol::RoundRobin
                                && (!upstream.enabled || candidate.enabled)
                        })
                    }),
                "invalid_upstream_pool"
            );
            continue;
        }
        ensure!(upstream.members.is_empty(), "invalid_upstream_pool");
        chain(config, *id)?;
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
            if upstream.protocol.tls() {
                config::domain(&upstream.server_name)
            } else {
                upstream.server_name.is_empty()
            },
            "TLS upstream needs a verified server name"
        );
        match (upstream.protocol, secrets.upstreams.get(id)) {
            (Protocol::Vless, Some(Credential::Vless { id }))
            | (Protocol::Vmess, Some(Credential::Vmess { id })) => {
                ensure!(
                    Uuid::parse_str(id).is_ok_and(|id| !id.is_nil()),
                    "Invalid upstream UUID"
                );
            }
            (_, None) if !upstream.enabled => {}
            (
                Protocol::Socks5 | Protocol::Socks5Tls | Protocol::HttpsConnect,
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
            (Protocol::Socks5 | Protocol::Socks5Tls | Protocol::HttpsConnect, None) => {}
            (
                Protocol::Trojan | Protocol::Shadowsocks | Protocol::Hysteria2,
                Some(Credential::Secret { secret }),
            ) => {
                ensure!(
                    !secret.is_empty()
                        && secret.len() <= 256
                        && !secret.chars().any(char::is_control),
                    "Invalid upstream secret"
                );
            }
            (Protocol::Shadowsocks2022, Some(Credential::Secret { secret })) => {
                let keys = secret.split(':').collect::<Vec<_>>();
                ensure!(
                    keys.len() <= 2
                        && keys
                            .iter()
                            .all(|key| STANDARD.decode(key).is_ok_and(|key| key.len() == 16)),
                    "Shadowsocks-2022 needs one or two base64 AES-128 keys"
                );
            }
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

fn chain(config: &Config, id: Uuid) -> Result<Vec<(Uuid, &Upstream)>> {
    let management = config
        .management
        .as_ref()
        .context("invalid_upstream_chain")?;
    let mut found = BTreeSet::new();
    let mut result = vec![];
    let mut next = Some(id);
    while let Some(id) = next {
        ensure!(found.insert(id), "invalid_upstream_chain");
        let node = management
            .upstreams
            .get(&id)
            .context("invalid_upstream_chain")?;
        ensure!(
            node.protocol != Protocol::RoundRobin,
            "invalid_upstream_chain"
        );
        ensure!(
            result
                .first()
                .is_none_or(|entry: &(Uuid, &Upstream)| !entry.1.enabled || node.enabled),
            "invalid_upstream_chain"
        );
        result.push((id, node));
        next = node.via;
    }
    Ok(result)
}

pub fn probe_paths(config: &Config, secrets: &Secrets, id: Uuid) -> Result<Vec<Vec<Value>>> {
    let node = config
        .management
        .as_ref()
        .and_then(|m| m.upstreams.get(&id))
        .filter(|upstream| upstream.enabled)
        .context("not_found")?;
    let roots = if node.protocol == Protocol::RoundRobin {
        node.members.iter().copied().collect()
    } else {
        vec![id]
    };
    roots
        .into_iter()
        .map(|root| {
            chain(config, root)?
                .into_iter()
                .map(|(id, node)| upstream(id, node, secrets.upstreams.get(&id)))
                .collect()
        })
        .collect()
}

fn balancer_tag(id: Uuid) -> String {
    format!("pool-{}", id.simple())
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
            .and_then(|id| {
                let node = c
                    .management
                    .as_ref()?
                    .upstreams
                    .get(&id)
                    .filter(|node| node.enabled)?;
                Some(if node.protocol == Protocol::RoundRobin {
                    balancer_tag(id)
                } else {
                    tag(id)
                })
            })
            .unwrap_or_else(|| "block".into()),
    }
}

pub fn upstream(id: Uuid, node: &Upstream, credential: Option<&Credential>) -> Result<Value> {
    ensure!(
        node.protocol != Protocol::RoundRobin,
        "invalid_upstream_pool"
    );
    let mut server = json!({"address":node.address,"port":node.port});
    let mut result = json!({"tag":tag(id)});
    if node.protocol.tls() {
        result["streamSettings"] = json!({"network":"tcp","security":"tls","tlsSettings":{
            "serverName":node.server_name,"allowInsecure":false,"minVersion":"1.3"
        }});
    }
    match node.protocol {
        Protocol::Socks5 | Protocol::Socks5Tls | Protocol::HttpsConnect => {
            if let Some(Credential::Password { username, password }) = credential {
                server["users"] = json!([{"user":username,"pass":password}]);
            }
            if node.protocol == Protocol::Socks5Tls {
                result["streamSettings"]["tlsSettings"]["alpn"] = json!(["http/1.1"]);
            }
            result["protocol"] = json!(if node.protocol != Protocol::HttpsConnect {
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
        Protocol::Vmess => {
            let Some(Credential::Vmess { id }) = credential else {
                anyhow::bail!("Missing VMess upstream UUID");
            };
            server["id"] = json!(id);
            server["security"] = json!("auto");
            result["protocol"] = json!("vmess");
            result["settings"] = server;
        }
        protocol => {
            let Some(Credential::Secret { secret }) = credential else {
                anyhow::bail!("Missing upstream secret");
            };
            match protocol {
                Protocol::Trojan => {
                    server["password"] = json!(secret);
                    result["protocol"] = json!("trojan");
                }
                Protocol::Shadowsocks | Protocol::Shadowsocks2022 => {
                    server["password"] = json!(secret);
                    server["method"] = json!(if protocol == Protocol::Shadowsocks2022 {
                        "2022-blake3-aes-128-gcm"
                    } else {
                        "aes-256-gcm"
                    });
                    result["protocol"] = json!("shadowsocks");
                }
                Protocol::Hysteria2 => {
                    result["protocol"] = json!("hysteria");
                    result["streamSettings"]["network"] = json!("hysteria");
                    result["streamSettings"]["tlsSettings"]["alpn"] = json!(["h3"]);
                    result["streamSettings"]["hysteriaSettings"] =
                        json!({"version":2,"auth":secret});
                    server["version"] = json!(2);
                }
                _ => unreachable!("handled authenticated upstream"),
            }
            result["settings"] = server;
        }
    }
    if let Some(via) = node.via {
        result["streamSettings"]["sockopt"]["dialerProxy"] = json!(tag(via));
    }
    Ok(result)
}

pub fn append_outbounds(c: &Config, s: &Secrets, rendered: &mut Value) -> Result<()> {
    if let Some(management) = &c.management {
        let mut balancers = Vec::new();
        let outbounds = rendered["outbounds"]
            .as_array_mut()
            .context("Missing outbounds")?;
        for (&id, node) in management.upstreams.iter().filter(|(_, node)| node.enabled) {
            if node.protocol == Protocol::RoundRobin {
                balancers.push(json!({
                    "tag":balancer_tag(id), "selector":node.members.iter().copied().map(tag).collect::<Vec<_>>(),
                    "strategy":{"type":"roundRobin"}, "fallbackTag":"block"
                }));
            } else {
                outbounds.push(upstream(id, node, s.upstreams.get(&id))?);
            }
        }
        if !balancers.is_empty() {
            rendered["routing"]["balancers"] = json!(balancers);
            // The round-robin strategy requires the feature even when member
            // health is checked by nodectl's explicit probes.
            rendered["observatory"] = json!({"subjectSelector":[]});
        }
    }
    Ok(())
}

pub fn routing(c: &Config, ingress_tags: &[(String, String)]) -> Vec<Value> {
    c.management.as_ref().map_or_else(Vec::new, |m| {
        sorted(m)
            .into_iter()
            .filter_map(|(_, rule)| {
                let tags: Vec<_> = ingress_tags
                    .iter()
                    .filter(|(id, _)| rule.inbounds.is_empty() || rule.inbounds.contains(id))
                    .map(|(_, tag)| tag)
                    .collect();
                if tags.is_empty() {
                    return None;
                }
                let target = effective(c, &rule.outbound);
                let mut filter = json!({"type":"field","inboundTag":tags});
                let key = if target.starts_with("pool-") {
                    "balancerTag"
                } else {
                    "outboundTag"
                };
                filter[key] = json!(target);
                if !rule.domains.is_empty() {
                    filter["domain"] = json!(
                        rule.domains
                            .iter()
                            .map(|d| format!("domain:{d}"))
                            .collect::<Vec<_>>()
                    );
                }
                if !rule.ips.is_empty() {
                    filter["ip"] = json!(rule.ips);
                }
                if let Some((min, max)) = rule.port_min.zip(rule.port_max) {
                    filter["port"] = json!(format!("{min}-{max}"));
                }
                if let Some(network) = rule.network {
                    filter["network"] = json!(network);
                }
                Some(filter)
            })
            .collect()
    })
}

pub fn needs_ingress(c: &Config) -> bool {
    c.management.as_ref().is_some_and(|m| {
        m.rules.values().any(|rule| rule.enabled)
            || m.active_inbounds()
                .any(|(_, inbound)| inbound.expires.is_some())
    })
}
