use super::{Catalogue, LOCAL, Listener, reserved_paths, reserved_ports, uses_path_slot};
use crate::{
    admin_policy, config,
    config::{Config, Secrets},
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::{Builder, Uuid};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Inbound,
    Host,
    Group,
    Upstream,
    Rule,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub kind: Kind,
    pub id: Uuid,
}

impl Resource {
    fn new(kind: Kind, id: Uuid) -> Self {
        Self { kind, id }
    }

    fn copied_id(self, request: Uuid) -> Uuid {
        let digest = Sha256::digest(
            [
                b"nodectl catalogue copy".as_slice(),
                request.as_bytes(),
                &[self.kind as u8],
                self.id.as_bytes(),
            ]
            .concat(),
        );
        Builder::from_custom_bytes(digest[..16].try_into().unwrap()).into_uuid()
    }

    fn name(self, catalogue: &Catalogue) -> Option<&str> {
        Some(match self.kind {
            Kind::Inbound => &catalogue.inbounds.get(&self.id)?.remark,
            Kind::Host => &catalogue.hosts.get(&self.id)?.remark,
            Kind::Group => &catalogue.groups.get(&self.id)?.name,
            Kind::Upstream => &catalogue.upstreams.get(&self.id)?.name,
            Kind::Rule => &catalogue.rules.get(&self.id)?.name,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub source: String,
    pub target: String,
    pub source_base: String,
    pub target_base: String,
    pub request: Uuid,
    pub resources: BTreeSet<Resource>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub base: String,
    pub catalogue: Catalogue,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub base: String,
    pub request: Uuid,
    pub selected: BTreeSet<Resource>,
    pub catalogue: Catalogue,
}

pub fn source(store: &Store) -> Result<Source> {
    let _guard = store.lock()?;
    Ok(Source {
        base: admin_policy::fingerprint(store)?,
        catalogue: store.inputs()?.0.management.unwrap_or_default(),
    })
}

pub fn apply_job(owner: &str, request: Uuid) -> String {
    store::digest(format!("catalogue-copy:{owner}:{request}").as_bytes())
}

fn parse_reference(kind: Kind, value: &str) -> Option<Resource> {
    value.parse().ok().map(|id| Resource::new(kind, id))
}

pub fn select(catalogue: &Catalogue, selected: &BTreeSet<Resource>) -> Result<Catalogue> {
    ensure!(!selected.is_empty() && selected.len() <= 448, "bad_request");
    let mut collected = BTreeSet::new();
    let mut pending: Vec<_> = selected.iter().copied().collect();
    let mut result = Catalogue::default();
    while let Some(resource) = pending.pop() {
        if !collected.insert(resource) {
            continue;
        }
        resource.name(catalogue).context("not_found")?;
        let id = resource.id;
        match resource.kind {
            Kind::Inbound => {
                let inbound = catalogue.inbounds[&id].clone();
                pending.extend(
                    inbound
                        .fallback_parent
                        .map(|id| Resource::new(Kind::Inbound, id)),
                );
                result.inbounds.insert(id, inbound);
            }
            Kind::Host => {
                let host = catalogue.hosts[&id].clone();
                pending.extend(parse_reference(Kind::Inbound, &host.inbound));
                result.hosts.insert(id, host);
            }
            Kind::Group => {
                let group = catalogue.groups[&id].clone();
                pending.extend(
                    group
                        .inbounds
                        .iter()
                        .map(|&id| Resource::new(Kind::Inbound, id)),
                );
                pending.extend(group.hosts.iter().map(|&id| Resource::new(Kind::Host, id)));
                result.groups.insert(id, group);
            }
            Kind::Upstream => {
                let upstream = catalogue.upstreams[&id].clone();
                pending.extend(upstream.via.map(|id| Resource::new(Kind::Upstream, id)));
                pending.extend(
                    upstream
                        .members
                        .iter()
                        .map(|&id| Resource::new(Kind::Upstream, id)),
                );
                result.upstreams.insert(id, upstream);
            }
            Kind::Rule => {
                let rule = catalogue.rules[&id].clone();
                pending.extend(
                    rule.inbounds
                        .iter()
                        .filter_map(|id| parse_reference(Kind::Inbound, id)),
                );
                pending.extend(parse_reference(Kind::Upstream, &rule.outbound));
                result.rules.insert(id, rule);
            }
        }
    }
    Ok(result)
}

pub fn candidate(
    old: &Config,
    secrets: &Secrets,
    input: Import,
    admin_port: Option<u16>,
) -> Result<(Config, Value)> {
    ensure!(!input.request.is_nil(), "bad_request");
    let source = select(&input.catalogue, &input.selected)?;
    let mut candidate = old.clone();
    let target = candidate.management.get_or_insert_with(Catalogue::default);
    let resources: BTreeMap<_, _> = [
        (
            Kind::Inbound,
            source.inbounds.keys().copied().collect::<Vec<_>>(),
        ),
        (Kind::Host, source.hosts.keys().copied().collect()),
        (Kind::Group, source.groups.keys().copied().collect()),
        (Kind::Upstream, source.upstreams.keys().copied().collect()),
        (Kind::Rule, source.rules.keys().copied().collect()),
    ]
    .into_iter()
    .flat_map(|(kind, ids)| ids.into_iter().map(move |id| Resource::new(kind, id)))
    .map(|resource| (resource, resource.copied_id(input.request)))
    .collect();
    let mut rows = Vec::new();
    for (&resource, &target_id) in &resources {
        ensure!(
            Resource::new(resource.kind, target_id)
                .name(target)
                .is_none(),
            "copy_already_applied"
        );
        rows.push(json!({
            "kind":resource.kind, "source":resource.id, "target":target_id,
            "name":resource.name(&source), "dependency":!input.selected.contains(&resource),
        }));
    }

    // All managed references must resolve inside the copied graph. Built-in
    // resource identifiers resolve to the corresponding built-ins on the target.
    let mapped = |kind, id| resources[&Resource::new(kind, id)];
    let reference = |kind, value: String| {
        parse_reference(kind, &value).map_or(value, |r| resources[&r].to_string())
    };
    let mut conflicts = Vec::new();
    let mut ports = reserved_ports(old);
    ports.extend(admin_port);
    ports.extend(
        target
            .inbounds
            .values()
            .filter_map(|i| (i.checked_stack()?.listener == Listener::Dedicated).then_some(i.port)),
    );
    let mut paths: Vec<_> = reserved_paths(old).map(str::to_owned).collect();
    paths.extend(
        target
            .inbounds
            .values()
            .filter(|inbound| {
                inbound
                    .checked_stack()
                    .is_some_and(|stack| uses_path_slot(inbound, stack))
            })
            .map(|inbound| inbound.path.clone()),
    );
    for (id, mut inbound) in source.inbounds {
        let Some(stack) = inbound.checked_stack() else {
            conflicts.push(json!({"kind":"inbound","source":id,"code":"copy_capability_missing"}));
            continue;
        };
        let runtime = match inbound.protocol {
            super::Protocol::Tuic => Some(("sing-box", crate::proxy_access::tuic::verify_binary())),
            super::Protocol::Amneziawg => {
                Some(("AmneziaWG", crate::proxy_access::amneziawg::verify_binary()))
            }
            super::Protocol::Masque => {
                Some(("Xray MASQUE", crate::proxy_access::masque::verify_binary()))
            }
            super::Protocol::Mtproto => {
                Some(("mtg-multi", crate::proxy_access::mtproto::verify_binary()))
            }
            _ => None,
        };
        if let Some((name, Err(_))) = runtime {
            conflicts.push(json!({
                "kind":"inbound","source":id,"code":"copy_capability_missing","value":name
            }));
        }
        if stack.listener == Listener::Dedicated && !ports.insert(inbound.port) {
            conflicts.push(json!({"kind":"inbound","source":id,"code":"inbound_port_conflict","value":inbound.port}));
        }
        if uses_path_slot(&inbound, stack) {
            if paths.iter().any(|p| config::overlap(p, &inbound.path)) {
                conflicts.push(json!({"kind":"inbound","source":id,"code":"inbound_path_conflict","value":inbound.path}));
            }
            paths.push(inbound.path.clone());
        }
        inbound.enabled = false;
        inbound.fallback_parent = inbound.fallback_parent.map(|id| mapped(Kind::Inbound, id));
        target.inbounds.insert(mapped(Kind::Inbound, id), inbound);
    }
    for (id, mut host) in source.hosts {
        for (field, value) in [("sni", &host.sni), ("host_header", &host.host_header)] {
            if !value.is_empty() && !old.domains().contains(value) {
                conflicts.push(json!({"kind":"host","source":id,"code":"copy_host_domain","field":field,"value":value}));
            }
        }
        host.enabled = false;
        host.node = LOCAL.into();
        host.inbound = reference(Kind::Inbound, host.inbound);
        target.hosts.insert(mapped(Kind::Host, id), host);
    }
    let mut names: BTreeSet<_> = target
        .groups
        .values()
        .map(|group| group.name.trim().to_owned())
        .collect();
    for (id, mut group) in source.groups {
        if !names.insert(group.name.trim().to_owned()) {
            conflicts.push(
                json!({"kind":"group","source":id,"code":"copy_group_name","value":group.name}),
            );
        }
        group.enabled = false;
        group.inbounds = group
            .inbounds
            .into_iter()
            .map(|id| mapped(Kind::Inbound, id))
            .collect();
        group.hosts = group
            .hosts
            .into_iter()
            .map(|id| mapped(Kind::Host, id))
            .collect();
        target.groups.insert(mapped(Kind::Group, id), group);
    }
    for (id, mut upstream) in source.upstreams {
        upstream.enabled = false;
        upstream.via = upstream.via.map(|id| mapped(Kind::Upstream, id));
        upstream.members = upstream
            .members
            .into_iter()
            .map(|id| mapped(Kind::Upstream, id))
            .collect();
        target
            .upstreams
            .insert(mapped(Kind::Upstream, id), upstream);
    }
    let occupied: BTreeSet<_> = target.rules.values().map(|rule| rule.order).collect();
    let start = occupied.last().map_or(0, |order| order.saturating_add(1));
    let mut rules: Vec<_> = source.rules.into_iter().collect();
    rules.sort_by_key(|(_, rule)| rule.order);
    let mut orders: Vec<_> = (start..=u16::MAX)
        .chain(0..start)
        .filter(|order| !occupied.contains(order))
        .take(rules.len())
        .collect();
    ensure!(orders.len() == rules.len(), "copy_target_validation");
    orders.sort_unstable();
    for ((id, mut rule), order) in rules.into_iter().zip(orders) {
        rule.enabled = false;
        rule.order = order;
        rule.inbounds = rule
            .inbounds
            .into_iter()
            .map(|id| reference(Kind::Inbound, id))
            .collect();
        rule.outbound = reference(Kind::Upstream, rule.outbound);
        target.rules.insert(mapped(Kind::Rule, id), rule);
    }
    if conflicts.is_empty() && config::validate(&candidate, secrets).is_err() {
        conflicts.push(json!({"code":"copy_target_validation"}));
    }
    Ok((candidate, json!({"resources":rows,"conflicts":conflicts})))
}
