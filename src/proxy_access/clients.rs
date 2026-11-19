use super::{Database, Device};
use crate::{catalogue, config::Config};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Client {
    pub(super) name: String,
    pub(super) inbounds: BTreeSet<Uuid>,
    pub(super) usernames: BTreeSet<String>,
    pub(super) links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) claim_key: Option<Uuid>,
}

impl Client {
    pub(super) fn view(&self, id: Uuid, db: &Database) -> Value {
        json!({"id":id,"name":self.name,"inbounds":self.inbounds,"usernames":self.usernames,"link_count":self.links.len(),
            "claim_enabled":self.claim_key.is_some(),"claim_remaining":db.ready_installations(id)})
    }

    pub(super) fn restrict(&self, config: &Config) -> Config {
        let mut scoped = config.clone();
        if let Some(management) = &mut scoped.management {
            management
                .inbounds
                .retain(|id, _| self.inbounds.contains(id));
            management.hosts.retain(|_, host| {
                host.inbound
                    .parse::<Uuid>()
                    .map_or(true, |id| self.inbounds.contains(&id))
            });
        }
        scoped
    }
}

impl Database {
    pub(super) fn membership(&self, device: &Device, username: &str) -> bool {
        device.client.is_none_or(|id| {
            self.clients
                .get(&id)
                .is_some_and(|profile| profile.usernames.contains(username))
        })
    }

    pub(super) fn client_allows(&self, device: &Device, inbound: Uuid) -> bool {
        device.client.is_none_or(|id| {
            self.clients.get(&id).is_some_and(|profile| {
                profile.usernames.contains(&device.username) && profile.inbounds.contains(&inbound)
            })
        })
    }

    pub(super) fn install_on_inbound(
        &self,
        device: &Device,
        catalogue: &catalogue::Catalogue,
        inbound: Uuid,
    ) -> bool {
        if device.enrollment.is_some() {
            return device
                .client
                .and_then(|id| self.clients.get(&id))
                .is_some_and(|profile| profile.inbounds.contains(&inbound));
        }
        self.client_allows(device, inbound)
            && self
                .users
                .get(&device.username)
                .is_some_and(|account| catalogue.granted(&account.groups, inbound))
    }

    pub(super) fn save_client(
        &mut self,
        installed: &Config,
        id: Option<Uuid>,
        mut profile: Client,
    ) -> Result<bool> {
        ensure!(self.enabled, "policies_require_proxy_access");
        profile.name = profile.name.trim().to_owned();
        ensure!(
            !profile.name.is_empty()
                && profile.name.len() <= 120
                && !profile.name.chars().any(char::is_control)
                && (id.is_some() || self.clients.len() < 128)
                && id.is_none_or(|id| self.clients.contains_key(&id))
                && self.clients.iter().all(|(other, current)| {
                    Some(*other) == id || !current.name.eq_ignore_ascii_case(&profile.name)
                })
                && profile
                    .usernames
                    .iter()
                    .all(|name| self.users.contains_key(name))
                && profile.links.len() <= 32,
            "invalid_client_definition"
        );
        let valid_inbounds = installed
            .management
            .as_ref()
            .into_iter()
            .flat_map(|management| management.active_inbounds())
            .filter(|(_, inbound)| {
                !matches!(
                    inbound.protocol,
                    catalogue::Protocol::Tunnel | catalogue::Protocol::Tun
                )
            })
            .map(|(id, _)| id)
            .collect::<BTreeSet<_>>();
        ensure!(
            profile.inbounds.is_subset(&valid_inbounds),
            "invalid_client_inbound"
        );
        for (index, link) in profile.links.iter().enumerate() {
            crate::render::external::parse(link, index)
                .map_err(|_| anyhow::anyhow!("invalid_external_link:{}", index + 1))?;
        }
        let id = id.unwrap_or_else(Uuid::new_v4);
        let needs_runtime_update = self.clients.get(&id).is_some_and(|previous| {
            !previous.inbounds.is_superset(&profile.inbounds)
                && self.devices.values().any(|device| {
                    device.client == Some(id)
                        && (device.enrollment.is_some()
                            || profile.usernames.contains(&device.username))
                })
        });
        profile.claim_key = self
            .clients
            .get(&id)
            .and_then(|previous| previous.claim_key);
        self.devices.retain(|_, device| {
            device.client != Some(id)
                || device.username.is_empty()
                || profile.usernames.contains(&device.username)
        });
        self.clients.insert(id, profile);
        Ok(needs_runtime_update)
    }
}
