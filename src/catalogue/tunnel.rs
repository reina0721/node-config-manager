use super::Inbound;
use crate::egress;
use anyhow::{Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
    pub listen: IpAddr,
    pub sources: BTreeSet<String>,
    pub target: IpAddr,
    pub target_port: u16,
    pub network: Network,
}

impl Tunnel {
    pub(super) fn validate(&self) -> Result<()> {
        let unicast = |ip: IpAddr| {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        };
        ensure!(
            unicast(self.listen) && unicast(self.target) && self.target_port > 0,
            "invalid_tunnel_endpoint"
        );
        ensure!(
            !self.sources.is_empty()
                && self.sources.len() <= 32
                && self.sources.iter().all(|source| {
                    egress::read_cidr(source).is_some_and(|(address, prefix)| {
                        prefix > 0 && unicast(address) && address.is_ipv6() == self.listen.is_ipv6()
                    })
                }),
            "invalid_tunnel_sources"
        );
        Ok(())
    }

    pub fn tcp(&self) -> bool {
        self.network != Network::Udp
    }

    pub fn udp(&self) -> bool {
        self.network != Network::Tcp
    }

    pub(super) fn inbound(&self, id: Uuid, inbound: &Inbound) -> Value {
        let network = match self.network {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
            Network::Both => "tcp,udp",
        };
        json!({
            "tag":super::tag(id),"listen":self.listen,"port":inbound.port,
            "protocol":"tunnel","settings":{"address":self.target,"port":self.target_port,"network":network}
        })
    }

    pub fn scope(&self, tag: &str, mut rule: Value) -> Value {
        rule["inboundTag"] = json!([tag]);
        rule["sourceIP"] = json!(self.sources);
        rule
    }

    pub fn direct(&self, tag: &str) -> Value {
        let target = if self.target.is_ipv6() {
            format!("[{}]:{}", self.target, self.target_port)
        } else {
            format!("{}:{}", self.target, self.target_port)
        };
        let ip = format!(
            "{}/{}",
            self.target,
            if self.target.is_ipv6() { 128 } else { 32 }
        );
        json!({"tag":tag,"protocol":"freedom","settings":{
            "redirect":target,
            "finalRules":[{"action":"allow","ip":[ip],"port":self.target_port.to_string()}]
        }})
    }
}

pub fn check_listen(inbound: &Inbound) -> Result<()> {
    let info = crate::host::command(
        "ss",
        &["-H", "-lnut", "sport", "=", &format!(":{}", inbound.port)],
    )?;
    let tunnel = inbound.tunnel.as_ref().expect("validated tunnel");
    let has = |kind| {
        info.lines()
            .any(|line| line.split_ascii_whitespace().next() == Some(kind))
    };
    ensure!(
        (!tunnel.tcp() || has("tcp")) && (!tunnel.udp() || has("udp")),
        "Managed tunnel listener is missing"
    );
    Ok(())
}
