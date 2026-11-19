use crate::{catalogue, config::Config, host, store};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, path::Path};

pub(crate) const BINARY: &str = "/usr/local/bin/nodectl-xray-amneziawg";
pub(super) const GENERATED: &str = "/run/nodectl-proxy-access/amneziawg.json";
pub(crate) const PARAMETERS: &str = include_str!("../../patches/amneziawg-parameters.conf");

pub(crate) fn tags(config: &Config) -> BTreeSet<String> {
    config
        .management
        .iter()
        .flat_map(|c| c.active_inbounds())
        .filter(|(_, inbound)| inbound.protocol == catalogue::Protocol::Amneziawg)
        .flat_map(|(id, _)| {
            [catalogue::tag(id)]
                .into_iter()
                .chain((!config.node.ipv6.is_empty()).then(|| catalogue::ipv6_tag(id)))
        })
        .collect()
}

pub(crate) fn active(config: &Config) -> bool {
    config
        .management
        .iter()
        .flat_map(|c| c.active_inbounds())
        .any(|(_, inbound)| inbound.protocol == catalogue::Protocol::Amneziawg)
}

pub(crate) fn verify_binary() -> Result<()> {
    host::trusted_binary(Path::new(BINARY)).context("amneziawg_runtime_missing")?;
    ensure!(
        store::file_digest(Path::new(BINARY))?
            == crate::artifacts::component_digest("xray-amneziawg")?,
        "amneziawg_runtime_invalid"
    );
    Ok(())
}
