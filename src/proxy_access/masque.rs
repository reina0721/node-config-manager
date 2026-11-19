//! The upstream CONNECT-IP core forwards within tunnel pools internally. Only
//! the pinned, peer-isolating build may open managed MASQUE public sockets.
use crate::{catalogue::Protocol, config::Config, host, store};
use anyhow::{Context, Result, ensure};
use std::path::Path;

pub(crate) const BINARY: &str = "/usr/local/bin/nodectl-xray-masque";
pub(super) const GENERATED: &str = "/run/nodectl-proxy-access/masque.json";

pub(crate) fn active(config: &Config) -> bool {
    config.management.as_ref().is_some_and(|catalogue| {
        catalogue
            .active_inbounds()
            .any(|(_, inbound)| inbound.protocol == Protocol::Masque)
    })
}

pub(crate) fn verify_binary() -> Result<()> {
    host::trusted_binary(Path::new(BINARY)).context("masque_runtime_missing")?;
    ensure!(
        store::file_digest(Path::new(BINARY))?
            == crate::artifacts::component_digest("xray-masque")?,
        "masque_runtime_invalid"
    );
    Ok(())
}
