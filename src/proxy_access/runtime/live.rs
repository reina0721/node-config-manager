//! Synchronize an installation with the running core over private Unix sockets.
use super::{Database, isolate_core, project};
use crate::{catalogue::device_alias, store::Store};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::Write,
    net::IpAddr,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    process::{Command, Stdio},
};
use uuid::Uuid;

const SOCKET_DIR: &str = "/run/nodectl-proxy-xray";

fn socket(name: &str) -> String {
    format!("{SOCKET_DIR}/{name}-control.sock")
}

pub(super) fn settings(config: &mut Value, name: &str, track_origin: bool) {
    configure_api(config, &socket(name), track_origin);
}

fn configure_api(config: &mut Value, socket: &str, track_origin: bool) {
    config["api"] = json!({
        "tag": "nodectl-runtime-api",
        "listen": format!("{socket},0600"),
        "services": ["HandlerService", "RoutingService", "StatsService"]
    });
    if track_origin {
        config["stats"] = json!({});
        config["policy"]["levels"]["0"]["statsUserOnline"] = json!(true);
    }
}

struct Core<'a> {
    socket: String,
    binary: &'a str,
    geodata: Option<&'a Path>,
}

impl<'a> Core<'a> {
    fn new(name: &str, binary: &'a str, geodata: Option<&'a Path>) -> Self {
        Self {
            socket: socket(name),
            binary,
            geodata,
        }
    }

    fn check_socket(&self) -> Result<()> {
        let info = std::fs::symlink_metadata(&self.socket).context("proxy_runtime_unavailable")?;
        ensure!(
            info.file_type().is_socket() && info.mode() & 0o777 == 0o600,
            "proxy_runtime_unavailable"
        );
        Ok(())
    }

    fn call(&self, verb: &str, args: &[&str]) -> Result<String> {
        self.check_socket()?;
        let socket = &self.socket;
        let mut command = Command::new(self.binary);
        if let Some(geodata) = self.geodata {
            // Xray parses routing matchers in the CLI before the RPC. Match
            // the checked asset directory of the running CN-aware instance.
            command.env("XRAY_LOCATION_ASSET", geodata);
        }
        let reply = command
            .args(["api", verb, "-s", &format!("unix:{socket}"), "-t", "2"])
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .context("proxy_runtime_unavailable")?;
        ensure!(reply.status.success(), "proxy_runtime_update_failed");
        Ok(String::from_utf8(reply.stdout)?)
    }

    fn configure(&self, verb: &str, value: &Value) -> Result<String> {
        // The CLI's add-user command requires a filename. Keep account data
        // out of argv and logs and in a mode-0600, short-lived file instead.
        let mut input = tempfile::NamedTempFile::new()?;
        serde_json::to_writer(&mut input, value)?;
        input.flush()?;
        self.call(
            verb,
            &[input.path().to_str().context("Invalid temporary path")?],
        )
    }

    fn outbounds(&self) -> Result<Value> {
        Ok(serde_json::from_str(&self.call("lso", &[])?)?)
    }

    fn prune(&self, config: &Value, retired: &std::collections::BTreeSet<Uuid>) -> Result<()> {
        let aliases = retired
            .iter()
            .copied()
            .map(device_alias)
            .collect::<std::collections::BTreeSet<_>>();
        self.configure("adrules", &json!({"routing":config["routing"]}))?;
        for row in config["inbounds"]
            .as_array()
            .context("Missing projected inbounds")?
        {
            if !hot_protocol(row) {
                continue;
            }
            let tag = row["tag"].as_str().context("Missing ingress tag")?;
            let users: Value = serde_json::from_str(&self.call("inbounduser", &["-tag", tag])?)?;
            let remove = users["users"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|user| user["email"].as_str())
                .filter(|alias| aliases.contains(*alias))
                .collect::<Vec<_>>();
            if !remove.is_empty() {
                let arguments = ["-tag", tag]
                    .into_iter()
                    .chain(remove.iter().copied())
                    .collect::<Vec<_>>();
                let output = self.call("rmu", &arguments)?;
                ensure!(
                    output
                        .lines()
                        .any(|line| line == format!("Removed {} user(s) in total.", remove.len())),
                    "proxy_runtime_update_failed"
                );
            }
        }
        let active = self.outbounds()?;
        let stale = active["outbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row["tag"].as_str())
            .filter(|tag| aliases.iter().any(|alias| relay_for(tag, alias)))
            .collect::<Vec<_>>();
        if !stale.is_empty() {
            self.call("rmo", &stale)?;
            let active = self.outbounds()?;
            ensure!(
                !active["outbounds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|out| out["tag"].as_str().is_some_and(|tag| stale.contains(&tag))),
                "proxy_runtime_update_failed"
            );
        }
        Ok(())
    }

    fn update(&self, config: &Value, id: Uuid) -> Result<()> {
        let alias = device_alias(id);
        let users = config["inbounds"]
            .as_array()
            .context("Missing projected inbounds")?
            .iter()
            .filter_map(|inbound| user_subset(inbound, &alias))
            .collect::<Vec<_>>();
        if users.is_empty() {
            return Ok(());
        }
        ensure!(
            users.iter().all(hot_protocol),
            "proxy_runtime_protocol_unavailable"
        );

        let routes = config["routing"].clone();
        let active = self.outbounds()?;
        let relays = config["outbounds"]
            .as_array()
            .context("Missing projected relays")?
            .iter()
            .filter(|outbound| {
                outbound["tag"].as_str().is_some_and(|tag| {
                    relay_for(tag, &alias)
                        && !active["outbounds"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|current| current["tag"] == tag)
                })
            })
            .collect::<Vec<_>>();
        if !relays.is_empty() {
            self.configure("ado", &json!({"outbounds":relays}))?;
            let active = self.outbounds()?;
            ensure!(
                relays.iter().all(|relay| active["outbounds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|current| current["tag"] == relay["tag"])),
                "proxy_runtime_update_failed"
            );
        }
        // Replace the complete ordered router view, including the default
        // denying rules. Appending rules behind those rules cannot activate
        // a credential and altering the fallback could bypass authorization.
        self.configure("adrules", &json!({"routing":routes}))?;

        let (peers, standard): (Vec<_>, Vec<_>) = users
            .into_iter()
            .partition(|row| row["protocol"] == "wireguard");
        for peer in peers {
            let tag = peer["tag"].as_str().context("Missing ingress tag")?;
            if !self.has_user(tag, &alias)? {
                self.check_socket()?;
                super::wireguard_api::add_peer(&self.socket, &peer)?;
            }
        }
        if !standard.is_empty() {
            let result = self.configure("adu", &json!({"inbounds":standard}))?;
            let expected = format!("Added {} user(s) in total.", standard.len());
            if !result.lines().any(|line| line == expected) {
                // Xray's CLI exits successfully even when individual adds fail.
                // A previous partial operation or a core restart can already
                // have installed part of this exact projection.
                for row in standard {
                    let tag = row["tag"].as_str().context("Missing ingress tag")?;
                    ensure!(self.has_user(tag, &alias)?, "proxy_runtime_update_failed");
                }
            }
        }

        Ok(())
    }
    fn has_user(&self, tag: &str, alias: &str) -> Result<bool> {
        // A missing user is returned as a gRPC response without users.
        let result = self.call("inbounduser", &["-tag", tag, "-email", alias])?;
        let current: Value = serde_json::from_str(&result)?;
        Ok(current["users"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|user| user["email"] == alias))
    }
}

fn hot_protocol(row: &Value) -> bool {
    matches!(
        row["protocol"].as_str(),
        Some("vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria" | "masque" | "wireguard")
    )
}

fn relay_for(tag: &str, alias: &str) -> bool {
    tag.strip_prefix("portal-") == Some(alias)
        || tag
            .strip_prefix("transit-")
            .and_then(|tag| tag.strip_prefix(alias))
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('-'))
}

fn user_subset(inbound: &Value, alias: &str) -> Option<Value> {
    let mut selected = inbound.clone();
    let settings = selected["settings"].as_object_mut()?;
    let key = ["clients", "accounts", "peers"]
        .into_iter()
        .find(|key| settings.contains_key(*key))?;
    let users = settings.get_mut(key)?.as_array_mut()?;
    users.retain(|user| user["email"] == alias || user["name"] == alias);
    (!users.is_empty()).then_some(selected)
}

pub(in crate::proxy_access) fn install(
    store: &Store,
    data: &Database,
    id: Uuid,
    bootstrap: bool,
) -> Result<()> {
    crate::store::check_private(&store.state_dir, true)?;
    let (_, config, secrets, _, mut core) = project(store, Some(data))?;
    let geodata = config
        .routes_cn()
        .then(crate::cn_warp::runtime_asset_dir)
        .transpose()?;
    let geodata = geodata.as_deref();
    let masque = super::masque::active(&config)
        .then(|| isolate_core(&mut core, |row| row["protocol"] == "masque"))
        .transpose()?;
    let amnezia_tags = super::amneziawg::tags(&config);
    let amnezia = (!amnezia_tags.is_empty())
        .then(|| {
            isolate_core(&mut core, |row| {
                row["tag"]
                    .as_str()
                    .is_some_and(|tag| amnezia_tags.contains(tag))
            })
        })
        .transpose()?;

    let device = data.devices.get(&id).context("not_found")?;
    let attached = |protocol| {
        config.management.iter().any(|catalogue| {
            catalogue.active_inbounds().any(|(inbound, definition)| {
                definition.protocol == protocol
                    && data.install_on_inbound(device, catalogue, inbound)
            })
        })
    };
    ensure!(
        bootstrap || !attached(crate::catalogue::Protocol::Tuic),
        "proxy_runtime_protocol_unavailable"
    );

    Core::new("core", &config.runtime.xray_binary, geodata).update(&core, id)?;
    if !bootstrap {
        if let Some(masque) = masque {
            Core::new("masque", super::masque::BINARY, geodata).update(&masque, id)?;
        }
        if let Some(amnezia) = amnezia {
            Core::new("amneziawg", super::amneziawg::BINARY, geodata).update(&amnezia, id)?;
        }
        if attached(crate::catalogue::Protocol::Mtproto) {
            let pin = super::RelayIdentity::load(store)?.spki_pin()?;
            super::mtproto::refresh(&config, &secrets, data, &pin)?;
        }
    }
    Ok(())
}

pub(in crate::proxy_access) fn activate(store: &Store, data: &Database, id: Uuid) -> Result<()> {
    let config = super::installed(store)?;
    let device = data.devices.get(&id).context("not_found")?;
    if config.management.iter().any(|catalogue| {
        catalogue
            .active_inbounds()
            .any(|(inbound, _)| data.install_on_inbound(device, catalogue, inbound))
    }) {
        install(store, data, id, false)?;
    }
    Ok(())
}

pub(in crate::proxy_access) fn prune(store: &Store, data: &Database) -> Result<()> {
    let (_, config, secrets, _, mut core) = project(store, Some(data))?;
    let geodata = config
        .routes_cn()
        .then(crate::cn_warp::runtime_asset_dir)
        .transpose()?;
    let geodata = geodata.as_deref();
    if super::masque::active(&config) {
        let adapter = isolate_core(&mut core, |row| row["protocol"] == "masque")?;
        Core::new("masque", super::masque::BINARY, geodata).prune(&adapter, &data.retired)?;
    }
    let tags = super::amneziawg::tags(&config);
    if !tags.is_empty() {
        let adapter = isolate_core(&mut core, |row| {
            row["tag"].as_str().is_some_and(|tag| tags.contains(tag))
        })?;
        Core::new("amneziawg", super::amneziawg::BINARY, geodata).prune(&adapter, &data.retired)?;
    }
    if super::mtproto::active(&config) {
        let pin = super::RelayIdentity::load(store)?.spki_pin()?;
        super::mtproto::refresh(&config, &secrets, data, &pin)?;
    }
    Core::new("core", &config.runtime.xray_binary, geodata).prune(&core, &data.retired)
}

pub(in crate::proxy_access) fn origin_ip(store: &Store, id: Uuid) -> Option<IpAddr> {
    let config = super::installed(store).ok()?;
    let core = Core::new("core", &config.runtime.xray_binary, None);
    let value: Value = serde_json::from_str(
        &core
            .call("statsonlineiplist", &["-email", &device_alias(id)])
            .ok()?,
    )
    .ok()?;
    latest_public_origin(&value)
}

fn latest_public_origin(value: &Value) -> Option<IpAddr> {
    value["ips"]
        .as_object()?
        .iter()
        .filter_map(|(address, time)| {
            // Xray's address formatter encloses IPv6 in brackets.
            let address = address
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(address)
                .parse::<IpAddr>()
                .ok()?
                .to_canonical();
            let time = time
                .as_u64()
                .or_else(|| time.as_str()?.parse::<u64>().ok())?;
            super::super::metadata::public_address(address).then_some((time, address))
        })
        .max()
        .map(|(_, address)| address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, process::Child, thread, time::Duration};

    struct Server(Child);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn reads_the_latest_public_address_from_xray_online_statistics() {
        assert_eq!(
            latest_public_origin(&json!({"ips":{
                "8.8.8.8": 10,
                "[2606:4700::1111]": "20",
                "[::1]": 30,
                "192.168.0.1": 40,
                "1.1.1.1": "invalid"
            }})),
            Some("2606:4700::1111".parse().unwrap())
        );
        assert_eq!(
            latest_public_origin(&json!({"ips":{"[::ffff:8.8.8.8]": 10}})),
            Some("8.8.8.8".parse().unwrap())
        );
        assert_eq!(latest_public_origin(&json!({})), None);
    }

    #[test]
    #[ignore = "requires pinned Xray; set NODECTL_ACCESS_TEST_XRAY"]
    fn real_xray_installs_and_reaps_users_without_restarting() -> Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let binary = std::env::var("NODECTL_ACCESS_TEST_XRAY")?;
        let geodata = std::env::var_os("NODECTL_ACCESS_TEST_XRAY_ASSETS").map(PathBuf::from);
        let folder = tempfile::tempdir()?;
        let path = folder.path().join("running.json");
        let api = folder.path().join("api.sock").to_str().unwrap().to_owned();
        let ingress = folder.path().join("inbound.sock");
        let vmess = folder.path().join("vmess.sock");
        let id = Uuid::new_v4();
        let alias = device_alias(id);
        let relay = format!("transit-{alias}");
        let udp = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let udp_port = udp.local_addr()?.port();
        drop(udp);
        let mut base = json!({
            "inbounds":[{"tag":"public","listen":ingress,"protocol":"vless",
                "settings":{"decryption":"none","clients":[]}},
                {"tag":"wg","listen":"127.0.0.1","port":udp_port,"protocol":"wireguard",
                 "settings":{"secretKey":STANDARD.encode([11u8;32]),"address":["10.0.0.1"],
                       "mtu":1280,"peers":[]}},
                {"tag":"managed-vmess","listen":vmess,"protocol":"vmess","settings":{"clients":[]}}],
            "outbounds":[{"tag":"block","protocol":"blackhole"}],
            "routing":{"rules":[{"type":"field","inboundTag":["public"],"outboundTag":"block"}]}
        });
        if geodata.is_some() {
            base["routing"]["rules"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                "type":"field","domain":["geosite:cn"],"ip":["geoip:cn"],"outboundTag":"block"
                }));
        }
        configure_api(&mut base, &api, true);
        fs::write(&path, serde_json::to_vec(&base)?)?;
        let mut process = Command::new(&binary);
        if let Some(geodata) = &geodata {
            process.env("XRAY_LOCATION_ASSET", geodata);
        }
        let mut server = Server(
            process
                .args(["run", "-config"])
                .arg(&path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        for _ in 0..80 {
            if Path::new(&api).exists() && ingress.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let core = Core {
            socket: api,
            binary: &binary,
            geodata: geodata.as_deref(),
        };
        let mut desired = base.clone();
        desired["inbounds"][0]["settings"]["clients"] = json!([{"id":id,"email":alias}]);
        let key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([12u8; 32]));
        desired["inbounds"][1]["settings"]["peers"] = json!([{
            "publicKey":STANDARD.encode(key.as_bytes()),"allowedIPs":["10.0.0.2/32"],"email":alias
        }]);
        desired["inbounds"][2]["settings"]["clients"] = json!([{"id":id,"email":alias}]);
        desired["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"tag":relay,"protocol":"freedom"}));
        desired["routing"]["rules"].as_array_mut().unwrap().insert(
            0,
            json!({
                "type":"field","inboundTag":["public"],"user":[alias],"outboundTag":relay
            }),
        );
        core.update(&desired, id).context("install installation")?;
        core.update(&desired, id).context("retry installation")?;
        let count: Value =
            serde_json::from_str(&core.call("inboundusercount", &["-tag", "public"])?)?;
        assert!(count["count"] == 1 || count["count"] == "1");
        assert!(core.has_user("wg", &alias)?);
        assert!(core.has_user("managed-vmess", &alias)?);
        core.prune(&base, &std::collections::BTreeSet::from([id]))
            .context("prune installation")?;
        let count: Value =
            serde_json::from_str(&core.call("inboundusercount", &["-tag", "public"])?)?;
        assert!(count["count"] == 0 || count["count"] == "0" || count["count"].is_null());
        assert!(!core.has_user("wg", &alias)?);
        assert!(!core.has_user("managed-vmess", &alias)?);
        assert!(server.0.try_wait()?.is_none());
        Ok(())
    }
}
