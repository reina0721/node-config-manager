use crate::{config::Config, egress, host};
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr, path::Path};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tun {
    pub namespace: String,
    pub interface: String,
    pub gateway: Vec<String>,
    pub sources: BTreeSet<String>,
    pub destinations: BTreeSet<String>,
}

impl Tun {
    pub(super) fn validate(&self) -> Result<()> {
        let name = |value: &str, max| {
            !value.is_empty()
                && value.len() <= max
                && value.as_bytes()[0].is_ascii_alphabetic()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        };
        ensure!(
            name(&self.namespace, 32) && name(&self.interface, 15) && self.interface != "lo",
            "invalid_tun_namespace"
        );
        let valid = |entry: &str| {
            egress::read_cidr(entry).is_some_and(|(address, prefix)| {
                prefix != 0 && !address.is_multicast() && !address.is_unspecified()
            })
        };
        ensure!(
            !self.gateway.is_empty()
                && self.gateway.len() <= 2
                && self.gateway.iter().all(|g| g.contains('/') && valid(g))
                && self.gateway.iter().filter(|g| g.contains(':')).count() <= 1
                && self.gateway.iter().filter(|g| !g.contains(':')).count() <= 1
                && !self.sources.is_empty()
                && self.sources.len() <= 32
                && self.sources.iter().all(|entry| valid(entry))
                && !self.destinations.is_empty()
                && self.destinations.len() <= 32
                && self.destinations.iter().all(|entry| valid(entry)),
            "invalid_tun_routes"
        );
        Ok(())
    }

    pub fn active_namespace(&self) -> String {
        format!("/run/netns/{}", self.namespace)
    }

    pub fn device(id: Uuid) -> String {
        format!("nctun{}", &id.simple().to_string()[..10])
    }

    pub fn unit(id: Uuid) -> String {
        format!("nodectl-tun-{id}.service")
    }

    pub fn check_namespace(&self, id: Uuid) -> Result<()> {
        let namespace = self.active_namespace();
        let ns = Path::new(&namespace)
            .symlink_metadata()
            .context("invalid_tun_namespace")?;
        ensure!(!ns.file_type().is_symlink(), "invalid_tun_namespace");
        // A bind mount of the host network namespace must never be used.
        let metadata = Path::new("/proc/self/ns/net").metadata()?;
        let target = Path::new(&namespace).metadata()?;
        use std::os::unix::fs::MetadataExt;
        ensure!(
            (metadata.dev(), metadata.ino()) != (target.dev(), target.ino()),
            "invalid_tun_namespace"
        );
        let links = host::command("ip", &["-n", &self.namespace, "-j", "link", "show"])
            .context("invalid_tun_namespace")?;
        let rows: Vec<Value> = serde_json::from_str(&links)?;
        let device = Self::device(id);
        let mut attached = false;
        for row in rows {
            let name = row["ifname"].as_str().context("invalid_tun_namespace")?;
            if name == self.interface {
                attached = true;
            } else {
                ensure!(name == "lo" || name == device, "invalid_tun_namespace");
            }
        }
        ensure!(
            attached && Path::new("/dev/net/tun").exists(),
            "invalid_tun_namespace"
        );
        for family in [false, true] {
            if self.sources.iter().any(|s| s.contains(':') == family) {
                let knob = if family {
                    "net.ipv6.conf.all.forwarding"
                } else {
                    "net.ipv4.ip_forward"
                };
                let value = host::command(
                    "ip",
                    &["netns", "exec", &self.namespace, "sysctl", "-n", knob],
                )?;
                ensure!(value.trim() == "1", "tun_namespace_forwarding");
            }
        }
        Ok(())
    }

    pub fn private_id(secret: &str, id: Uuid) -> Uuid {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let mut hmac = ring::hmac::Context::with_key(&key);
        hmac.update(b"nodectl/private-tun");
        hmac.update(id.as_bytes());
        uuid::Builder::from_random_bytes(hmac.sign().as_ref()[..16].try_into().unwrap()).into_uuid()
    }

    pub fn worker(&self, id: Uuid, credential: Uuid) -> Value {
        let routes = self
            .destinations
            .iter()
            .map(|range| {
                if range.contains('/') {
                    range.clone()
                } else {
                    let ip: IpAddr = range.parse().expect("validated destination");
                    format!("{range}/{}", if ip.is_ipv6() { 128 } else { 32 })
                }
            })
            .collect::<Vec<_>>();
        json!({
            "log":{"loglevel":"none"},
            "inbounds":[{
                "tag":"ingress","protocol":"tun","settings":{
                    "name":Self::device(id),"mtu":1280,"gateway":self.gateway,
                    "autoSystemRoutingTable":routes,"autoOutboundsInterface":"",
                    "autoSystemDnsToGateway":false
                }
            }],
            "outbounds":[
                {"tag":"block","protocol":"blackhole"},
                {"tag":"relay","protocol":"vless","settings":{"vnext":[{
                    "address":"127.0.0.1","port":19082,"users":[{"id":credential,"encryption":"none"}]
                }]}}
            ],
            "routing":{"rules":[{
                "type":"field","inboundTag":["ingress"],"sourceIP":self.sources,"ip":self.destinations,
                "network":"tcp,udp","outboundTag":"relay"
            }]}
        })
    }

    pub fn stop(id: Uuid) -> Result<()> {
        let service = Self::unit(id);
        let loaded = || {
            Ok::<_, anyhow::Error>(
                !host::command(
                    "systemctl",
                    &["list-units", "--all", "--plain", "--no-legend", &service],
                )?
                .trim()
                .is_empty(),
            )
        };
        if !loaded()? {
            return Ok(());
        }
        host::command("systemctl", &["stop", &service])?;
        for _ in 0..20 {
            if !loaded()? {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        anyhow::bail!("TUN worker did not stop and unload");
    }

    pub fn start(&self, c: &Config, id: Uuid) -> Result<()> {
        Self::stop(id)?;
        let namespace = format!("NetworkNamespacePath={}", self.active_namespace());
        let user = format!("User={}", c.runtime.xray_user);
        let group = format!("Group={}", c.runtime.nginx_user);
        let exe = std::env::current_exe()?;
        let exe = exe.to_str().context("Path encoding")?;
        host::command(
            "systemd-run",
            &[
                "--quiet",
                "--collect",
                "--no-block",
                "--unit",
                &Self::unit(id),
                "-p",
                "After=xray.service",
                "-p",
                "BindsTo=xray.service",
                "-p",
                &namespace,
                "-p",
                &user,
                "-p",
                &group,
                "-p",
                "AmbientCapabilities=CAP_NET_ADMIN",
                "-p",
                "CapabilityBoundingSet=CAP_NET_ADMIN",
                "-p",
                "NoNewPrivileges=true",
                "-p",
                "ProtectSystem=strict",
                exe,
                "proxy-access",
                "tun-worker",
                &c.runtime.xray_binary,
                &id.to_string(),
            ],
        )?;
        Ok(())
    }
}

pub fn config_path(id: Uuid) -> String {
    format!("/run/nodectl-proxy-access/tun-{id}.json")
}

pub fn private_socket(id: Uuid) -> String {
    format!("/run/nodectl-proxy-xray/tun-{id}.sock")
}

pub fn run(binary: &Path, id: Uuid) -> Result<()> {
    host::trusted_binary(binary)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        use std::process::{Child, Command, Stdio};
        use std::sync::Arc;
        use tokio::net::{TcpListener, UnixStream};
        use tokio::sync::Semaphore;

        let relay = TcpListener::bind("127.0.0.1:19082").await?;
        let socket = Arc::new(private_socket(id));
        let slots = Arc::new(Semaphore::new(512));
        let mut watcher = tokio::time::interval(std::time::Duration::from_millis(200));
        struct Worker(Child);
        impl Drop for Worker {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut worker = Worker(Command::new(binary)
            .args(["run", "-config", &config_path(id)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?);
        loop {
            tokio::select! {
                _ = watcher.tick() => ensure!(worker.0.try_wait()?.is_none(), "TUN runtime exited"),
                accepted = relay.accept() => {
                    let (mut connection, _) = accepted?;
                    let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                    let socket = socket.clone();
                    tokio::spawn(async move {
                        let _slot = slot;
                        if let Ok(mut backend) = UnixStream::connect(socket.as_str()).await {
                            let _ = tokio::io::copy_bidirectional(&mut connection, &mut backend).await;
                        }
                    });
                }
            }
        }
    })
}
