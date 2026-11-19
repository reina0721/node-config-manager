use super::{Access, Database, amneziawg, gateway, masque, mtproto, tuic};
use crate::{
    config::{self, Config},
    host,
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::Path,
};

const LEGACY_PORT: u16 = 19443;

pub fn reserved_port(port: u16) -> bool {
    [LEGACY_PORT, GATE.port()].contains(&port)
}
pub(super) const GATE: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 19081);
pub(super) const BACKEND: &str = "/run/nodectl-proxy-xray/egress.sock";
const RUNTIME: &str = "/run/nodectl-proxy-access";
const GENERATED: &str = "/run/nodectl-proxy-access/xray.json";
pub(super) const XRAY_CONFIG: &str = "/etc/xray/config.json";
const DROP_IN: &str = "/etc/systemd/system/xray.service.d/91-nodectl-proxy-access.conf";
const SERVICE: &str = "/etc/systemd/system/nodectl-proxy-access.service";
const MARKER: &str = "# Managed by nodectl proxy access\n";
const PUBLIC_TAGS: [&str; 4] = [
    "vless-xhttp",
    "vless-ws",
    "vless-reality",
    "vless-reality-ipv6",
];

#[derive(Serialize, Deserialize)]
pub(super) struct RelayIdentity {
    certificate: Vec<u8>,
    key: Vec<u8>,
}

impl RelayIdentity {
    pub(super) fn load(store: &Store) -> Result<Self> {
        let path = Access(store).dir().join("relay.json");
        store::check_private(&path, false)?;
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    pub(super) fn prepare(store: &Store) -> Result<()> {
        let directory = Access(store).dir();
        let path = directory.join("relay.json");
        if path.exists() {
            Self::load(store)?.tls()?;
            return Ok(());
        }
        let temporary = tempfile::tempdir_in(&directory)?;
        let key = temporary.path().join("key.pem");
        let cert = temporary.path().join("cert.pem");
        host::command(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "3650",
                "-subj",
                "/CN=nodectl-proxy-relay",
                "-keyout",
                key.to_str().context("Invalid relay key path")?,
                "-out",
                cert.to_str().context("Invalid relay certificate path")?,
            ],
        )?;
        let identity = Self {
            certificate: fs::read(cert)?,
            key: fs::read(key)?,
        };
        identity.tls()?;
        store::atomic_write(&path, &serde_json::to_vec(&identity)?)
    }

    pub(super) fn pin(&self) -> Result<String> {
        Ok(store::digest(
            CertificateDer::from_pem_slice(&self.certificate)?.as_ref(),
        ))
    }

    pub(super) fn spki_pin(&self) -> Result<String> {
        tuic::encode_spki(&self.certificate)
    }

    pub(super) fn tls(&self) -> Result<rustls::ServerConfig> {
        let chain = CertificateDer::pem_slice_iter(&self.certificate)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_slice(&self.key)?;
        Ok(
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(chain, key)?,
        )
    }
}

pub(super) fn portal(config: &Config) -> String {
    match config.auth_domain() {
        Some(host) => format!("https://{host}"),
        None => format!("https://{}:{LEGACY_PORT}", config.node.domain),
    }
}

fn installed_source(store: &Store) -> Result<(String, std::path::PathBuf)> {
    // Use the actual service entrypoint, including during apply and recovery,
    // when the committed release pointer can still refer to the old release.
    let source = fs::read_link(XRAY_CONFIG)?;
    let release = source.parent().context("Missing Xray release")?;
    ensure!(
        release.parent() == Some(store.state_dir.join("releases").as_path()),
        "Unmanaged Xray configuration"
    );
    let id = release
        .file_name()
        .and_then(|s| s.to_str())
        .context("Missing Xray release")?;
    ensure!(
        source == store.release(id)?.join("xray.json"),
        "Unmanaged Xray configuration"
    );
    Ok((id.to_owned(), source))
}

pub(super) fn installed(store: &Store) -> Result<Config> {
    let (_, source) = installed_source(store)?;
    let release = source.parent().context("Missing Xray release")?;
    store::check_private(release, true)?;
    let inputs = release.join("source");
    store::check_private(&inputs, true)?;
    Ok(config::load(&inputs)?.0)
}

pub(super) fn validate(store: &Store, binary: &Path) -> Result<()> {
    host::linux_root()?;
    let running = installed(store)?;
    let locked: toml::Value = toml::from_str(include_str!("../../versions.lock.toml"))?;
    let version = locked["xray"]["version"]
        .as_str()
        .context("Missing pinned Xray version")?;
    ensure!(
        host::command(&running.runtime.xray_binary, &["version"])?
            .split_ascii_whitespace()
            .any(|v| v == version),
        "Browser access requires the pinned Xray version"
    );
    for path in [&store.config_dir, &store.state_dir, binary] {
        ensure!(
            config::abs_path(path.to_str().context("Invalid service path")?),
            "Invalid service path"
        );
    }
    check_ports(&running)?;
    super::certificate::verify(&running)?;
    for path in [DROP_IN, SERVICE] {
        if Path::new(path).symlink_metadata().is_ok() {
            store::check_private(Path::new(path), false)?;
            ensure!(
                fs::read_to_string(path)?.starts_with(MARKER),
                "Unmanaged proxy access service"
            );
        }
    }
    Ok(())
}

fn check_ports(config: &Config) -> Result<()> {
    ensure!(
        ![config.ports.http, config.ports.https, config.ports.reality]
            .into_iter()
            .any(reserved_port),
        "Proxy access port conflicts with an existing node port"
    );
    Ok(())
}

pub(super) fn install_units(store: &Store, binary: &Path) -> Result<()> {
    let command = format!(
        "{} --config-dir {} --state-dir {}",
        binary.display(),
        store.config_dir.display(),
        store.state_dir.display()
    );
    let service = format!(
        "{MARKER}[Unit]\nDescription=nodectl browser proxy authorization\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={command} proxy-access serve\nRestart=on-failure\nRestartSec=1\nUMask=0077\nNoNewPrivileges=true\nProtectSystem=strict\nReadWritePaths={}\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n",
        store.state_dir.display()
    );
    let drop_in = format!(
        "{MARKER}[Unit]\nWants=nodectl-proxy-access.service\nAfter=nodectl-proxy-access.service\n\n[Service]\nRuntimeDirectory=nodectl-proxy-xray\nExecStartPre=\nExecStartPre=+{command} proxy-access prepare\nExecStartPre={command} proxy-access check\nExecStart=\nExecStart={command} proxy-access start\n"
    );
    fs::create_dir_all(Path::new(DROP_IN).parent().unwrap())?;
    store::atomic_write(Path::new(SERVICE), service.as_bytes())?;
    store::atomic_write(Path::new(DROP_IN), drop_in.as_bytes())?;
    Ok(())
}

pub(super) fn set_mode(enabled: bool) -> Result<()> {
    if enabled {
        host::command("systemctl", &["daemon-reload"])?;
        host::command("systemctl", &["enable", "--now", "nodectl-proxy-access"])?;
    } else {
        if Path::new(SERVICE).exists() {
            host::command("systemctl", &["disable", "--now", "nodectl-proxy-access"])?;
            fs::remove_file(SERVICE)?;
        }
        if Path::new(DROP_IN).exists() {
            fs::remove_file(DROP_IN)?;
        }
        host::command("systemctl", &["daemon-reload"])?;
    }
    Ok(())
}

pub(super) fn restart(store: &Store) -> Result<()> {
    if super::enabled(store)? {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        loop {
            ensure!(
                std::time::Instant::now() < deadline,
                "Proxy access relay did not become ready"
            );
            if host::command(
                "systemctl",
                &["is-active", "--quiet", "nodectl-proxy-access"],
            )
            .is_ok()
                && std::net::TcpStream::connect_timeout(
                    &GATE,
                    std::time::Duration::from_millis(200),
                )
                .is_ok()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    host::command("systemctl", &["restart", "xray"])?;
    host::verify_live_success(store, &store.pointer("current")?.context("not_deployed")?)
}

pub fn prepare(store: &Store) -> Result<()> {
    super::certificate::verify(&installed(store)?)?;
    let (id, source) = installed_source(store)?;
    let (config, secrets) = store.verify(&id)?;
    check_ports(&config)?;
    let database = Access(store)
        .read()?
        .context("Proxy access state missing")?;
    ensure!(
        database.enabled,
        "Proxy access state disabled while service override is installed"
    );
    let mut json: Value = serde_json::from_slice(&fs::read(source)?)?;
    crate::catalogue::materialize_tls(&config, &mut json)?;
    let identity = RelayIdentity::load(store)?;
    let pin = identity.pin()?;
    let probes = config
        .management
        .as_ref()
        .filter(|m| m.hosts.values().any(|h| h.enabled))
        .map(|_| host::probe_origin(store, &id))
        .transpose()?;
    overlay(
        (&config, &secrets),
        &database,
        &mut json,
        GATE,
        BACKEND,
        &pin,
        probes.as_ref(),
    )?;
    let dir = Path::new(RUNTIME);
    if !dir.exists() {
        fs::DirBuilder::new().mode(0o750).create(dir)?;
    }
    let meta = dir.symlink_metadata()?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "Unsafe proxy access runtime directory"
    );
    let group = format!("root:{}", config.runtime.nginx_user);
    host::command("chown", &[&group, RUNTIME])?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
    let mut files = Vec::new();
    if masque::active(&config) {
        masque::verify_binary()?;
        let adapter = isolate_core(&mut json, |entry| entry["protocol"] == "masque")?;
        files.push((masque::GENERATED.to_string(), serde_json::to_vec(&adapter)?));
    } else if Path::new(masque::GENERATED).exists() {
        fs::remove_file(masque::GENERATED)?;
    }
    if amneziawg::active(&config) {
        amneziawg::verify_binary()?;
        let tags = amneziawg::tags(&config);
        let adapter = isolate_core(&mut json, |entry| {
            entry["tag"].as_str().is_some_and(|tag| tags.contains(tag))
        })?;
        files.push((
            amneziawg::GENERATED.to_string(),
            serde_json::to_vec(&adapter)?,
        ));
    } else if Path::new(amneziawg::GENERATED).exists() {
        fs::remove_file(amneziawg::GENERATED)?;
    }
    files.push((GENERATED.to_string(), serde_json::to_vec(&json)?));
    if tuic::active(&config) {
        tuic::verify_binary()?;
        let config = tuic::render(
            &config,
            &secrets,
            &database,
            &host::probe_origin(store, &id)?,
            &identity.spki_pin()?,
        )?;
        files.push((tuic::GENERATED.to_string(), serde_json::to_vec(&config)?));
    } else if Path::new(tuic::GENERATED).exists() {
        fs::remove_file(tuic::GENERATED)?;
    }
    files.push((
        "/run/nodectl-proxy-access/binary".into(),
        config.runtime.xray_binary.as_bytes().to_vec(),
    ));
    let prior_mtproto = mtproto::instances()?;
    if mtproto::active(&config) {
        mtproto::verify_binary()?;
        files.extend(mtproto::files(
            &config,
            &secrets,
            &database,
            &identity.spki_pin()?,
        )?);
    } else if Path::new(mtproto::INDEX).exists() {
        fs::remove_file(mtproto::INDEX)?;
    }
    let tuns: Vec<_> = config
        .management
        .iter()
        .flat_map(|m| m.active_inbounds())
        .filter_map(|(id, inbound)| inbound.tun.as_ref().map(|tun| (id, tun)))
        .collect();
    for file in fs::read_dir(dir)? {
        let file = file?;
        let name = file.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix("tun-"))
            .and_then(|name| name.strip_suffix(".json"))
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
        else {
            continue;
        };
        if tuns.iter().all(|(active, _)| *active != id) {
            crate::catalogue::tun::Tun::stop(id)?;
            fs::remove_file(file.path())?;
        }
    }
    for (id, tun) in &tuns {
        use crate::catalogue::tun::{Tun, config_path};
        tun.check_namespace(*id)?;
        let credential = Tun::private_id(&secrets.reality_private_key, *id);
        files.push((
            config_path(*id),
            serde_json::to_vec(&tun.worker(*id, credential))?,
        ));
    }
    for (path, bytes) in files {
        store::atomic_write(Path::new(&path), &bytes)?;
        host::command("chown", &[&group, &path])?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640))?;
    }
    for (id, tun) in tuns {
        tun.start(&config, id)?;
    }
    let active_mtproto = mtproto::instances()?;
    for id in prior_mtproto
        .into_iter()
        .filter(|id| !active_mtproto.contains(id))
    {
        let (config, relay) = mtproto::filenames(id);
        for file in [config, relay] {
            if Path::new(&file).exists() {
                fs::remove_file(file)?;
            }
        }
    }
    Ok(())
}

fn isolate_core(xray: &mut Value, select: impl Fn(&Value) -> bool) -> Result<Value> {
    let inbounds = xray["inbounds"]
        .as_array_mut()
        .context("Missing Xray inbounds")?;
    let mut public = Vec::new();
    inbounds.retain(|inbound| {
        if select(inbound) {
            public.push(inbound.clone());
            false
        } else {
            true
        }
    });
    ensure!(!public.is_empty(), "No listeners for managed runtime");
    let mut rules = xray["routing"]["rules"]
        .as_array()
        .context("Missing gateway routes")?
        .clone();
    let tags: Vec<_> = public.iter().map(|inbound| &inbound["tag"]).collect();
    let dns_tags: Vec<_> = xray["dns"]["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|server| &server["tag"])
        .filter(|tag| tag.is_string())
        .collect();
    rules.retain_mut(|rule| {
        let Some(inbounds) = rule["inboundTag"].as_array_mut() else {
            return false;
        };
        inbounds.retain(|tag| tags.contains(&tag) || dns_tags.contains(&tag));
        !inbounds.is_empty()
    });
    let outbounds = xray["outbounds"]
        .as_array()
        .context("Missing gateway outbounds")?;
    let mut selected = vec![json!({"protocol":"blackhole","tag":"block"})];
    for outbound in outbounds {
        if outbound["tag"] != "block"
            && rules
                .iter()
                .any(|rule| rule["outboundTag"] == outbound["tag"])
        {
            selected.push(outbound.clone());
        }
    }
    let mut adapter = json!({
        "log":{"loglevel":"none"},
        "inbounds":public,"outbounds":selected,
        "routing":{
            "domainStrategy":xray["routing"]["domainStrategy"].as_str().unwrap_or("AsIs"),
            "rules":rules
        }
    });
    if xray["dns"].is_object() {
        adapter["dns"] = xray["dns"].clone();
    }
    Ok(adapter)
}

pub fn launch(check: bool) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let binary = fs::read_to_string(Path::new(RUNTIME).join("binary"))?;
    ensure!(config::abs_path(&binary), "Invalid managed Xray executable");
    let mut command = std::process::Command::new(binary);
    command.arg("run");
    if check {
        command.arg("-test");
    }
    command.args(["-config", GENERATED]);
    use std::process::{Command, Stdio};
    let mut adapters = Vec::new();
    for (binary, config, code) in [
        (masque::BINARY, masque::GENERATED, "masque_config_invalid"),
        (
            amneziawg::BINARY,
            amneziawg::GENERATED,
            "amneziawg_config_invalid",
        ),
    ] {
        if Path::new(config).exists() {
            let mut adapter = Command::new(binary);
            adapter.arg("run");
            if check {
                adapter.arg("-test");
            }
            adapter.args(["-config", config]);
            adapters.push((adapter, code));
        }
    }
    if Path::new(tuic::GENERATED).exists() {
        let mut adapter = Command::new(tuic::BINARY);
        adapter.args([if check { "check" } else { "run" }, "-c", tuic::GENERATED]);
        adapters.push((adapter, "tuic_config_invalid"));
    }
    for id in mtproto::instances()? {
        let (config, bridge) = mtproto::filenames(id);
        let mut adapter = Command::new(mtproto::BINARY);
        if check {
            adapter.args(mtproto::check_args(&config));
        } else {
            adapter
                .args(["run", &config])
                .env("NODECTL_MTG_RELAY", bridge);
        }
        adapters.push((adapter, "mtproto_config_invalid"));
    }
    for (adapter, _) in &mut adapters {
        // Each adapter may print a credential on configuration failure.
        adapter.stdout(Stdio::null()).stderr(Stdio::null());
    }
    if check {
        for (mut adapter, code) in adapters {
            ensure!(adapter.status()?.success(), "{code}");
        }
        return Err(command.exec().into());
    }
    if adapters.is_empty() {
        return Err(command.exec().into());
    }
    // The Xray unit owns all of the frontend and backend processes. Restart
    // the entire set on a runtime failure to close stale listener state.
    struct RuntimeSet(Vec<std::process::Child>);
    impl Drop for RuntimeSet {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut running = RuntimeSet(vec![command.spawn()?]);
    for (mut adapter, _) in adapters {
        running.0.push(adapter.spawn()?);
    }
    loop {
        for child in &mut running.0 {
            ensure!(child.try_wait()?.is_none(), "Managed proxy runtime exited");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub(super) fn managed_tags(config: &Config) -> BTreeMap<String, uuid::Uuid> {
    config
        .management
        .iter()
        .flat_map(|catalogue| catalogue.active_inbounds())
        .filter(|(_, inbound)| inbound.tunnel.is_none() && inbound.tun.is_none())
        .flat_map(|(id, inbound)| {
            [(crate::catalogue::tag(id), id)].into_iter().chain(
                (inbound.dedicated()
                    && !matches!(
                        inbound.protocol,
                        crate::catalogue::Protocol::Tuic | crate::catalogue::Protocol::Mtproto
                    )
                    && !config.node.ipv6.is_empty())
                .then(|| (crate::catalogue::ipv6_tag(id), id)),
            )
        })
        .collect()
}

pub(super) fn ingress_id(device: uuid::Uuid, tag: &str) -> uuid::Uuid {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, device.as_bytes());
    let signed = ring::hmac::sign(&key, tag.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&signed.as_ref()[..16]);
    uuid::Builder::from_random_bytes(id).into_uuid()
}

pub(super) struct Ingress {
    pub tag: String,
    pub managed: Option<uuid::Uuid>,
    pub expires: Option<u64>,
    pub groups: Option<BTreeSet<uuid::Uuid>>,
}

pub(super) fn ingress(config: &Config) -> Vec<Ingress> {
    if !per_ingress(config) {
        return Vec::new();
    }
    PUBLIC_TAGS
        .into_iter()
        .map(|tag| Ingress {
            tag: tag.to_owned(),
            managed: None,
            expires: None,
            groups: None,
        })
        .chain(managed_tags(config).into_iter().map(|(tag, id)| {
            let catalogue = config.management.as_ref().expect("managed tag");
            let expires = catalogue.inbounds[&id].expires;
            let groups = catalogue
                .groups
                .iter()
                .filter_map(|(&group, definition)| {
                    (definition.enabled && definition.inbounds.contains(&id)).then_some(group)
                })
                .collect();
            Ingress {
                tag,
                managed: Some(id),
                expires,
                groups: Some(groups),
            }
        }))
        .collect()
}

fn per_ingress(config: &Config) -> bool {
    crate::egress::needs_ingress(config) || !managed_tags(config).is_empty()
}

pub(super) fn backend_for(path: &Path, ingress: &str) -> std::path::PathBuf {
    path.with_file_name(format!("{ingress}.sock"))
}

pub(super) fn overlay(
    source: (&Config, &crate::config::Secrets),
    database: &Database,
    xray: &mut Value,
    gate: SocketAddr,
    backend: &str,
    relay_pin: &str,
    probe: Option<&(String, u16)>,
) -> Result<()> {
    let (config, secrets) = source;
    let inbounds = xray["inbounds"]
        .as_array_mut()
        .context("Missing Xray inbounds")?;
    let mut tags = vec![];
    let tunnels: BTreeMap<_, _> = config
        .management
        .iter()
        .flat_map(|c| c.active_inbounds())
        .filter_map(|(id, inbound)| {
            inbound
                .tunnel
                .as_ref()
                .map(|tunnel| (crate::catalogue::tag(id), (id, tunnel)))
        })
        .collect();
    let managed = managed_tags(config);
    let ingress_routing = per_ingress(config);
    use crate::catalogue::{HEALTH_ALIAS, device_alias, host_probe_alias};
    let hosts = config
        .management
        .iter()
        .flat_map(|m| m.hosts.iter())
        .filter(|(_, host)| host.enabled && probe.is_some());
    let host_probes = hosts
        .map(|(&id, host)| (id, host.inbound.as_str()))
        .collect::<Vec<_>>();
    for inbound in inbounds.iter_mut() {
        let tag = inbound["tag"]
            .as_str()
            .context("Missing Xray inbound tag")?;
        if tunnels.contains_key(tag) {
            ensure!(
                inbound["protocol"] == "tunnel",
                "Unexpected managed Tunnel inbound"
            );
            continue;
        }
        let managed_id = managed.get(tag);
        let managed_inbound = managed_id.and_then(|id| {
            config
                .management
                .as_ref()?
                .inbounds
                .get(id)
                .map(|inbound| (*id, inbound))
        });
        ensure!(
            PUBLIC_TAGS.contains(&tag) || managed_id.is_some(),
            "Unexpected Xray inbound tag"
        );
        tags.push(tag.to_owned());
        let mut accounts = vec![(database.health_id, HEALTH_ALIAS.to_owned())];
        for &(id, target) in &host_probes {
            let matches = if let Some(managed_id) = managed_id {
                target == managed_id.to_string()
            } else {
                tag.strip_prefix("vless-")
                    .map(|kind| kind.trim_end_matches("-ipv6"))
                    == Some(target)
            };
            if matches {
                accounts.push((
                    crate::catalogue::host_probe_id(database.health_id, id),
                    host_probe_alias(id),
                ));
            }
        }
        accounts.extend(
            database
                .devices
                .iter()
                .filter(|(_, device)| {
                    managed_id.is_none_or(|managed_id| {
                        database.install_on_inbound(
                            device,
                            config.management.as_ref().unwrap(),
                            *managed_id,
                        )
                    })
                })
                .map(|(id, _)| (*id, device_alias(*id))),
        );
        crate::catalogue::replace_accounts(inbound, managed_inbound, secrets, accounts)?;
    }
    ensure!(tags.len() >= 3, "Incomplete managed Xray inbounds");

    // Re-enter Xray after the relay so its original direct/CN routing and UDP
    // handling apply to the destination, without replicating either in Rust.
    const BACK_TAG: &str = "nodectl-proxy-egress";
    let mut backend_tags = Vec::new();
    if ingress_routing {
        let backend_ingresses = tags
            .iter()
            .chain(managed.keys().filter(|tag| !tags.contains(tag)));
        for tag in backend_ingresses {
            let ingress = managed.get(tag).map_or_else(
                || {
                    tag.trim_start_matches("vless-")
                        .trim_end_matches("-ipv6")
                        .to_owned()
                },
                |id| id.to_string(),
            );
            let path = backend_for(Path::new(backend), tag);
            let private_tag = format!("egress-{tag}");
            inbounds.push(json!({
                "tag":private_tag,"protocol":"vless","listen":format!("{},0600", path.display()),
                "settings":{"clients":database.devices.values().map(|d| json!({"id":ingress_id(d.transit, tag)})).collect::<Vec<_>>(),"decryption":"none"}
            }));
            backend_tags.push((ingress, private_tag));
        }
    } else {
        inbounds.push(json!({
            "tag":BACK_TAG,"protocol":"vless","listen":format!("{backend},0600"),
            "settings":{"clients":database.devices.values().map(|d| json!({"id":d.transit})).collect::<Vec<_>>(),"decryption":"none"}
        }));
    }
    if let Some(catalogue) = &config.management {
        for (id, _) in catalogue
            .active_inbounds()
            .filter(|(_, inbound)| inbound.tun.is_some())
        {
            use crate::catalogue::tun::{Tun, private_socket};
            let credential = Tun::private_id(&secrets.reality_private_key, id);
            let private_tag = format!("tun-backend-{id}");
            inbounds.push(json!({
                "tag":private_tag,"protocol":"vless","listen":format!("{},0600", private_socket(id)),
                "settings":{"clients":[{"id":credential}],"decryption":"none"}
            }));
            backend_tags.push((id.to_string(), private_tag));
        }
    }
    let outbounds = xray["outbounds"]
        .as_array_mut()
        .context("Missing Xray outbounds")?;
    let mut rules = vec![];
    let amnezia_tags = amneziawg::tags(config);
    if !amnezia_tags.is_empty() {
        rules.push(json!({
            "type":"field","inboundTag":amnezia_tags,"ip":["10.0.0.0/8","fd00::/8"],"outboundTag":"block"
        }));
    }
    let auth_domain = config.auth_domain();
    let portal_host = auth_domain.as_deref().unwrap_or(&config.node.domain);
    let portal_port = if auth_domain.is_some() {
        443
    } else {
        LEGACY_PORT
    };
    for (id, device) in &database.devices {
        let user = device_alias(*id);
        let portal = format!("portal-{user}");
        let transit = format!("transit-{user}");
        rules.push(json!({"type":"field","inboundTag":tags,"user":[user],"network":"tcp","port":portal_port.to_string(),
            "domain":[format!("full:{portal_host}")],"outboundTag":portal}));
        if auth_domain.is_none() {
            rules.push(json!({"type":"field","inboundTag":tags,"user":[user],"network":"tcp","port":LEGACY_PORT.to_string(),
                "ip":config.ips(),"outboundTag":portal}));
        }
        let mut relays = vec![(portal.clone(), device.portal)];
        if ingress_routing {
            for tag in &tags {
                let relay = format!("{transit}-{tag}");
                rules.push(
                    json!({"type":"field","inboundTag":[tag],"user":[user],"outboundTag":relay}),
                );
                relays.push((relay, ingress_id(device.transit, tag)));
            }
        } else {
            rules.push(
                json!({"type":"field","inboundTag":tags,"user":[user],"outboundTag":transit}),
            );
            relays.push((transit, device.transit));
        }
        for (tag, account) in relays {
            outbounds.push(json!({"tag":tag,"protocol":"vless","streamSettings":{"security":"tls","tlsSettings":{
                "minVersion":"1.3","pinnedPeerCertSha256":relay_pin
            }},"settings":{"vnext":[{
                "address":gate.ip().to_string(),"port":gate.port(),"users":[{"id":account,"encryption":"none"}]
            }]}}));
        }
    }
    // Existing rules are only reachable from the private egress or the
    // protected health identity. No shared subscription UUID survives.
    let old = xray["routing"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !xray["routing"].is_object() {
        xray["routing"] = json!({});
    }
    for rule in &old {
        if rule["inboundTag"].is_array() {
            // The snapshot locks additional listeners when the relay does not run.
            if rule["outboundTag"] == "block"
                && rule["inboundTag"].as_array().is_some_and(|tags| {
                    !tags.is_empty()
                        && tags.iter().all(|tag| {
                            tag.as_str().is_some_and(|tag| {
                                managed.contains_key(tag) || tunnels.contains_key(tag)
                            })
                        })
                })
            {
                continue;
            }
            rules.push(rule.clone());
        } else {
            for (tag, (_, tunnel)) in &tunnels {
                rules.push(tunnel.scope(tag, rule.clone()));
            }
            let mut rule = rule.clone();
            rule["inboundTag"] = if ingress_routing {
                json!(backend_tags.iter().map(|(_, tag)| tag).collect::<Vec<_>>())
            } else {
                json!([BACK_TAG])
            };
            rules.push(rule.clone());
            let mut probe = rule;
            probe["inboundTag"] = json!(tags);
            probe["user"] = json!([HEALTH_ALIAS]);
            rules.push(probe);
        }
    }
    if ingress_routing {
        // Resolve an IP criterion when evaluating its position in the list.
        xray["routing"]["domainStrategy"] = json!("IPOnDemand");
        rules.extend(crate::egress::routing(config, &backend_tags));
    }
    for (tag, (id, tunnel)) in &tunnels {
        let identity = [(id.to_string(), tag.clone())];
        for rule in crate::egress::routing(config, &identity) {
            rules.push(tunnel.scope(tag, rule));
        }
        let outbound = format!("tunnel-target-{id}");
        rules.push(tunnel.scope(tag, json!({"type":"field","outboundTag":outbound})));
        rules.push(json!({"type":"field","inboundTag":[tag],"outboundTag":"block"}));
        xray["outbounds"]
            .as_array_mut()
            .context("Missing Xray outbounds")?
            .push(tunnel.direct(&outbound));
    }
    if let Some((target, port)) = probe {
        let mut rule = json!({"type":"field", "inboundTag":tags,"user":host_probes.iter().map(|(id, _)| host_probe_alias(*id)).collect::<Vec<_>>(),"network":"tcp","port":port.to_string(),"outboundTag":"direct"});
        if target.parse::<std::net::IpAddr>().is_ok() {
            rule["ip"] = json!([target]);
        } else {
            rule["domain"] = json!([format!("full:{target}")]);
        }
        rules.push(rule);
    }
    rules.push(
        json!({"type":"field","inboundTag":tags,"user":[HEALTH_ALIAS],"outboundTag":"direct"}),
    );
    rules.push(json!({"type":"field","inboundTag":tags,"outboundTag":"block"}));
    xray["routing"]["rules"] = json!(rules);
    Ok(())
}

pub fn serve(store: &Store) -> Result<()> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(2).enable_all();
    builder.build()?.block_on(gateway::serve(store))
}
