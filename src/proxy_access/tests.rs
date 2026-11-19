use super::*;
use anyhow::bail;
use std::{
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

fn device() -> Device {
    Device {
        username: "alice".into(),
        client: None,
        label: "laptop".into(),
        transit: Uuid::new_v4(),
        portal: Uuid::new_v4(),
        authenticated: None,
        attempts: vec![],
        enrollment: None,
    }
}

#[test]
fn enrollment_is_bounded_and_unbound_claims_are_idempotent() -> Result<()> {
    use super::enrollment::ProfileAccess;
    let config: crate::config::Config = toml::from_str(crate::config::EXAMPLE)?;
    let mut db = Database {
        enabled: true,
        ..Default::default()
    };
    db.add_users(vec![("alice", "test-password", 1)])?;
    db.save_client(
        &config,
        None,
        clients::Client {
            name: "shared".into(),
            inbounds: BTreeSet::new(),
            usernames: BTreeSet::from(["alice".into()]),
            links: vec![],
            claim_key: None,
        },
    )?;
    let client = *db.clients.keys().next().unwrap();
    let request = Uuid::new_v4();
    assert!(db.claim_installation(client, request, 100).is_err());
    db.prepare_enrollment(client, 1, 100)?;
    let key = db.clients[&client].claim_key;
    let first = db.claim_installation(client, request, 100)?;
    assert_eq!(db.claim_installation(client, request, 101)?, first);
    assert_eq!(db.ready_installations(client), 0);
    assert_eq!(
        db.claim_installation(client, Uuid::new_v4(), 100)
            .unwrap_err()
            .to_string(),
        "enrollment_exhausted"
    );
    assert!(matches!(
        db.profile_access(&db.devices[&first], 100),
        Some(ProfileAccess::Bootstrap)
    ));
    assert!(db.expiry(&db.devices[&first], 100).is_none());
    assert!(
        db.profile_access(&db.devices[&first], 100 + 86400)
            .is_none()
    );
    db.prepare_enrollment(client, 1, 100 + 86400)?;
    assert_eq!(db.clients[&client].claim_key, key);
    assert!(!db.devices.contains_key(&first));
    assert_ne!(db.claim_installation(client, request, 100 + 86400)?, first);
    Ok(())
}

#[test]
fn shared_client_assignments_revoke_only_the_removed_users_device() -> Result<()> {
    let config: crate::config::Config = toml::from_str(crate::config::EXAMPLE)?;
    let mut db = Database {
        enabled: true,
        ..Default::default()
    };
    db.add_users(vec![
        ("alice", "test-password", 2),
        ("bob", "another-password", 1),
    ])?;
    let mut profile = clients::Client {
        name: "shared".into(),
        inbounds: BTreeSet::new(),
        usernames: BTreeSet::from(["alice".into(), "bob".into()]),
        links: vec![],
        claim_key: None,
    };
    db.save_client(&config, None, profile.clone())?;
    let id = *db.clients.keys().next().unwrap();
    let legacy = Uuid::new_v4();
    db.devices.insert(legacy, device());
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();
    db.devices.insert(
        alice,
        Device {
            client: Some(id),
            ..device()
        },
    );
    db.devices.insert(
        bob,
        Device {
            client: Some(id),
            username: "bob".into(),
            ..device()
        },
    );
    profile.usernames.remove("alice");
    db.save_client(&config, Some(id), profile)?;
    assert!(!db.devices.contains_key(&alice));
    assert!(db.devices.contains_key(&bob));
    assert!(db.devices.contains_key(&legacy));
    assert_ne!(db.devices[&legacy].transit, db.devices[&bob].transit);
    Ok(())
}

#[test]
fn shared_client_attachments_are_intersected_with_account_groups() -> Result<()> {
    let (_tmp, store) = crate::tests::sandbox();
    let (mut config, secrets) = store.inputs()?;
    let mut management = crate::catalogue::Catalogue::default();
    let inbound = |remark: &str, port| {
        serde_json::from_value(json!({
            "remark":remark, "protocol":"vless", "transport":"raw", "security":"tls",
            "listener":"dedicated", "port":port, "path":"", "enabled":true
        }))
    };
    let selected = Uuid::new_v4();
    let other = Uuid::new_v4();
    let group = Uuid::new_v4();
    management
        .inbounds
        .insert(selected, inbound("selected", 25880)?);
    management.inbounds.insert(other, inbound("other", 25881)?);
    management.groups.insert(
        group,
        crate::catalogue::Group {
            name: "granted".into(),
            description: String::new(),
            enabled: true,
            inbounds: BTreeSet::from([selected, other]),
            hosts: BTreeSet::new(),
        },
    );
    config.management = Some(management);
    let definition = clients::Client {
        name: "shared".into(),
        inbounds: BTreeSet::from([selected]),
        usernames: BTreeSet::new(),
        links: vec![],
        claim_key: None,
    };
    let config = definition.restrict(&config);
    for groups in [BTreeSet::from([group]), BTreeSet::new()] {
        let model: Value = serde_json::from_slice(&crate::render::device_profiles_with_links(
            &config,
            &secrets,
            Uuid::new_v4(),
            &groups,
            "mihomo",
            "https://auth.private-example.invalid",
            Some(&[]),
        )?)?;
        let proxies = model["proxies"].as_array().unwrap();
        assert_eq!(proxies.len(), if groups.is_empty() { 6 } else { 7 });
        assert!(!proxies.iter().any(|entry| entry["port"] == 25881));
    }
    Ok(())
}

#[test]
fn passwords_stay_out_of_the_portable_user_list_and_expired_leases_stay_expired() {
    let mut db = Database {
        enabled: true,
        ..Default::default()
    };
    db.add_users(vec![("alice", "123456", 2)]).unwrap();
    assert_eq!(db.export(), json!([{"username":"alice","device_limit":2}]));
    assert!(db.users["alice"].verify("123456"));
    assert!(!db.users["alice"].verify("bad password"));
    assert!(
        serde_json::from_value::<Change>(json!({"action":"import","users":[
        {"username":"eve","password":"unexpected"}]}))
        .is_err()
    );
    let id = Uuid::new_v4();
    let mut entry = device();
    entry.authenticated = Some(100);
    db.devices.insert(id, entry);
    assert_eq!(db.expiry(&db.devices[&id], 100), Some(100 + DEFAULT_TTL));
    db.retain_current_grants(100 + DEFAULT_TTL);
    db.ttl_seconds += 300;
    assert_eq!(db.expiry(&db.devices[&id], 100 + DEFAULT_TTL), None);
}

#[test]
fn device_profiles_can_be_issued_before_enabling_access() -> Result<()> {
    let (_tmp, store) = crate::tests::sandbox();
    let current = store.render()?;
    store.set_pointer("current", Some(&current))?;
    let (config, secrets) = store.inputs()?;
    let id = Uuid::new_v4();
    let access = Access(&store);
    let _guard = access.lock()?;
    let mut db = Database::default();
    db.add_users(vec![("alice", "test-password", 1)])?;
    db.devices.insert(id, device());
    access.write(&db)?;
    assert!(!enabled(&store)?);

    let mihomo: Value = serde_json::from_str(&profile(&store, id, "mihomo")?)?;
    let original: Value = serde_json::from_slice(&crate::render::mihomo(&config, &secrets)?)?;
    let proxies = mihomo["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), original["proxies"].as_array().unwrap().len());
    assert!(proxies.iter().all(|node| node["uuid"] == id.to_string()));
    Ok(())
}

#[test]
fn subscriptions_follow_the_device_and_are_revoked_without_disabling_the_service() -> Result<()> {
    let (_tmp, store) = crate::tests::sandbox();
    drop(store.lock()?);
    let (mut c, _) = store.inputs()?;
    c.distribution = Some(crate::config::Distribution { enabled: true });
    store::atomic_write(
        &store.config_dir.join("node.toml"),
        toml::to_string_pretty(&c)?.as_bytes(),
    )?;
    let current = store.render()?;
    store.set_pointer("current", Some(&current))?;
    let success = store.state_dir.join("success");
    store::private_dir(&success)?;
    store::atomic_write(
        &success.join(&current),
        &serde_json::to_vec(&json!({"release":current}))?,
    )?;
    crate::share::rotate(&store, None)?;
    let access = Access(&store);
    let guard = access.lock()?;
    let mut db = Database {
        enabled: true,
        ..Default::default()
    };
    db.add_users(vec![("alice", "test-password", 2)])?;
    let id = Uuid::new_v4();
    let second = Uuid::new_v4();
    db.devices.insert(id, device());
    db.devices.insert(second, device());
    access.write(&db)?;
    drop(guard);

    let token = |id| -> Result<String> {
        let data: Value = serde_json::from_str(&profile(&store, id, "subscriptions")?)?;
        Ok(data["token"].as_str().context("subscription token")?.into())
    };
    let get = |path: &str, token: &str| -> Result<String> {
        let request = format!("GET {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n");
        let mut exchange = std::io::Cursor::new(request.as_bytes().to_vec());
        crate::share_http::connection(&store, &mut exchange)?;
        Ok(String::from_utf8(
            exchange.into_inner().split_off(request.len()),
        )?)
    };
    let first = token(id)?;
    let second_token = token(second)?;
    for format in ["xray", "mihomo", "mihomo-weighted"] {
        let response = get(&format!("/nodes/sub/{format}"), &first)?;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            response.split_once("\r\n\r\n").unwrap().1,
            profile(&store, id, format)?
        );
        assert!(!response.contains(&second.to_string()));
        assert!(!response.contains(&db.devices[&id].portal.to_string()));
    }
    assert!(get("/nodes/api", &second_token)?.contains(&second.to_string()));
    let weighted: Value = serde_json::from_str(&profile(&store, id, "mihomo-weighted")?)?;
    assert_eq!(
        weighted["proxy-groups"][1]["url"],
        format!("{}/", runtime::portal(&c))
    );
    assert!(get("/nodes/api", &first[32..].repeat(2))?.starts_with("HTTP/1.1 401"));
    crate::share::rotate(&store, None)?;
    assert!(get("/nodes/api", &first)?.starts_with("HTTP/1.1 401"));
    let fresh = token(id)?;
    assert!(get("/nodes/api", &fresh)?.starts_with("HTTP/1.1 200"));
    let guard = access.lock()?;
    db.devices.remove(&id);
    access.write(&db)?;
    drop(guard);
    assert!(get("/nodes/api", &fresh)?.starts_with("HTTP/1.1 401"));
    assert!(get("/nodes/sub/mihomo-weighted", &fresh)?.starts_with("HTTP/1.1 401"));
    let unaffected = token(second)?;
    assert!(get("/nodes/api", &unaffected)?.starts_with("HTTP/1.1 200"));
    crate::share::revoke(&store)?;
    assert!(get("/nodes/api", &unaffected)?.starts_with("HTTP/1.1 401"));
    assert!(get("/nodes/", "")?.starts_with("HTTP/1.1 200"));
    assert!(enabled(&store)?);
    Ok(())
}

struct FixtureProcess(Child);
impl Drop for FixtureProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn execute(mut cmd: Command) -> Result<Output> {
    let result = cmd.output()?;
    if !result.status.success() {
        bail!(
            "Fixture command failed {:?}: {} {}",
            cmd,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(result)
}
fn start(binary: &Path, folder: &Path, name: &str, config: Value) -> Result<FixtureProcess> {
    let file = folder.join(name);
    fs::write(&file, serde_json::to_vec(&config)?)?;
    let mut verify = Command::new(binary);
    verify.args(["run", "-test", "-c"]).arg(&file);
    execute(verify)?;
    Ok(FixtureProcess(
        Command::new(binary)
            .args(["run", "-c"])
            .arg(file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    ))
}
fn start_mihomo(
    binary: &Path,
    folder: &Path,
    inbound: SocketAddr,
    server: SocketAddr,
    id: Uuid,
) -> Result<FixtureProcess> {
    let config = folder.join("mihomo.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "mixed-port":inbound.port(), "bind-address":inbound.ip().to_string(), "mode":"rule",
            "proxies":[{"name":"fixture-device","type":"vless","server":server.ip().to_string(),
                        "port":server.port(),"uuid":id,"network":"tcp","udp":true}],
            "rules":["MATCH,fixture-device"]
        }))?,
    )?;
    Ok(FixtureProcess(
        Command::new(binary)
            .arg("-d")
            .arg(folder)
            .arg("-f")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    ))
}

fn unused() -> Result<SocketAddr> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?)
}
async fn ready(address: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        if TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(40)).await;
    }
    bail!("Xray fixture did not come up")
}

async fn socks_request(
    socks: SocketAddr,
    command: u8,
    port: u16,
) -> Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    ensure!(greeting == [5, 0], "SOCKS negotiation failed");
    let [high, low] = port.to_be_bytes();
    stream
        .write_all(&[5, command, 0, 1, 127, 0, 0, 1, high, low])
        .await?;
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply[..4] == [5, 0, 0, 1],
        "SOCKS request failed: {reply:?}"
    );
    let bind = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    Ok((stream, bind))
}

async fn curl(socks: Option<SocketAddr>, args: Vec<String>) -> Result<Output> {
    tokio::task::spawn_blocking(move || {
        let mut curl = Command::new("curl");
        curl.args([
            "--disable",
            "--silent",
            "--show-error",
            "--max-time",
            "4",
            "--noproxy",
            "",
        ]);
        if let Some(socks) = socks {
            curl.args(["--socks5-hostname", &socks.to_string()]);
        }
        Ok(curl.args(args).output()?)
    })
    .await?
}

#[tokio::test]
#[ignore = "requires pinned Xray, curl and openssl; set NODECTL_ACCESS_TEST_XRAY"]
async fn real_xray_denies_unauthenticated_traffic_and_revokes_existing_connections() -> Result<()> {
    let binary = PathBuf::from(std::env::var("NODECTL_ACCESS_TEST_XRAY")?);
    let (tmp, store) = crate::tests::sandbox();
    let (mut config, _) = store.inputs()?;
    config.tls.domain_cert_dir = tmp.path().to_str().unwrap().into();
    if std::env::var_os("NODECTL_ACCESS_TEST_ROUTING").is_some() {
        let management = config.management.get_or_insert_with(Default::default);
        management.rules.insert(
            Uuid::new_v4(),
            crate::egress::Rule {
                name: "Only the XHTTP ingress may reach the echo service".into(),
                order: 0,
                enabled: true,
                inbounds: ["xhttp".into()].into(),
                domains: vec![],
                ips: vec!["127.0.0.0/8".into()],
                port_min: None,
                port_max: None,
                network: None,
                outbound: "direct".into(),
            },
        );
        management.rules.insert(
            Uuid::new_v4(),
            crate::egress::Rule {
                name: "Reject other ingress traffic".into(),
                order: 1,
                enabled: true,
                inbounds: Default::default(),
                domains: vec![],
                ips: vec![],
                port_min: None,
                port_max: None,
                network: None,
                outbound: "block".into(),
            },
        );
    }
    store::atomic_write(
        &store.config_dir.join("node.toml"),
        toml::to_string(&config)?.as_bytes(),
    )?;
    let key = tmp.path().join("privkey.pem");
    let cert = tmp.path().join("fullchain.pem");
    let mut openssl = Command::new("openssl");
    openssl
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            &format!("/CN={}", config.node.domain),
            "-addext",
            &format!("subjectAltName=DNS:{}", config.node.domain),
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert);
    execute(openssl)?;

    let access = Access(&store);
    let lock = access.lock()?;
    let mut db = Database {
        enabled: true,
        ..Default::default()
    };
    db.add_users(vec![("alice", "test-password", 1)])?;
    let id = Uuid::new_v4();
    let second = Uuid::new_v4();
    db.devices.insert(id, device());
    db.devices.insert(second, device());
    access.write(&db)?;
    runtime::RelayIdentity::prepare(&store)?;
    let pin = runtime::RelayIdentity::load(&store)?.pin()?;
    drop(lock);

    let gate = TcpListener::bind("127.0.0.1:0").await?;
    let address = gate.local_addr()?;
    let backend = tmp.path().join("egress.sock");
    let copy = Store::new(store.config_dir.clone(), store.state_dir.clone())?;
    let socket = backend.clone();
    let _gateway = tokio::spawn(async move {
        gateway::serve_on(&copy, gate, socket, |store| Ok(store.inputs()?.0)).await
    });
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let target_port = target.local_addr()?.port();
    let _echo = tokio::spawn(async move {
        while let Ok((mut peer, _)) = target.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 2048];
                let count = peer.read(&mut buffer).await.unwrap_or(0);
                if buffer[..count].starts_with(b"hold") {
                    let _ = peer.write_all(b"open").await;
                    let _ = peer.read(&mut buffer).await;
                } else {
                    let _ = peer
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .await;
                }
            });
        }
    });

    let udp = UdpSocket::bind(("127.0.0.1", target_port)).await?;
    let _udp_echo = tokio::spawn(async move {
        let mut bytes = [0; 512];
        while let Ok((size, source)) = udp.recv_from(&mut bytes).await {
            let _ = udp.send_to(&bytes[..size], source).await;
        }
    });

    let front = unused()?;
    let socks = unused()?;
    let socks_second = unused()?;
    let old = Uuid::new_v4();
    let socks_old = unused()?;
    let mut server = json!({
        "log":{"loglevel":"none"},
        "inbounds":(["vless-xhttp","vless-ws","vless-reality"].into_iter().enumerate().map(|(i, tag)|
            json!({"tag":tag,"protocol":"vless","listen":if i == 0 { front.ip().to_string() } else {tmp.path().join(tag).display().to_string()},
              "port":front.port(),"settings":{"clients":[{"id":old}],"decryption":"none"}})).collect::<Vec<_>>()),
        "outbounds":[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[
            {"action":"allow","ip":["127.0.0.1/32"],"port":target_port.to_string()}
        ]}},{"tag":"block","protocol":"blackhole"}]
    });
    runtime::overlay(
        (&config, &store.inputs()?.1),
        &db,
        &mut server,
        address,
        backend.to_str().unwrap(),
        &pin,
        None,
    )?;
    let _server = start(&binary, tmp.path(), "server.json", server)?;
    ready(front).await?;
    let mut clients =
        json!({"log":{"loglevel":"none"},"inbounds":[],"outbounds":[],"routing":{"rules":[]}});
    for (socks, user) in [(socks, id), (socks_second, second), (socks_old, old)] {
        let tag = format!("socks-{}", socks.port());
        clients["inbounds"].as_array_mut().unwrap().push(json!({
            "tag":tag,"protocol":"socks","listen":socks.ip().to_string(),"port":socks.port(),"settings":{"udp":true}
        }));
        clients["outbounds"].as_array_mut().unwrap().push(json!({"tag":tag,"protocol":"vless","settings":{"vnext":[{
            "address":front.ip().to_string(),"port":front.port(),"users":[{"id":user,"encryption":"none"}]
        }]}}));
        clients["routing"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"field","inboundTag":[tag],"outboundTag":tag}));
    }
    let _client = start(&binary, tmp.path(), "client.json", clients)?;
    ready(socks).await?;
    let mihomo = if let Some(path) = std::env::var_os("NODECTL_ACCESS_TEST_MIHOMO") {
        let address = unused()?;
        let process = start_mihomo(Path::new(&path), tmp.path(), address, front, id)?;
        ready(address).await?;
        Some((process, address))
    } else {
        None
    };

    let portal = runtime::portal(&config);
    let portal_args = vec![
        "--cacert".into(),
        cert.display().to_string(),
        portal.clone(),
    ];
    let target = || vec![format!("http://127.0.0.1:{target_port}/")];
    let assert_reply = |reply: Output, expected: &str| {
        assert!(
            String::from_utf8_lossy(&reply.stdout).contains(expected),
            "Expected {expected:?}; output: {}; HTTP error: {}",
            String::from_utf8_lossy(&reply.stdout),
            String::from_utf8_lossy(&reply.stderr)
        );
    };
    assert!(!curl(Some(socks), target()).await?.status.success());
    if let Some((_, address)) = &mihomo {
        assert!(!curl(Some(*address), target()).await?.status.success());
        assert_reply(curl(Some(*address), portal_args.clone()).await?, "节点认证");
    }
    let mut direct = portal_args.clone();
    direct.extend([
        "--resolve".into(),
        format!("{}:19443:127.0.0.1", config.node.domain),
    ]);
    assert!(!curl(None, direct).await?.status.success());
    assert!(
        !curl(Some(socks_old), portal_args.clone())
            .await?
            .status
            .success()
    );
    assert_reply(curl(Some(socks), portal_args.clone()).await?, "节点认证");
    let mut health_check = portal_args.clone();
    health_check.push("--head".into());
    let reply = curl(Some(socks), health_check).await?;
    assert!(reply.stdout.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(reply.stdout.ends_with(b"\r\n\r\n"));
    assert!(!curl(Some(socks), target()).await?.status.success());
    // A no-referrer policy would serialize a browser navigation POST's Origin
    // as null. Keep the same-origin form compatible with the strict check.
    let mut page_headers = portal_args.clone();
    page_headers.extend(["--dump-header".into(), "-".into()]);
    assert_reply(
        curl(Some(socks), page_headers).await?,
        "Referrer-Policy: same-origin\r\n",
    );
    let mut foreign_login = portal_args.clone();
    foreign_login.extend([
        "-H".into(),
        "Origin: null".into(),
        "-d".into(),
        "username=alice&password=test-password".into(),
    ]);
    assert_reply(curl(Some(socks), foreign_login).await?, "页面不存在");
    assert!(!curl(Some(socks), target()).await?.status.success());
    let mut login = portal_args.clone();
    login.extend([
        "-H".into(),
        format!("Origin: {portal}"),
        "-d".into(),
        "username=alice&password=test-password".into(),
    ]);
    assert_reply(curl(Some(socks), login.clone()).await?, "认证成功");
    sleep(Duration::from_millis(350)).await;
    assert_reply(curl(Some(socks), target()).await?, "OK");
    if let Some((_, address)) = &mihomo {
        assert_reply(curl(Some(*address), target()).await?, "OK");
    }
    assert_reply(
        curl(Some(socks_second), login.clone()).await?,
        "已达到账号的在线设备上限",
    );
    assert!(!curl(Some(socks_second), target()).await?.status.success());

    let (mut open, _) = socks_request(socks, 1, target_port).await?;
    open.write_all(b"hold").await?;
    let mut marker = [0; 4];
    timeout(Duration::from_secs(3), open.read_exact(&mut marker))
        .await
        .context("Open TCP fixture did not respond")??;
    assert_eq!(&marker, b"open");

    let (udp_session, relay) = socks_request(socks, 3, 0).await?;
    let datagram = UdpSocket::bind("127.0.0.1:0").await?;
    let [high, low] = target_port.to_be_bytes();
    let packet = [0, 0, 0, 1, 127, 0, 0, 1, high, low, 42];
    datagram.send_to(&packet, relay).await?;
    let mut reply = [0; 33];
    let (length, _) = timeout(Duration::from_secs(3), datagram.recv_from(&mut reply))
        .await
        .context("UDP fixture did not respond")??;
    assert_eq!(&reply[..length], &packet);
    drop(udp_session);

    {
        let _guard = access.lock()?;
        let mut expired = access.read()?.context("Missing access state")?;
        expired.devices.get_mut(&id).unwrap().authenticated =
            Some(admin_auth::now().saturating_sub(expired.ttl_seconds));
        access.write(&expired)?;
    }
    sleep(Duration::from_millis(350)).await;
    assert!(!curl(Some(socks), target()).await?.status.success());
    assert_reply(curl(Some(socks), login).await?, "认证成功");
    sleep(Duration::from_millis(350)).await;
    let (mut open, _) = socks_request(socks, 1, target_port).await?;
    open.write_all(b"hold").await?;
    timeout(Duration::from_secs(3), open.read_exact(&mut marker)).await??;
    assert_eq!(&marker, b"open");

    super::change(
        &store,
        Change::Delete {
            usernames: vec!["alice".into()],
        },
        Path::new("/unused"),
    )?;
    let result = timeout(Duration::from_secs(6), open.read(&mut marker))
        .await
        .context("Revocation did not close TCP connection")?;
    assert!(result.is_err() || result? == 0);
    assert!(!curl(Some(socks), target()).await?.status.success());
    assert!(!curl(Some(socks), portal_args).await?.status.success());
    Ok(())
}

#[test]
fn scheduled_usage_reset_keeps_the_interval_across_restarts() -> Result<()> {
    let (_tmp, store) = crate::tests::sandbox();
    let access = Access(&store);
    let guard = access.lock()?;
    let now = admin_auth::now();
    let mut account = Account::new("local-traffic-test", 1)?;
    let previous = account.ledger_id();
    account.traffic_cycle = Some(TrafficCycle {
        next_reset: now - 125,
        interval_seconds: 60,
    });
    let mut profile = device();
    profile.authenticated = Some(now - 100);
    let id = Uuid::new_v4();
    access.write(&Database {
        enabled: true,
        users: BTreeMap::from([("alice".into(), account)]),
        devices: BTreeMap::from([(id, profile)]),
        ..Default::default()
    })?;
    assert!(access.reset_due(now).is_err());
    drop(guard);

    assert!(has_traffic_cycles(&store)?);
    assert!(crate::upgrade::validate_web(&store, "v0.9.0").is_err());
    let updated = access
        .reset_due(now)?
        .context("Missing test access state")?;
    let rotated = updated.users["alice"].ledger_id();
    assert_ne!(rotated, previous);
    assert_eq!(updated.devices[&id].authenticated, None);
    assert_eq!(
        updated.users["alice"]
            .traffic_cycle
            .as_ref()
            .unwrap()
            .next_reset,
        now + 55
    );
    let reopened = Access(&store).reset_due(now + 30)?.unwrap();
    assert_eq!(reopened.users["alice"].ledger_id(), rotated);
    Ok(())
}
