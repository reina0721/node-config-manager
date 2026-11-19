use super::{
    Access, Database,
    meter::{Budget, Online},
    runtime,
};
use crate::{admin_auth, config::Config, store::Store};
use anyhow::{Context, Result, ensure};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use std::{collections::HashMap, io::ErrorKind, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
    sync::{Semaphore, watch},
    time::{interval, timeout},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(250);

#[derive(Default)]
struct Admission {
    transit: HashMap<Uuid, Grant>,
    portals: HashMap<Uuid, Uuid>,
}

#[derive(Clone, PartialEq, Eq)]
struct Grant {
    device: Uuid,
    expires: u64,
    budget: Budget,
    ingress: Option<String>,
}

impl Admission {
    fn from_database(
        store: &Store,
        db: &Database,
        now: u64,
        ingress: &[(String, Option<u64>)],
    ) -> Self {
        let mut result = Self::default();
        let mut capacity = HashMap::new();
        if db.enabled {
            for (profile, device) in &db.devices {
                if let Some(account) = db.users.get(&device.username) {
                    result.portals.insert(device.portal, *profile);
                    if let Some(expiry) = db.expiry(device, now) {
                        let expiry = account
                            .traffic_cycle
                            .as_ref()
                            .map_or(expiry, |cycle| expiry.min(cycle.next_reset));
                        if expiry <= now {
                            continue;
                        }
                        let budget = Budget {
                            ledger: account.ledger_id(),
                            quota: account.quota_bytes,
                        };
                        if *capacity
                            .entry(budget.ledger)
                            .or_insert_with(|| budget.can_send(store).unwrap_or(false))
                        {
                            if ingress.is_empty() {
                                result.transit.insert(
                                    device.transit,
                                    Grant {
                                        device: *profile,
                                        expires: expiry,
                                        budget,
                                        ingress: None,
                                    },
                                );
                            } else {
                                for (tag, end) in ingress {
                                    let expires = expiry.min(end.unwrap_or(u64::MAX));
                                    if expires <= now {
                                        continue;
                                    }
                                    result.transit.insert(
                                        runtime::ingress_id(device.transit, tag),
                                        Grant {
                                            device: *profile,
                                            expires,
                                            budget,
                                            ingress: Some(tag.clone()),
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        result
    }
}

fn state_revision(path: &std::path::Path) -> Option<(u64, i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some((meta.ino(), meta.ctime(), meta.ctime_nsec()))
}

pub(super) async fn serve(store: &Store) -> Result<()> {
    serve_on(
        store,
        TcpListener::bind(runtime::GATE).await?,
        PathBuf::from(runtime::BACKEND),
        runtime::installed,
    )
    .await
}

pub(super) async fn serve_on(
    store: &Store,
    listener: TcpListener,
    backend: PathBuf,
    site: fn(&Store) -> Result<Config>,
) -> Result<()> {
    let (sender, receiver) = watch::channel(Admission::default());
    let refresh = Arc::new(Store::new(
        store.config_dir.clone(),
        store.state_dir.clone(),
    )?);
    let store = refresh.clone();
    let backend = Arc::new(backend);
    let online = Arc::new(Online::default());
    let activity = online.clone();
    tokio::spawn(async move {
        let mut ticks = interval(POLL);
        let access = Access(&refresh);
        let path = access.dir().join("access.json");
        let mut loaded = None;
        let mut database = None;
        let mut installed_revision = None;
        let mut ingress = site(&refresh).ok().map(|config| runtime::ingress(&config));
        let mut last_published = None;
        loop {
            ticks.tick().await;
            let revision = state_revision(&path);
            if revision != loaded {
                database = access.read().ok().flatten();
                // Retry an unreadable record while denying new and existing flows.
                loaded = database.as_ref().and(revision);
            }
            let now = admin_auth::now();
            if database.as_ref().is_some_and(|db| {
                db.users.values().any(|account| {
                    account
                        .traffic_cycle
                        .as_ref()
                        .is_some_and(|cycle| cycle.next_reset <= now)
                })
            }) {
                let store = refresh.clone();
                if let Ok(Ok(updated)) =
                    tokio::task::spawn_blocking(move || Access(&store).reset_due(now)).await
                {
                    database = updated;
                    loaded = None;
                }
            }
            let revision = state_revision(std::path::Path::new(runtime::XRAY_CONFIG));
            if revision != installed_revision || ingress.is_none() {
                ingress = site(&refresh).ok().map(|config| runtime::ingress(&config));
                installed_revision = revision;
            }
            let admission = database
                .as_ref()
                .zip(ingress.as_deref())
                .map(|(db, ingress)| {
                    Admission::from_database(&refresh, db, admin_auth::now(), ingress)
                })
                .unwrap_or_default();
            sender.send_if_modified(|old| {
                if old.transit == admission.transit && old.portals == admission.portals {
                    return false;
                }
                *old = admission;
                true
            });
            let now = admin_auth::now();
            if database.as_ref().is_some_and(|db| db.enabled) && last_published != Some(now) {
                last_published = Some(now);
                let _ = activity.publish(&refresh, now);
            }
        }
    });
    let tls = TlsAcceptor::from(Arc::new(runtime::RelayIdentity::load(&store)?.tls()?));
    let streams = Arc::new(Semaphore::new(4096));
    let logins = Arc::new(Semaphore::new(4));
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        let Ok(permit) = streams.clone().try_acquire_owned() else {
            continue;
        };
        let state = receiver.clone();
        let store = store.clone();
        let logins = logins.clone();
        let backend = backend.clone();
        let tls = tls.clone();
        let online = online.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(Ok(stream)) = timeout(IO_TIMEOUT, tls.accept(stream)).await {
                let _ = connection(store, stream, state, logins, &backend, site, &online).await;
            }
        });
    }
}

async fn connection(
    store: Arc<Store>,
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    mut state: watch::Receiver<Admission>,
    logins: Arc<Semaphore>,
    backend: &std::path::Path,
    site: fn(&Store) -> Result<Config>,
    online: &Online,
) -> Result<()> {
    // The private VLESS credential is generated per device and per purpose.
    // External profiles contain neither internal credential. Transit headers
    // and UDP payloads remain opaque to the relay.
    let mut header = [0u8; 17];
    timeout(IO_TIMEOUT, stream.read_exact(&mut header)).await??;
    ensure!(header[0] == 0, "Unexpected relay protocol version");
    let internal = Uuid::from_slice(&header[1..])?;
    let profile = state.borrow().portals.get(&internal).copied();
    if let Some(profile) = profile {
        timeout(IO_TIMEOUT, portal(store, stream, profile, logins, site)).await??;
        return Ok(());
    }
    let grant = |state: &watch::Receiver<Admission>| {
        state
            .borrow()
            .transit
            .get(&internal)
            .filter(|grant| grant.expires > admin_auth::now())
            .cloned()
    };
    let initial = grant(&state).context("Authorization required")?;
    let backend = initial.ingress.as_deref().map_or_else(
        || backend.to_owned(),
        |tag| runtime::backend_for(backend, tag),
    );
    let mut outbound = UnixStream::connect(backend).await?;
    outbound.write_all(&header).await?;
    let _active = online.enter(initial.device);
    let (up_reader, down_writer) = tokio::io::split(stream);
    let (down_reader, up_writer) = outbound.into_split();
    let upload = forward(up_reader, up_writer, store.clone(), initial.budget, true);
    let download = forward(down_reader, down_writer, store, initial.budget, false);
    let relay = async { tokio::try_join!(upload, download).map(|_| ()) };
    tokio::pin!(relay);
    loop {
        tokio::select! {
            result = &mut relay => {
                result?;
                return Ok(());
            }
            changed = state.changed() => {
                changed?;
                if !grant(&state).is_some_and(|grant| grant.budget == initial.budget && grant.ingress == initial.ingress) {
                    return Ok(());
                }
            }
        }
    }
}

async fn forward(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
    store: Arc<Store>,
    budget: Budget,
    upload: bool,
) -> Result<()> {
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let store = store.clone();
        let allowed =
            tokio::task::spawn_blocking(move || budget.reserve(&store, length, upload)).await??;
        if allowed > 0 {
            writer.write_all(&buffer[..allowed]).await?;
        }
        ensure!(allowed == length, "Proxy traffic quota exhausted");
    }
}

async fn portal(
    store: Arc<Store>,
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    profile: Uuid,
    logins: Arc<Semaphore>,
    site: fn(&Store) -> Result<Config>,
) -> Result<()> {
    // The routed portal outbound selects the address and port. Consume just
    // the VLESS TCP destination header before accepting the browser's TLS.
    let addon_len = stream.read_u8().await?;
    ensure!(
        addon_len == 0 && stream.read_u8().await? == 1,
        "Expected portal TCP connection"
    );
    let _destination_port = stream.read_u16().await?;
    let addr_len = match stream.read_u8().await? {
        1 => 4,
        2 => usize::from(stream.read_u8().await?),
        3 => 16,
        _ => anyhow::bail!("Invalid portal address"),
    };
    stream.read_exact(&mut [0u8; 255][..addr_len]).await?;
    let config = site(&store)?;
    let origin = runtime::portal(&config);
    let cert = std::path::Path::new(&config.tls.domain_cert_dir);
    let chain = CertificateDer::pem_file_iter(cert.join("fullchain.pem"))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(cert.join("privkey.pem"))?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    stream.write_all(&[0, 0]).await?;
    let mut tls = TlsAcceptor::from(Arc::new(tls)).accept(stream).await?;
    let request = request(&mut tls).await?;
    let reply = match (request.method.as_str(), request.path.as_str()) {
        ("GET" | "HEAD", "/") if request.body.is_empty() => {
            let mut reply = response(200, "OK", "登录以使用当前设备的代理节点。");
            if request.method == "HEAD" {
                let end = reply
                    .find("\r\n\r\n")
                    .context("Missing HTTP response separator")?;
                reply.truncate(end + 4);
            }
            reply
        }
        ("POST", "/")
            if request.origin.as_deref() == Some(&origin)
                && request.content_type.as_deref().is_some_and(|value| {
                    value.split(';').next() == Some("application/x-www-form-urlencoded")
                }) =>
        {
            let login: Login = serde_urlencoded::from_bytes(&request.body)?;
            let _permit = logins.try_acquire_owned()?;
            let result = tokio::task::spawn_blocking(move || {
                let _permit = _permit;
                authenticate(&store, profile, login)
            })
            .await??;
            match result {
                LoginResult::Success => response(200, "OK", "认证成功。此设备现在可以使用节点。"),
                LoginResult::Denied => response(
                    401,
                    "Unauthorized",
                    "用户名或密码不正确，或该设备已被撤销。",
                ),
                LoginResult::Limit => response(409, "Conflict", "已达到账号的在线设备上限。"),
                LoginResult::Rate => {
                    response(429, "Too Many Requests", "尝试过于频繁，请一分钟后重试。")
                }
            }
        }
        _ => response(404, "Not Found", "页面不存在。"),
    };
    tls.write_all(reply.as_bytes()).await?;
    tls.shutdown().await?;
    Ok(())
}

struct Request {
    method: String,
    path: String,
    origin: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

async fn request(stream: &mut (impl AsyncReadExt + Unpin)) -> Result<Request> {
    let mut bytes = Vec::new();
    let (mut request, length) = loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).await?;
        ensure!(read > 0, "Incomplete HTTP request");
        bytes.extend_from_slice(&chunk[..read]);
        ensure!(bytes.len() <= 8192, "HTTP request too large");
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut headers);
        let httparse::Status::Complete(offset) = parsed.parse(&bytes)? else {
            continue;
        };
        let header = |name: &str| -> Result<Option<String>> {
            let mut values = parsed
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case(name));
            let value = values
                .next()
                .map(|h| std::str::from_utf8(h.value).map(str::to_owned))
                .transpose()?;
            ensure!(values.next().is_none(), "Duplicate HTTP header");
            Ok(value)
        };
        ensure!(
            header("transfer-encoding")?.is_none(),
            "Unexpected transfer encoding"
        );
        let length = header("content-length")?
            .map(|n| n.parse::<usize>())
            .transpose()?
            .unwrap_or(0);
        ensure!(
            length <= 4096 && bytes.len() - offset <= length,
            "Invalid request body length"
        );
        break (
            Request {
                method: parsed.method.context("Missing HTTP method")?.into(),
                path: parsed.path.context("Missing HTTP path")?.into(),
                origin: header("origin")?,
                content_type: header("content-type")?,
                body: bytes[offset..].to_vec(),
            },
            length,
        );
    };
    let offset = request.body.len();
    request.body.resize(length, 0);
    stream.read_exact(&mut request.body[offset..]).await?;
    Ok(request)
}

fn response(status: u16, reason: &str, message: &str) -> String {
    let body = format!(
        r#"<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>nodectl 节点认证</title><main><h1>节点认证</h1><p role="status">{message}</p><form method="post" action="/"><p><label>用户名 <input name="username" autocomplete="username" required maxlength="64"></label></p><p><label>密码 <input type="password" name="password" autocomplete="current-password" required maxlength="256"></label></p><button>登录</button></form></main></html>"#
    );
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: same-origin\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'\r\n\r\n{body}",
        body.len()
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}

#[derive(Debug, PartialEq, Eq)]
enum LoginResult {
    Success,
    Denied,
    Limit,
    Rate,
}

fn authenticate(store: &Store, id: Uuid, login: Login) -> Result<LoginResult> {
    let access = Access(store);
    let _guard = access.lock()?;
    let mut data = access.read()?.context("Proxy access state missing")?;
    let now = admin_auth::now();
    data.retain_current_grants(now);
    if !data.enabled {
        return Ok(LoginResult::Denied);
    }
    let Some(device) = data.devices.get_mut(&id) else {
        return Ok(LoginResult::Denied);
    };
    device.attempts.retain(|t| now.saturating_sub(*t) < 60);
    if device.attempts.len() >= 5 {
        return Ok(LoginResult::Rate);
    }
    device.attempts.push(now);
    let username = &device.username;
    let Some(account) = data.users.get(username) else {
        return Ok(LoginResult::Denied);
    };
    let budget = Budget {
        ledger: account.ledger_id(),
        quota: account.quota_bytes,
    };
    let outcome = if username != &login.username
        || !account.verify(&login.password)
        || !account.active(now)
        || !budget.can_send(store)?
    {
        LoginResult::Denied
    } else if device.authenticated.is_none()
        && data
            .devices
            .values()
            .filter(|d| d.username == login.username && d.authenticated.is_some())
            .count()
            >= usize::from(account.device_limit)
    {
        LoginResult::Limit
    } else {
        let device = data.devices.get_mut(&id).context("Missing device")?;
        device.authenticated = Some(now);
        device.attempts.clear();
        LoginResult::Success
    };
    access.write(&data)?;
    Ok(outcome)
}
