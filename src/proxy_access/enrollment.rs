use super::{
    Access, Account, Database, Device, MAX_DEVICES, admin_auth, runtime, subscription_token,
};
use crate::{config::Config, store::Store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{fs::FileTypeExt, net::UnixStream},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::Semaphore,
    time::timeout,
};
use uuid::Uuid;

const CLAIM_TTL: u64 = 24 * 60 * 60;
const MAX_BATCH: usize = 32;
const REQUEST_LIMIT: u64 = 1024;
const REPLY_LIMIT: u64 = 4096;

#[derive(Serialize, Deserialize)]
struct ClaimRequest {
    key: Uuid,
    request: Uuid,
    origin: String,
}

#[derive(Serialize, Deserialize)]
struct ClaimReply {
    status: u16,
    payload: Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Enrollment {
    Ready,
    Claimed { request: Uuid, expires: u64 },
}

pub(super) enum ProfileAccess<'a> {
    Bootstrap,
    Account(&'a Account),
}

impl Device {
    pub(super) fn awaiting_login(&self, now: u64) -> bool {
        self.username.is_empty()
            && matches!(self.enrollment, Some(Enrollment::Claimed { expires, .. }) if expires > now)
    }
}

impl Database {
    pub(super) fn ready_installations(&self, client: Uuid) -> usize {
        self.devices
            .values()
            .filter(|device| {
                device.client == Some(client)
                    && matches!(device.enrollment, Some(Enrollment::Ready))
            })
            .count()
    }

    pub(super) fn prepare_enrollment(
        &mut self,
        client: Uuid,
        count: usize,
        now: u64,
    ) -> Result<()> {
        ensure!(self.enabled, "enrollment_requires_proxy_access");
        ensure!((1..=MAX_BATCH).contains(&count), "invalid_enrollment_count");
        let definition = self.clients.get_mut(&client).context("not_found")?;
        self.devices.retain(|_, device| {
            !device.username.is_empty()
                || !matches!(device.enrollment, Some(Enrollment::Claimed { expires, .. }) if expires <= now)
        });
        ensure!(
            self.devices.len() + count <= MAX_DEVICES,
            "enrollment_capacity"
        );
        definition.claim_key.get_or_insert_with(Uuid::new_v4);
        for _ in 0..count {
            self.devices.insert(
                Uuid::new_v4(),
                Device {
                    username: String::new(),
                    client: Some(client),
                    label: "Subscription installation".into(),
                    transit: Uuid::new_v4(),
                    portal: Uuid::new_v4(),
                    authenticated: None,
                    attempts: Vec::new(),
                    enrollment: Some(Enrollment::Ready),
                },
            );
        }
        Ok(())
    }

    pub(super) fn claim_installation(
        &mut self,
        client: Uuid,
        request: Uuid,
        now: u64,
    ) -> Result<Uuid> {
        ensure!(self.enabled && !request.is_nil(), "not_found");
        ensure!(
            self.clients
                .get(&client)
                .is_some_and(|definition| definition.claim_key.is_some()),
            "not_found"
        );
        if let Some((&id, device)) = self.devices.iter().find(|(_, device)| {
            device.client == Some(client)
                && matches!(device.enrollment, Some(Enrollment::Claimed { request: previous, .. }) if previous == request)
        }) {
            self.profile_access(device, now).context("not_found")?;
            return Ok(id);
        }
        let (&id, device) = self
            .devices
            .iter_mut()
            .find(|(_, device)| {
                device.client == Some(client)
                    && matches!(device.enrollment, Some(Enrollment::Ready))
            })
            .context("enrollment_exhausted")?;
        device.enrollment = Some(Enrollment::Claimed {
            request,
            expires: now + CLAIM_TTL,
        });
        device.label = format!("Subscription {}", &id.simple().to_string()[..8]);
        Ok(id)
    }

    pub(super) fn profile_access(&self, device: &Device, now: u64) -> Option<ProfileAccess<'_>> {
        if device.awaiting_login(now) {
            let client = self.clients.get(&device.client?)?;
            return (self.enabled && client.claim_key.is_some())
                .then_some(ProfileAccess::Bootstrap);
        }
        let account = self.users.get(&device.username)?;
        (account.active(now) && self.membership(device, &device.username))
            .then_some(ProfileAccess::Account(account))
    }
}

pub(super) fn origin(config: &Config) -> String {
    let port = config.ports.https;
    let domain = &config.node.domain;
    if port == 443 {
        format!("https://{domain}")
    } else {
        format!("https://{domain}:{port}")
    }
}

fn claim(store: &Store, input: ClaimRequest) -> Result<Value> {
    // Serialize against runtime preparation and configuration changes.
    let _host = store.lock()?;
    ensure!(!crate::upgrade::pending(store)?, "operation_busy");
    let config = runtime::installed(store)?;
    ensure!(
        config.distributes() && input.origin == origin(&config),
        "not_found"
    );
    let access = Access(store);
    let _lock = access.lock()?;
    let mut data = access.read()?.context("not_found")?;
    let client = data
        .clients
        .iter()
        .find_map(|(&id, definition)| {
            definition
                .claim_key
                .filter(|saved| bool::from(saved.as_bytes().ct_eq(input.key.as_bytes())))
                .map(|_| id)
        })
        .context("not_found")?;
    let id = data.claim_installation(client, input.request, admin_auth::now())?;
    let token = subscription_token(&crate::share::device_key(store)?, id, &data.devices[&id]);
    access.write(&data)?;
    Ok(json!({
        "browser_login":runtime::portal(&config),
        "mihomo":format!("/nodes/sub/mihomo-weighted?token={token}"),
        "xray":format!("/nodes/sub/xray-config?token={token}"),
    }))
}

fn socket(store: &Store) -> PathBuf {
    Access(store).dir().join("claim.sock")
}

pub(super) fn start(store: &Store) -> Result<()> {
    let path = socket(store);
    crate::store::check_private(&Access(store).dir(), true)?;
    match fs::symlink_metadata(&path) {
        Ok(old) => {
            ensure!(old.file_type().is_socket(), "Invalid enrollment socket");
            fs::remove_file(&path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&path)?;
    let store = Arc::new(Store::new(
        store.config_dir.clone(),
        store.state_dir.clone(),
    )?);
    let workers = Arc::new(Semaphore::new(8));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(permit) = workers.clone().try_acquire_owned() else {
                continue;
            };
            let store = store.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = handle_claim(stream, store).await;
            });
        }
    });
    Ok(())
}

async fn handle_claim(mut stream: tokio::net::UnixStream, store: Arc<Store>) -> Result<()> {
    let mut bytes = Vec::new();
    timeout(
        Duration::from_secs(2),
        (&mut stream)
            .take(REQUEST_LIMIT + 1)
            .read_to_end(&mut bytes),
    )
    .await??;
    ensure!(
        bytes.len() as u64 <= REQUEST_LIMIT,
        "Invalid enrollment request"
    );
    let input = serde_json::from_slice::<ClaimRequest>(&bytes)?;
    let (status, payload) = match tokio::task::spawn_blocking(move || claim(&store, input)).await? {
        Ok(value) => (200, value),
        Err(error) => match error.to_string().as_str() {
            "not_found" => (404, json!({"error":"not_found"})),
            "enrollment_exhausted" => (409, json!({"error":"enrollment_exhausted"})),
            _ => (503, json!({"error":"unavailable"})),
        },
    };
    let reply = serde_json::to_vec(&ClaimReply { status, payload })?;
    timeout(Duration::from_secs(2), stream.write_all(&reply)).await??;
    Ok(())
}

pub(crate) fn request_claim(
    store: &Store,
    key: Uuid,
    request: Uuid,
    origin: &str,
) -> Result<(u16, Value)> {
    let mut stream = UnixStream::connect(socket(store))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let bytes = serde_json::to_vec(&ClaimRequest {
        key,
        request,
        origin: origin.into(),
    })?;
    ensure!(
        bytes.len() as u64 <= REQUEST_LIMIT,
        "Invalid enrollment request"
    );
    stream.write_all(&bytes)?;
    stream.shutdown(Shutdown::Write)?;
    let mut reply = Vec::new();
    stream.take(REPLY_LIMIT + 1).read_to_end(&mut reply)?;
    ensure!(
        reply.len() as u64 <= REPLY_LIMIT,
        "Invalid enrollment response"
    );
    let reply: ClaimReply = serde_json::from_slice(&reply)?;
    Ok((reply.status, reply.payload))
}
