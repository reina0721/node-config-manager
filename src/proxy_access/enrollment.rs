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

#[derive(Serialize, Deserialize)]
struct ClientReport {
    token: String,
    agent: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SocketRequest {
    Claim(ClaimRequest),
    Client(ClientReport),
}

fn record_client(store: &Store, report: ClientReport) -> Result<()> {
    let Some(client) = super::metadata::client_report(&report.agent) else {
        return Ok(());
    };
    let access = Access(store);
    let _guard = access.lock()?;
    if let Some(id) = super::subscription_device(store, &report.token)?
        && let Some(mut data) = access.read()?
        && let Some(device) = data.devices.get_mut(&id)
        && device.info.client.as_ref() != Some(&client)
    {
        device.info.client = Some(client);
        access.write(&data)?;
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Enrollment {
    Ready,
    Claimed {
        request: Uuid,
        expires: u64,
        #[serde(default = "legacy_provisioned")]
        provisioned: bool,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        live: bool,
    },
}

pub(super) enum ProfileAccess<'a> {
    Bootstrap,
    Account(&'a Account),
}

fn legacy_provisioned() -> bool {
    true
}

impl Device {
    pub(super) fn unclaimed_pool_entry(&self) -> bool {
        self.username.is_empty() && matches!(self.enrollment, Some(Enrollment::Ready))
    }

    pub(super) fn pending_expired(&self, now: u64) -> bool {
        self.username.is_empty()
            && matches!(self.enrollment, Some(Enrollment::Claimed { expires, .. }) if expires <= now)
    }

    pub(super) fn live_enrollment(&self) -> bool {
        matches!(
            self.enrollment,
            Some(Enrollment::Claimed { live: true, .. })
        )
    }

    pub(super) fn awaiting_login(&self, now: u64) -> bool {
        self.username.is_empty()
            && matches!(self.enrollment, Some(Enrollment::Claimed { expires, provisioned: true, .. }) if expires > now)
    }
}

impl Database {
    pub(super) fn claim_installation(
        &mut self,
        client: Uuid,
        request: Uuid,
        now: u64,
    ) -> Result<(Uuid, bool)> {
        ensure!(self.enabled && !request.is_nil(), "not_found");
        ensure!(
            self.clients
                .get(&client)
                .is_some_and(|definition| !definition.usernames.is_empty()),
            "not_found"
        );
        if let Some((&id, device)) = self.devices.iter().find(|(_, device)| {
            device.client == Some(client)
                && matches!(device.enrollment, Some(Enrollment::Claimed { request: previous, .. }) if previous == request)
        }) {
            let provisioned = matches!(device.enrollment, Some(Enrollment::Claimed { provisioned: true, .. }));
            ensure!(
                !device.pending_expired(now)
                    && (!provisioned || self.profile_access(device, now).is_some()),
                "not_found"
            );
            return Ok((id, provisioned));
        }
        ensure!(self.devices.len() < MAX_DEVICES, "enrollment_busy");
        let id = Uuid::new_v4();
        self.devices.insert(
            id,
            Device {
                username: String::new(),
                client: Some(client),
                label: format!("Subscription {}", &id.simple().to_string()[..8]),
                transit: Uuid::new_v4(),
                portal: Uuid::new_v4(),
                authenticated: None,
                attempts: Vec::new(),
                enrollment: Some(Enrollment::Claimed {
                    request,
                    expires: now + CLAIM_TTL,
                    provisioned: false,
                    live: true,
                }),
                info: Default::default(),
            },
        );
        Ok((id, false))
    }

    pub(super) fn profile_access(&self, device: &Device, now: u64) -> Option<ProfileAccess<'_>> {
        if device.awaiting_login(now) {
            let client = self.clients.get(&device.client?)?;
            return (self.enabled && !client.usernames.is_empty())
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

pub(super) fn issue(
    store: &Store,
    access: &Access,
    data: &mut Database,
    client: Uuid,
    request: Uuid,
) -> Result<Uuid> {
    crate::share::device_key(store).context("enrollment_requires_distribution")?;
    let now = admin_auth::now();
    let (id, provisioned) = data.claim_installation(client, request, now)?;
    if !provisioned {
        // Journal the UUID before touching runtime state. A lost response or
        // partial API failure can resume with exactly the same credentials.
        access.write(data)?;
        runtime::live::install(store, data, id, true)?;
        if let Some(Enrollment::Claimed { provisioned, .. }) =
            &mut data.devices.get_mut(&id).context("not_found")?.enrollment
        {
            *provisioned = true;
        }
        access.write(data)?;
    }
    Ok(id)
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
    let mut client = None;
    for (&id, definition) in &data.clients {
        if let Some(key) = definition.share_key(store, id)?
            && bool::from(key.as_bytes().ct_eq(input.key.as_bytes()))
        {
            client = Some(id);
        }
    }
    let id = issue(
        store,
        &access,
        &mut data,
        client.context("not_found")?,
        input.request,
    )?;
    let token = subscription_token(&crate::share::device_key(store)?, id, &data.devices[&id]);
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
    let maintenance = store.clone();
    let geodata = store.clone();
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(Duration::from_secs(3600));
        loop {
            ticks.tick().await;
            let store = geodata.clone();
            if let Ok(Ok(())) =
                tokio::task::spawn_blocking(move || super::metadata::prepare_location_db(&store))
                    .await
            {
                return;
            }
        }
    });
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticks.tick().await;
            let store = maintenance.clone();
            let _ = tokio::task::spawn_blocking(move || reap(&store)).await;
        }
    });
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

fn reap(store: &Store) -> Result<()> {
    let now = admin_auth::now();
    let access = Access(store);
    if access.read_state()?.is_none_or(|data| {
        data.retired.is_empty()
            && !data
                .devices
                .values()
                .any(|device| device.unclaimed_pool_entry() || device.pending_expired(now))
    }) {
        return Ok(());
    }
    let _host = store.lock()?;
    ensure!(!crate::upgrade::pending(store)?, "operation_busy");
    let _guard = access.lock()?;
    let mut data = access.read()?.context("not_found")?;
    data.devices.retain(|id, device| {
        if !device.pending_expired(now) {
            return true;
        }
        if device.live_enrollment() {
            data.retired.insert(*id);
        }
        false
    });
    access.write(&data)?;
    if !data.retired.is_empty() {
        runtime::live::prune(store, &data)?;
        data.retired.clear();
        access.write(&data)?;
    }
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
    let input = match serde_json::from_slice::<SocketRequest>(&bytes)? {
        SocketRequest::Claim(input) => input,
        SocketRequest::Client(report) => {
            tokio::task::spawn_blocking(move || record_client(&store, report)).await??;
            return Ok(());
        }
    };
    let (status, payload) = match tokio::task::spawn_blocking(move || claim(&store, input)).await? {
        Ok(value) => (200, value),
        Err(error) => match error.to_string().as_str() {
            "not_found" => (404, json!({"error":"not_found"})),
            "enrollment_busy" => (429, json!({"error":"enrollment_busy"})),
            _ => (503, json!({"error":"unavailable"})),
        },
    };
    let reply = serde_json::to_vec(&ClaimReply { status, payload })?;
    timeout(Duration::from_secs(2), stream.write_all(&reply)).await??;
    Ok(())
}

pub(crate) fn report_subscription_client(store: &Store, token: &str, agent: &str) {
    if agent.len() > 256 || super::metadata::client_report(agent).is_none() {
        return;
    }
    let _ = (|| -> Result<()> {
        let mut socket = UnixStream::connect(socket(store))?;
        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        serde_json::to_writer(
            &mut socket,
            &ClientReport {
                token: token.into(),
                agent: agent.into(),
            },
        )?;
        socket.shutdown(Shutdown::Write)?;
        Ok(())
    })();
}

pub(crate) fn request_claim(
    store: &Store,
    key: Uuid,
    request: Uuid,
    origin: &str,
) -> Result<(u16, Value)> {
    let mut stream = UnixStream::connect(socket(store))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_removes_unused_pool_entries_without_retiring_issued_devices() -> Result<()> {
        let (_folder, store) = crate::tests::sandbox();
        let access = Access(&store);
        let ready_id = Uuid::new_v4();
        let existing_id = Uuid::new_v4();
        let mut state = Database::default();
        let ready = Device {
            username: String::new(),
            client: Some(Uuid::new_v4()),
            label: String::new(),
            transit: Uuid::new_v4(),
            portal: Uuid::new_v4(),
            authenticated: None,
            attempts: vec![],
            enrollment: Some(Enrollment::Ready),
            info: Default::default(),
        };
        let mut existing = ready.clone();
        existing.username = "existing-user".into();
        existing.enrollment = Some(Enrollment::Claimed {
            request: Uuid::new_v4(),
            expires: admin_auth::now(),
            provisioned: true,
            live: false,
        });
        state.devices.insert(ready_id, ready);
        state.devices.insert(existing_id, existing);
        let guard = access.lock()?;
        access.write(&state)?;
        drop(guard);

        assert!(
            access
                .read_state()?
                .unwrap()
                .devices
                .contains_key(&ready_id)
        );
        reap(&store)?;
        let after = access.read_state()?.unwrap();
        assert!(!after.devices.contains_key(&ready_id));
        assert!(after.devices.contains_key(&existing_id));
        assert!(after.retired.is_empty());
        Ok(())
    }
}
