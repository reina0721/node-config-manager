//! Durable per-account accounting for the authenticated VLESS relay.
use crate::store::{self, Store};
use anyhow::Result;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap, fs, io::ErrorKind, os::unix::fs::OpenOptionsExt, path::PathBuf,
    sync::Mutex,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Usage {
    pub upload: u64,
    pub download: u64,
}

impl Usage {
    pub fn total(self) -> u64 {
        self.upload.saturating_add(self.download)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Budget {
    pub ledger: Uuid,
    pub quota: Option<u64>,
}

fn directory(store: &Store) -> PathBuf {
    super::Access(store).dir().join("traffic")
}

#[derive(Default)]
pub(super) struct Online(Mutex<BTreeMap<Uuid, usize>>);

pub(super) struct Active<'a> {
    state: &'a Online,
    id: Uuid,
}

#[derive(Deserialize, Serialize)]
struct Activity {
    observed: u64,
    devices: BTreeMap<Uuid, usize>,
}

impl Online {
    pub fn enter(&self, id: Uuid) -> Active<'_> {
        *self.0.lock().unwrap().entry(id).or_default() += 1;
        Active { state: self, id }
    }

    pub fn publish(&self, store: &Store, observed: u64) -> Result<()> {
        let devices = self.0.lock().unwrap().clone();
        store::atomic_write(
            &super::Access(store).dir().join("online.json"),
            &serde_json::to_vec(&Activity { observed, devices })?,
        )
    }

    pub fn read(store: &Store, now: u64) -> BTreeMap<Uuid, usize> {
        let path = super::Access(store).dir().join("online.json");
        if store::check_private(&path, false).is_err() {
            return BTreeMap::new();
        }
        fs::read(path)
            .ok()
            .and_then(|data| serde_json::from_slice::<Activity>(&data).ok())
            .filter(|snapshot| snapshot.observed <= now && now - snapshot.observed <= 5)
            .map_or_else(BTreeMap::new, |snapshot| snapshot.devices)
    }
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        let mut devices = self.state.0.lock().unwrap();
        if let Some(count) = devices.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                devices.remove(&self.id);
            }
        }
    }
}

pub(super) fn read(store: &Store, id: Uuid) -> Result<Usage> {
    let path = directory(store).join(id.to_string());
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Usage::default()),
        metadata => {
            metadata?;
        }
    }
    store::check_private(path.parent().unwrap(), true)?;
    store::check_private(&path, false)?;
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

impl Budget {
    pub fn can_send(self, store: &Store) -> Result<bool> {
        self.quota.map_or(Ok(true), |limit| {
            Ok(read(store, self.ledger)?.total() < limit)
        })
    }

    pub fn reserve(self, store: &Store, length: usize, upload: bool) -> Result<usize> {
        let directory = directory(store);
        store::private_dir(&directory)?;
        let lock = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join(format!("{}.lock", self.ledger)))?;
        lock.lock_exclusive()?;
        let mut usage = read(store, self.ledger)?;
        let remaining = self
            .quota
            .map_or(u64::MAX, |limit| limit.saturating_sub(usage.total()));
        let allowed = remaining.min(length as u64);
        if allowed > 0 {
            let counter = if upload {
                &mut usage.upload
            } else {
                &mut usage.download
            };
            *counter = counter.saturating_add(allowed);
            store::atomic_write(
                &directory.join(self.ledger.to_string()),
                &serde_json::to_vec(&usage)?,
            )?;
        }
        Ok(allowed as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_directions_share_durable_quota_and_reset_has_a_new_ledger() -> Result<()> {
        let (_dir, store) = crate::tests::sandbox();
        super::super::Access(&store).lock()?;
        let limit = 31_991;
        let budget = Budget {
            ledger: Uuid::new_v4(),
            quota: Some(limit),
        };
        let reserved: usize = std::thread::scope(|scope| {
            let writers: Vec<_> = (0..16)
                .map(|i| {
                    let store = &store;
                    scope.spawn(move || budget.reserve(store, 4096, i % 2 == 0).unwrap())
                })
                .collect();
            writers
                .into_iter()
                .map(|writer| writer.join().unwrap())
                .sum()
        });
        assert_eq!(reserved as u64, limit);
        let reopened = Store::new(store.config_dir.clone(), store.state_dir.clone())?;
        assert_eq!(read(&reopened, budget.ledger)?.total(), limit);
        assert!(!budget.can_send(&reopened)?);
        assert_eq!(budget.reserve(&reopened, 1, true)?, 0);
        let reset = Budget {
            ledger: Uuid::new_v4(),
            ..budget
        };
        assert!(reset.can_send(&reopened)?);
        assert_eq!(read(&reopened, reset.ledger)?.total(), 0);
        Ok(())
    }
}
