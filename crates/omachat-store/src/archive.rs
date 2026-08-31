use crate::sealed::{MAX_RECORD_BYTES, SealedStore, StoreError};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
};

const PUBLIC_ARCHIVE_RECORD: &str = "public-archive-v1";
const PUBLIC_ARCHIVE_CAPACITY: usize = 1_000;
const PUBLIC_ARCHIVE_AGE_SECONDS: u64 = 6 * 60 * 60;
const PUBLIC_EVENT_MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicArchiveEntry {
    pub event_id: String,
    pub created_at: u64,
    pub payload: Vec<u8>,
}

#[derive(Default, Deserialize, Serialize)]
struct PersistedPublicArchive {
    entries: Vec<PublicArchiveEntry>,
}

/// Six-hour sealed public-only backfill archive. Private message APIs never
/// write this record; short-lived live/dedup caches remain separate in memory.
pub struct PublicArchive<'store> {
    store: &'store SealedStore,
    state: PersistedPublicArchive,
}

impl<'store> PublicArchive<'store> {
    pub fn load(store: &'store SealedStore, now: u64) -> Result<Self, ArchiveError> {
        let state = match store.read(PUBLIC_ARCHIVE_RECORD) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| ArchiveError::Encoding)?,
            Err(StoreError::RecordNotFound) => PersistedPublicArchive::default(),
            Err(error) => return Err(ArchiveError::Store(error)),
        };
        let mut archive = Self { store, state };
        if archive.expire(now) {
            archive.persist()?;
        }
        Ok(archive)
    }

    pub fn insert(&mut self, entry: PublicArchiveEntry, now: u64) -> Result<bool, ArchiveError> {
        self.expire(now);
        if entry.event_id.is_empty()
            || entry.event_id.len() > 128
            || entry.payload.is_empty()
            || entry.payload.len() > PUBLIC_EVENT_MAX_BYTES
        {
            return Err(ArchiveError::Invalid);
        }
        if self
            .state
            .entries
            .iter()
            .any(|item| item.event_id == entry.event_id)
        {
            return Ok(false);
        }
        self.state.entries.push(entry);
        self.state.entries.sort_by_key(|item| item.created_at);
        if self.state.entries.len() > PUBLIC_ARCHIVE_CAPACITY {
            let remove = self.state.entries.len() - PUBLIC_ARCHIVE_CAPACITY;
            self.state.entries.drain(..remove);
        }
        while serde_json::to_vec(&self.state)
            .map_err(|_| ArchiveError::Encoding)?
            .len()
            > MAX_RECORD_BYTES
        {
            if self.state.entries.is_empty() {
                return Err(ArchiveError::Invalid);
            }
            self.state.entries.remove(0);
        }
        self.persist()?;
        Ok(true)
    }

    #[must_use]
    pub fn since(&self, since: u64, limit: usize) -> Vec<&PublicArchiveEntry> {
        self.state
            .entries
            .iter()
            .filter(|item| item.created_at >= since)
            .take(limit.min(PUBLIC_ARCHIVE_CAPACITY))
            .collect()
    }

    #[must_use]
    pub fn entries(&self) -> &[PublicArchiveEntry] {
        &self.state.entries
    }

    fn expire(&mut self, now: u64) -> bool {
        let before = self.state.entries.len();
        self.state
            .entries
            .retain(|item| now.saturating_sub(item.created_at) < PUBLIC_ARCHIVE_AGE_SECONDS);
        before != self.state.entries.len()
    }

    fn persist(&self) -> Result<(), ArchiveError> {
        self.store
            .write(
                PUBLIC_ARCHIVE_RECORD,
                &serde_json::to_vec(&self.state).map_err(|_| ArchiveError::Encoding)?,
            )
            .map_err(ArchiveError::Store)
    }
}

#[derive(Default)]
pub struct TransientPublicCaches {
    live: VecDeque<PublicArchiveEntry>,
    dedup: HashMap<String, u64>,
}

impl TransientPublicCaches {
    pub fn accept(&mut self, entry: PublicArchiveEntry, now: u64) -> bool {
        self.expire(now);
        if self.dedup.contains_key(&entry.event_id) {
            return false;
        }
        self.dedup.insert(entry.event_id.clone(), now);
        self.live.push_back(entry);
        while self.live.len() > PUBLIC_ARCHIVE_CAPACITY {
            self.live.pop_front();
        }
        true
    }

    pub fn expire(&mut self, now: u64) {
        const LIVE: u64 = 15 * 60;
        self.live
            .retain(|item| now.saturating_sub(item.created_at) < LIVE);
        self.dedup.retain(|_, at| now.saturating_sub(*at) < LIVE);
    }
}

#[derive(Debug)]
pub enum ArchiveError {
    Store(StoreError),
    Encoding,
    Invalid,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "public archive error: {self:?}")
    }
}

impl Error for ArchiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}
