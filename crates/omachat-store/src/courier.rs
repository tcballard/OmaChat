use crate::sealed::{SealedStore, StoreError};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

const COURIER_RECORD: &str = "courier-pool-v1";
const COURIER_POOL_CAPACITY: usize = 40;
const COURIER_VERIFIED_CAPACITY: usize = 20;
const COURIER_FAVORITE_QUOTA: usize = 5;
const COURIER_VERIFIED_QUOTA: usize = 2;
const COURIER_DAILY_BYTES: usize = 16 * 1024;
const COURIER_REMOTE_COOLDOWN_SECONDS: u64 = 10 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CourierTier {
    Favorite,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredCourier {
    pub id: String,
    pub depositor: String,
    pub recipient_tag: String,
    pub envelope: Vec<u8>,
    pub tier: CourierTier,
    pub deposited_at: u64,
    pub expires_at: u64,
    pub copies: u8,
    pub carriers: Vec<String>,
    pub spray_history: Vec<String>,
    pub last_remote_spray_at: Option<u64>,
}

#[derive(Default, Deserialize, Serialize)]
struct PersistedCourierPool {
    entries: Vec<StoredCourier>,
}

pub struct CourierPool<'store> {
    store: &'store SealedStore,
    state: PersistedCourierPool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Handover {
    DirectDelivery {
        envelope: Vec<u8>,
    },
    DirectedCopy {
        envelope: Vec<u8>,
    },
    Spray {
        envelope: Vec<u8>,
        transferred_copies: u8,
        retained_copies: u8,
    },
    Wait,
}

impl<'store> CourierPool<'store> {
    pub fn load(store: &'store SealedStore, now: u64) -> Result<Self, CourierPoolError> {
        let state = match store.read(COURIER_RECORD) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| CourierPoolError::Encoding)?,
            Err(StoreError::RecordNotFound) => PersistedCourierPool::default(),
            Err(error) => return Err(CourierPoolError::Store(error)),
        };
        let mut pool = Self { store, state };
        if pool.expire(now) {
            pool.persist()?;
        }
        Ok(pool)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn deposit(
        &mut self,
        id: String,
        depositor: String,
        recipient_tag: String,
        envelope: Vec<u8>,
        tier: CourierTier,
        authorized_favorite: bool,
        authorized_verified: bool,
        now: u64,
        expires_at: u64,
        copies: u8,
    ) -> Result<(), CourierPoolError> {
        self.expire(now);
        if id.is_empty()
            || depositor.is_empty()
            || recipient_tag.len() != 32
            || envelope.is_empty()
            || envelope.len() > COURIER_DAILY_BYTES
            || expires_at <= now
            || copies == 0
            || copies > 8
        {
            return Err(CourierPoolError::Invalid);
        }
        if self.state.entries.iter().any(|entry| entry.id == id) {
            return Err(CourierPoolError::Duplicate);
        }
        match tier {
            CourierTier::Favorite if !authorized_favorite => {
                return Err(CourierPoolError::Unauthorized);
            }
            CourierTier::Verified if !authorized_verified => {
                return Err(CourierPoolError::Unauthorized);
            }
            _ => {}
        }
        let same_tier = self
            .state
            .entries
            .iter()
            .filter(|entry| entry.depositor == depositor && entry.tier == tier)
            .count();
        let quota = if tier == CourierTier::Favorite {
            COURIER_FAVORITE_QUOTA
        } else {
            COURIER_VERIFIED_QUOTA
        };
        if same_tier >= quota {
            return Err(CourierPoolError::Quota);
        }
        let daily = self
            .state
            .entries
            .iter()
            .filter(|entry| {
                entry.depositor == depositor
                    && now.saturating_sub(entry.deposited_at) < 24 * 60 * 60
            })
            .map(|entry| entry.envelope.len())
            .sum::<usize>();
        if daily.saturating_add(envelope.len()) > COURIER_DAILY_BYTES {
            return Err(CourierPoolError::DailyBytes);
        }
        if tier == CourierTier::Verified
            && self
                .state
                .entries
                .iter()
                .filter(|entry| entry.tier == CourierTier::Verified)
                .count()
                >= COURIER_VERIFIED_CAPACITY
        {
            return Err(CourierPoolError::Quota);
        }
        if self.state.entries.len() >= COURIER_POOL_CAPACITY {
            let Some(index) = self
                .state
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.tier == CourierTier::Verified)
                .min_by_key(|(_, entry)| entry.deposited_at)
                .map(|(index, _)| index)
            else {
                return Err(CourierPoolError::PoolFull);
            };
            self.state.entries.remove(index);
        }
        self.state.entries.push(StoredCourier {
            id,
            depositor,
            recipient_tag,
            envelope,
            tier,
            deposited_at: now,
            expires_at,
            copies,
            carriers: Vec::new(),
            spray_history: Vec::new(),
            last_remote_spray_at: None,
        });
        self.persist()
    }

    pub fn handover(
        &mut self,
        id: &str,
        encounter: &str,
        direct_recipient: bool,
        relayed_recipient: bool,
        now: u64,
    ) -> Result<Handover, CourierPoolError> {
        let index = self
            .state
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(CourierPoolError::NotFound)?;
        if direct_recipient {
            let entry = self.state.entries.remove(index);
            self.persist()?;
            return Ok(Handover::DirectDelivery {
                envelope: entry.envelope,
            });
        }
        let entry = &mut self.state.entries[index];
        if relayed_recipient {
            if !entry.carriers.iter().any(|carrier| carrier == encounter)
                && entry.carriers.len() < 3
            {
                entry.carriers.push(encounter.to_owned());
            }
            let envelope = entry.envelope.clone();
            self.persist()?;
            return Ok(Handover::DirectedCopy { envelope });
        }
        if entry.copies < 2
            || entry.spray_history.iter().any(|peer| peer == encounter)
            || entry
                .last_remote_spray_at
                .is_some_and(|last| now.saturating_sub(last) < COURIER_REMOTE_COOLDOWN_SECONDS)
        {
            return Ok(Handover::Wait);
        }
        let transferred = entry.copies / 2;
        entry.copies -= transferred;
        entry.spray_history.push(encounter.to_owned());
        entry.last_remote_spray_at = Some(now);
        if !entry.carriers.iter().any(|carrier| carrier == encounter) && entry.carriers.len() < 3 {
            entry.carriers.push(encounter.to_owned());
        }
        let result = Handover::Spray {
            envelope: entry.envelope.clone(),
            transferred_copies: transferred,
            retained_copies: entry.copies,
        };
        self.persist()?;
        Ok(result)
    }

    #[must_use]
    pub fn entries(&self) -> &[StoredCourier] {
        &self.state.entries
    }

    fn expire(&mut self, now: u64) -> bool {
        let before = self.state.entries.len();
        self.state.entries.retain(|entry| entry.expires_at > now);
        before != self.state.entries.len()
    }

    fn persist(&self) -> Result<(), CourierPoolError> {
        let bytes = serde_json::to_vec(&self.state).map_err(|_| CourierPoolError::Encoding)?;
        self.store
            .write(COURIER_RECORD, &bytes)
            .map_err(CourierPoolError::Store)
    }
}

#[derive(Debug)]
pub enum CourierPoolError {
    Store(StoreError),
    Encoding,
    Invalid,
    Duplicate,
    Unauthorized,
    Quota,
    DailyBytes,
    PoolFull,
    NotFound,
}

impl fmt::Display for CourierPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "courier pool error: {self:?}")
    }
}

impl Error for CourierPoolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}
