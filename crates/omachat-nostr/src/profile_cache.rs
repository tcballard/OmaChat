use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::event::{EventLimits, SignedEvent};
use crate::profile_verification::{VerifiedNostrProfile, verify_profile_metadata};

pub const MAX_CACHED_PROFILES: usize = 4_096;
pub const DEFAULT_PROFILE_FRESHNESS_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_SERIALIZED_PROFILE_CACHE_BYTES: usize = 1_048_576;
const PROFILE_CACHE_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProfileCacheRecord {
    profile: VerifiedNostrProfile,
    verified_at: u64,
}

impl VerifiedProfileCacheRecord {
    pub fn profile(&self) -> &VerifiedNostrProfile {
        &self.profile
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedProfileCache {
    records: BTreeMap<String, VerifiedProfileCacheRecord>,
}

impl VerifiedProfileCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn insert(
        &mut self,
        profile: VerifiedNostrProfile,
        verified_at: u64,
    ) -> Result<ProfileCacheMutation, ProfileCacheError> {
        if verified_at < profile.source_created_at() {
            return Err(ProfileCacheError::InvalidVerificationTime);
        }
        let key = hex::encode(profile.public_key());
        if let Some(current) = self.records.get(&key) {
            if profile.source_created_at() < current.profile.source_created_at() {
                return Err(ProfileCacheError::Rollback);
            }
            if profile.source_created_at() == current.profile.source_created_at() {
                if profile.source_event_id() != current.profile.source_event_id() {
                    return Err(ProfileCacheError::Equivocation);
                }
                return Ok(ProfileCacheMutation::Unchanged);
            }
        } else if self.records.len() >= MAX_CACHED_PROFILES {
            return Err(ProfileCacheError::CacheFull);
        }

        let previous = self.records.insert(
            key.clone(),
            VerifiedProfileCacheRecord {
                profile,
                verified_at,
            },
        );
        if let Err(error) = self.to_json() {
            if let Some(previous) = previous {
                self.records.insert(key, previous);
            } else {
                self.records.remove(&key);
            }
            return Err(error);
        }
        Ok(ProfileCacheMutation::Stored)
    }

    pub fn lookup(
        &self,
        public_key: &[u8; 32],
        now: u64,
        freshness_window_seconds: u64,
    ) -> ProfileCacheLookup<'_> {
        let key = hex::encode(public_key);
        let Some(record) = self.records.get(&key) else {
            return ProfileCacheLookup::Missing;
        };
        let Some(age) = now.checked_sub(record.profile.source_created_at()) else {
            return ProfileCacheLookup::UnusableClockRollback(record);
        };
        if age <= freshness_window_seconds {
            ProfileCacheLookup::Fresh(record)
        } else {
            ProfileCacheLookup::OfflineStale(record)
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ProfileCacheError> {
        let persisted = PersistedProfileCache {
            version: PROFILE_CACHE_VERSION,
            records: self
                .records
                .values()
                .map(|record| PersistedProfileCacheRecord {
                    verified_at: record.verified_at,
                    source_event: record.profile.source_event().clone(),
                })
                .collect(),
        };
        let encoded =
            serde_json::to_vec(&persisted).map_err(|_| ProfileCacheError::InvalidEncoding)?;
        if encoded.len() > MAX_SERIALIZED_PROFILE_CACHE_BYTES {
            return Err(ProfileCacheError::CacheTooLarge);
        }
        Ok(encoded)
    }

    pub fn from_json(
        encoded: &[u8],
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<Self, ProfileCacheError> {
        if encoded.len() > MAX_SERIALIZED_PROFILE_CACHE_BYTES {
            return Err(ProfileCacheError::CacheTooLarge);
        }
        let persisted: PersistedProfileCache =
            serde_json::from_slice(encoded).map_err(|_| ProfileCacheError::InvalidEncoding)?;
        if persisted.version != PROFILE_CACHE_VERSION {
            return Err(ProfileCacheError::UnsupportedVersion(persisted.version));
        }
        if persisted.records.len() > MAX_CACHED_PROFILES {
            return Err(ProfileCacheError::CacheFull);
        }

        let mut seen = BTreeSet::new();
        let mut cache = Self::new();
        for record in persisted.records {
            if record.verified_at > now {
                return Err(ProfileCacheError::InvalidVerificationTime);
            }
            let mut public_key = [0; 32];
            hex::decode_to_slice(&record.source_event.pubkey, &mut public_key)
                .map_err(|_| ProfileCacheError::InvalidSourceEvent)?;
            if !seen.insert(public_key) {
                return Err(ProfileCacheError::InvalidEncoding);
            }
            let profile =
                verify_profile_metadata(&record.source_event, &public_key, now, event_limits)
                    .map_err(|_| ProfileCacheError::InvalidSourceEvent)?;
            cache.insert(profile, record.verified_at)?;
        }
        Ok(cache)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedProfileCache {
    version: u16,
    records: Vec<PersistedProfileCacheRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedProfileCacheRecord {
    verified_at: u64,
    source_event: SignedEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileCacheMutation {
    Stored,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileCacheLookup<'a> {
    Missing,
    Fresh(&'a VerifiedProfileCacheRecord),
    OfflineStale(&'a VerifiedProfileCacheRecord),
    UnusableClockRollback(&'a VerifiedProfileCacheRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileCacheError {
    InvalidVerificationTime,
    InvalidSourceEvent,
    InvalidEncoding,
    UnsupportedVersion(u16),
    Rollback,
    Equivocation,
    CacheFull,
    CacheTooLarge,
}

impl fmt::Display for ProfileCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVerificationTime => {
                formatter.write_str("invalid profile verification time")
            }
            Self::InvalidSourceEvent => formatter.write_str("invalid signed profile source event"),
            Self::InvalidEncoding => formatter.write_str("invalid profile cache encoding"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported profile cache version {version}")
            }
            Self::Rollback => {
                formatter.write_str("older profile metadata cannot replace newer state")
            }
            Self::Equivocation => {
                formatter.write_str("conflicting profile events share a timestamp")
            }
            Self::CacheFull => formatter.write_str("profile cache is full"),
            Self::CacheTooLarge => {
                formatter.write_str("serialized profile cache exceeds its bound")
            }
        }
    }
}

impl Error for ProfileCacheError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{UnsignedEvent, xonly_public_key};
    use crate::profile_metadata::PROFILE_METADATA_KIND;

    const NOW: u64 = 1_800_000_000;

    fn profile(secret_byte: u8, created_at: u64, name: &str) -> ([u8; 32], VerifiedNostrProfile) {
        let secret = [secret_byte; 32];
        let public_key = xonly_public_key(&secret).expect("public key");
        let event = UnsignedEvent::new(
            hex::encode(public_key),
            created_at,
            PROFILE_METADATA_KIND,
            Vec::new(),
            format!(r#"{{"name":"{name}"}}"#),
            &EventLimits::default(),
        )
        .expect("profile event")
        .sign_with_aux(&secret, &[17; 32], &EventLimits::default())
        .expect("signed profile");
        let profile = verify_profile_metadata(&event, &public_key, NOW, &EventLimits::default())
            .expect("verified profile");
        (public_key, profile)
    }

    #[test]
    fn freshness_and_offline_use_are_explicit() {
        let (public_key, profile) = profile(81, NOW - 10, "tom");
        let mut cache = VerifiedProfileCache::new();
        cache.insert(profile, NOW).expect("insert profile");
        assert!(matches!(
            cache.lookup(&public_key, NOW, 10),
            ProfileCacheLookup::Fresh(_)
        ));
        assert!(matches!(
            cache.lookup(&public_key, NOW + 1, 10),
            ProfileCacheLookup::OfflineStale(_)
        ));
        assert!(matches!(
            cache.lookup(&public_key, NOW - 11, 10),
            ProfileCacheLookup::UnusableClockRollback(_)
        ));
    }

    #[test]
    fn rollback_and_same_timestamp_equivocation_fail_closed() {
        let (_, current) = profile(82, NOW - 10, "current");
        let mut cache = VerifiedProfileCache::new();
        assert_eq!(
            cache.insert(current.clone(), NOW),
            Ok(ProfileCacheMutation::Stored)
        );
        assert_eq!(
            cache.insert(current, NOW),
            Ok(ProfileCacheMutation::Unchanged)
        );
        assert_eq!(
            cache.insert(profile(82, NOW - 11, "older").1, NOW),
            Err(ProfileCacheError::Rollback)
        );
        assert_eq!(
            cache.insert(profile(82, NOW - 10, "conflict").1, NOW),
            Err(ProfileCacheError::Equivocation)
        );
    }

    #[test]
    fn persisted_source_is_reverified_and_subject_bound() {
        let (_, profile) = profile(83, NOW - 10, "external");
        let mut cache = VerifiedProfileCache::new();
        cache.insert(profile, NOW).expect("insert profile");
        let encoded = cache.to_json().expect("cache JSON");
        assert_eq!(
            VerifiedProfileCache::from_json(&encoded, NOW, &EventLimits::default())
                .expect("validated restart"),
            cache
        );

        let tampered = String::from_utf8(encoded)
            .expect("UTF-8 JSON")
            .replace("external", "attacker");
        assert_eq!(
            VerifiedProfileCache::from_json(tampered.as_bytes(), NOW, &EventLimits::default()),
            Err(ProfileCacheError::InvalidSourceEvent)
        );
    }
}
