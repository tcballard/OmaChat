use std::{
    collections::{BTreeSet, HashSet},
    error::Error,
    fmt,
};

use omachat_nostr::{
    event::{EventLimits, SignedEvent},
    profile_verification::{ProfileVerificationError, verify_profile_metadata},
};
use omachat_store::{SealedStore, StoreError};
use serde::{Deserialize, Serialize};
use url::Url;

pub const PROFILE_PUBLICATION_INTENT_RECORD_NAME: &str = "profile-publication-intent-v1";
pub const MAX_PROFILE_PUBLICATION_RELAYS: usize = 16;
const PROFILE_PUBLICATION_INTENT_VERSION: u16 = 1;
const MAX_PROFILE_PUBLICATION_INTENT_BYTES: usize = 96 * 1024;

/// One exact signed replaceable profile event and its durable relay progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingProfilePublication {
    event: SignedEvent,
    relay_urls: Vec<String>,
    required_acknowledgements: usize,
    acknowledged_relay_indices: BTreeSet<usize>,
}

impl PendingProfilePublication {
    #[must_use]
    pub const fn event(&self) -> &SignedEvent {
        &self.event
    }

    #[must_use]
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    #[must_use]
    pub const fn required_acknowledgements(&self) -> usize {
        self.required_acknowledgements
    }

    #[must_use]
    pub const fn acknowledged_relay_indices(&self) -> &BTreeSet<usize> {
        &self.acknowledged_relay_indices
    }

    #[must_use]
    pub fn remaining_relay_indices(&self) -> BTreeSet<usize> {
        (0..self.relay_urls.len())
            .filter(|index| !self.acknowledged_relay_indices.contains(index))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfilePublicationProgress {
    Pending(PendingProfilePublication),
    Complete,
}

pub struct ProfilePublicationIntentStore<'store> {
    store: &'store SealedStore,
}

impl<'store> ProfilePublicationIntentStore<'store> {
    #[must_use]
    pub const fn new(store: &'store SealedStore) -> Self {
        Self { store }
    }

    pub fn load(
        &self,
        expected_public_key: &[u8; 32],
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<Option<PendingProfilePublication>, ProfilePublicationIntentError> {
        let encoded = match self.store.read(PROFILE_PUBLICATION_INTENT_RECORD_NAME) {
            Ok(encoded) => encoded,
            Err(StoreError::RecordNotFound) => return Ok(None),
            Err(error) => return Err(ProfilePublicationIntentError::Store(error)),
        };
        if encoded.len() > MAX_PROFILE_PUBLICATION_INTENT_BYTES {
            return Err(ProfilePublicationIntentError::Encoding);
        }
        let snapshot: ProfilePublicationSnapshot = serde_json::from_slice(&encoded)
            .map_err(|_| ProfilePublicationIntentError::Encoding)?;
        restore(snapshot, expected_public_key, now, event_limits).map(Some)
    }

    /// Persist one exact event/relay policy or return its identical replay.
    pub fn prepare(
        &self,
        event: &SignedEvent,
        relay_urls: &[String],
        required_acknowledgements: usize,
        expected_public_key: &[u8; 32],
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<PendingProfilePublication, ProfilePublicationIntentError> {
        verify_profile_metadata(event, expected_public_key, now, event_limits)
            .map_err(ProfilePublicationIntentError::Verification)?;
        let relay_urls = canonical_relay_urls(relay_urls)?;
        validate_threshold(required_acknowledgements, relay_urls.len())?;
        let candidate = PendingProfilePublication {
            event: event.clone(),
            relay_urls,
            required_acknowledgements,
            acknowledged_relay_indices: BTreeSet::new(),
        };
        if let Some(pending) = self.load(expected_public_key, now, event_limits)? {
            return if pending == candidate {
                Ok(pending)
            } else {
                Err(ProfilePublicationIntentError::PendingConflict)
            };
        }
        persist(self.store, &candidate)?;
        Ok(candidate)
    }

    /// Durably apply accepted relay indices for the exact pending event.
    /// Completion deletes the intent once its explicit threshold is met.
    pub fn acknowledge(
        &self,
        event_id: &str,
        accepted_relay_indices: &[usize],
        expected_public_key: &[u8; 32],
        now: u64,
        event_limits: &EventLimits,
    ) -> Result<ProfilePublicationProgress, ProfilePublicationIntentError> {
        let mut pending = self
            .load(expected_public_key, now, event_limits)?
            .ok_or(ProfilePublicationIntentError::PendingMissing)?;
        if pending.event.id != event_id {
            return Err(ProfilePublicationIntentError::PendingConflict);
        }
        if accepted_relay_indices
            .iter()
            .any(|index| *index >= pending.relay_urls.len())
        {
            return Err(ProfilePublicationIntentError::InvalidProgress);
        }
        pending
            .acknowledged_relay_indices
            .extend(accepted_relay_indices.iter().copied());
        if pending.acknowledged_relay_indices.len() >= pending.required_acknowledgements {
            self.store
                .delete(PROFILE_PUBLICATION_INTENT_RECORD_NAME)
                .map_err(ProfilePublicationIntentError::Store)?;
            Ok(ProfilePublicationProgress::Complete)
        } else {
            persist(self.store, &pending)?;
            Ok(ProfilePublicationProgress::Pending(pending))
        }
    }
}

fn restore(
    snapshot: ProfilePublicationSnapshot,
    expected_public_key: &[u8; 32],
    now: u64,
    event_limits: &EventLimits,
) -> Result<PendingProfilePublication, ProfilePublicationIntentError> {
    if snapshot.version != PROFILE_PUBLICATION_INTENT_VERSION {
        return Err(ProfilePublicationIntentError::UnsupportedVersion(
            snapshot.version,
        ));
    }
    verify_profile_metadata(&snapshot.event, expected_public_key, now, event_limits)
        .map_err(ProfilePublicationIntentError::Verification)?;
    let relay_urls = canonical_relay_urls(&snapshot.relay_urls)?;
    if relay_urls != snapshot.relay_urls {
        return Err(ProfilePublicationIntentError::InvalidRelays);
    }
    validate_threshold(snapshot.required_acknowledgements, relay_urls.len())?;
    if snapshot
        .acknowledged_relay_indices
        .iter()
        .any(|index| *index >= relay_urls.len())
        || snapshot.acknowledged_relay_indices.len() >= snapshot.required_acknowledgements
    {
        return Err(ProfilePublicationIntentError::InvalidProgress);
    }
    Ok(PendingProfilePublication {
        event: snapshot.event,
        relay_urls,
        required_acknowledgements: snapshot.required_acknowledgements,
        acknowledged_relay_indices: snapshot.acknowledged_relay_indices,
    })
}

fn canonical_relay_urls(
    relay_urls: &[String],
) -> Result<Vec<String>, ProfilePublicationIntentError> {
    if relay_urls.is_empty() || relay_urls.len() > MAX_PROFILE_PUBLICATION_RELAYS {
        return Err(ProfilePublicationIntentError::InvalidRelays);
    }
    let mut seen = HashSet::with_capacity(relay_urls.len());
    let mut canonical = Vec::with_capacity(relay_urls.len());
    for relay_url in relay_urls {
        let parsed =
            Url::parse(relay_url).map_err(|_| ProfilePublicationIntentError::InvalidRelays)?;
        if !matches!(parsed.scheme(), "ws" | "wss")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ProfilePublicationIntentError::InvalidRelays);
        }
        let parsed = parsed.to_string();
        if !seen.insert(parsed.clone()) {
            return Err(ProfilePublicationIntentError::InvalidRelays);
        }
        canonical.push(parsed);
    }
    canonical.sort_unstable();
    Ok(canonical)
}

fn validate_threshold(
    required_acknowledgements: usize,
    relay_count: usize,
) -> Result<(), ProfilePublicationIntentError> {
    if required_acknowledgements == 0 || required_acknowledgements > relay_count {
        Err(ProfilePublicationIntentError::InvalidThreshold)
    } else {
        Ok(())
    }
}

fn persist(
    store: &SealedStore,
    pending: &PendingProfilePublication,
) -> Result<(), ProfilePublicationIntentError> {
    let snapshot = ProfilePublicationSnapshot {
        version: PROFILE_PUBLICATION_INTENT_VERSION,
        event: pending.event.clone(),
        relay_urls: pending.relay_urls.clone(),
        required_acknowledgements: pending.required_acknowledgements,
        acknowledged_relay_indices: pending.acknowledged_relay_indices.clone(),
    };
    let encoded =
        serde_json::to_vec(&snapshot).map_err(|_| ProfilePublicationIntentError::Encoding)?;
    if encoded.len() > MAX_PROFILE_PUBLICATION_INTENT_BYTES {
        return Err(ProfilePublicationIntentError::Encoding);
    }
    store
        .write(PROFILE_PUBLICATION_INTENT_RECORD_NAME, &encoded)
        .map_err(ProfilePublicationIntentError::Store)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfilePublicationSnapshot {
    version: u16,
    event: SignedEvent,
    relay_urls: Vec<String>,
    required_acknowledgements: usize,
    acknowledged_relay_indices: BTreeSet<usize>,
}

#[derive(Debug)]
pub enum ProfilePublicationIntentError {
    Store(StoreError),
    Verification(ProfileVerificationError),
    Encoding,
    UnsupportedVersion(u16),
    InvalidRelays,
    InvalidThreshold,
    InvalidProgress,
    PendingConflict,
    PendingMissing,
}

impl fmt::Display for ProfilePublicationIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "profile publication storage failed: {error}"),
            Self::Verification(error) => {
                write!(formatter, "profile publication event is invalid: {error}")
            }
            Self::Encoding => formatter.write_str("profile publication encoding is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported profile publication version {version}"
                )
            }
            Self::InvalidRelays => formatter.write_str("profile publication relay set is invalid"),
            Self::InvalidThreshold => {
                formatter.write_str("profile publication acknowledgement threshold is invalid")
            }
            Self::InvalidProgress => {
                formatter.write_str("profile publication acknowledgement progress is invalid")
            }
            Self::PendingConflict => {
                formatter.write_str("a different profile publication is already pending")
            }
            Self::PendingMissing => formatter.write_str("profile publication intent is missing"),
        }
    }
}

impl Error for ProfilePublicationIntentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Verification(error) => Some(error),
            _ => None,
        }
    }
}
