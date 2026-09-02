use std::{collections::BTreeSet, error::Error, fmt};

use omachat_nostr::{
    discovery::{RelayDiscoveryLimits, RelayList, parse_nip65_relay_list},
    event::{EventLimits, SignedEvent},
};
use omachat_store::{SealedStore, StoreError};
use serde::{Deserialize, Serialize};

pub const RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME: &str =
    "nip65-relay-list-publication-intent-v1";
const RELAY_LIST_PUBLICATION_INTENT_VERSION: u16 = 1;
const MAX_RELAY_LIST_PUBLICATION_INTENT_BYTES: usize = 128 * 1_024;

pub struct RelayListPublicationIntentStore<'a> {
    store: &'a SealedStore,
}

impl<'a> RelayListPublicationIntentStore<'a> {
    pub fn new(store: &'a SealedStore) -> Self {
        Self { store }
    }

    pub fn prepare(
        &self,
        event: &SignedEvent,
        expected_public_key: &[u8; 32],
        required_acknowledgements: usize,
        now: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<RelayListPublicationMutation, RelayListPublicationIntentError> {
        let candidate = PendingRelayListPublication::validate(
            event.clone(),
            *expected_public_key,
            required_acknowledgements,
            BTreeSet::new(),
            now,
            event_limits,
            relay_limits,
        )?;
        match self.load(now, event_limits, relay_limits)? {
            RelayListPublicationIntentState::Missing => {
                self.save(&candidate)?;
                Ok(RelayListPublicationMutation::Stored)
            }
            RelayListPublicationIntentState::Pending(current)
                if current.event.id == candidate.event.id
                    && current.expected_public_key == candidate.expected_public_key
                    && current.required_acknowledgements == candidate.required_acknowledgements =>
            {
                Ok(RelayListPublicationMutation::Unchanged)
            }
            RelayListPublicationIntentState::Pending(_) => {
                Err(RelayListPublicationIntentError::PendingConflict)
            }
        }
    }

    pub fn load(
        &self,
        now: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<RelayListPublicationIntentState, RelayListPublicationIntentError> {
        let encoded = match self.store.read(RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME) {
            Ok(encoded) => encoded,
            Err(StoreError::RecordNotFound) => {
                return Ok(RelayListPublicationIntentState::Missing);
            }
            Err(error) => return Err(error.into()),
        };
        if encoded.len() > MAX_RELAY_LIST_PUBLICATION_INTENT_BYTES {
            return Err(RelayListPublicationIntentError::IntentTooLarge);
        }
        let persisted: PersistedRelayListPublicationIntent = serde_json::from_slice(&encoded)
            .map_err(|_| RelayListPublicationIntentError::InvalidEncoding)?;
        if persisted.version != RELAY_LIST_PUBLICATION_INTENT_VERSION {
            return Err(RelayListPublicationIntentError::UnsupportedVersion(
                persisted.version,
            ));
        }
        let expected_public_key = decode_public_key(&persisted.expected_public_key)?;
        let acknowledged_relays = persisted
            .acknowledged_relays
            .into_iter()
            .collect::<BTreeSet<_>>();
        if acknowledged_relays.len() != persisted.acknowledgement_count {
            return Err(RelayListPublicationIntentError::InvalidEncoding);
        }
        let pending = PendingRelayListPublication::validate(
            persisted.event,
            expected_public_key,
            persisted.required_acknowledgements,
            acknowledged_relays,
            now,
            event_limits,
            relay_limits,
        )?;
        Ok(RelayListPublicationIntentState::Pending(Box::new(pending)))
    }

    pub fn acknowledge(
        &self,
        event_id: &str,
        relay_url: &str,
        now: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<RelayListPublicationProgress, RelayListPublicationIntentError> {
        let RelayListPublicationIntentState::Pending(mut pending) =
            self.load(now, event_limits, relay_limits)?
        else {
            return Err(RelayListPublicationIntentError::MissingIntent);
        };
        if pending.event.id != event_id {
            return Err(RelayListPublicationIntentError::EventMismatch);
        }
        if !pending
            .publication_relays
            .iter()
            .any(|configured| configured == relay_url)
        {
            return Err(RelayListPublicationIntentError::UnknownRelay);
        }
        pending.acknowledged_relays.insert(relay_url.to_owned());
        let progress = pending.progress();
        if progress.complete {
            self.store
                .delete(RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME)?;
        } else {
            self.save(&pending)?;
        }
        Ok(progress)
    }

    pub fn clear(&self) -> Result<(), RelayListPublicationIntentError> {
        self.store
            .delete(RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME)?;
        Ok(())
    }

    fn save(
        &self,
        pending: &PendingRelayListPublication,
    ) -> Result<(), RelayListPublicationIntentError> {
        let persisted = PersistedRelayListPublicationIntent {
            version: RELAY_LIST_PUBLICATION_INTENT_VERSION,
            expected_public_key: hex::encode(pending.expected_public_key),
            event: pending.event.clone(),
            required_acknowledgements: pending.required_acknowledgements,
            acknowledgement_count: pending.acknowledged_relays.len(),
            acknowledged_relays: pending.acknowledged_relays.iter().cloned().collect(),
        };
        let encoded = serde_json::to_vec(&persisted)
            .map_err(|_| RelayListPublicationIntentError::InvalidEncoding)?;
        if encoded.len() > MAX_RELAY_LIST_PUBLICATION_INTENT_BYTES {
            return Err(RelayListPublicationIntentError::IntentTooLarge);
        }
        self.store
            .write(RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME, &encoded)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRelayListPublication {
    expected_public_key: [u8; 32],
    event: SignedEvent,
    relay_list: RelayList,
    publication_relays: Vec<String>,
    required_acknowledgements: usize,
    acknowledged_relays: BTreeSet<String>,
}

impl PendingRelayListPublication {
    fn validate(
        event: SignedEvent,
        expected_public_key: [u8; 32],
        required_acknowledgements: usize,
        acknowledged_relays: BTreeSet<String>,
        now: u64,
        event_limits: &EventLimits,
        relay_limits: &RelayDiscoveryLimits,
    ) -> Result<Self, RelayListPublicationIntentError> {
        if event.pubkey != hex::encode(expected_public_key) {
            return Err(RelayListPublicationIntentError::UnexpectedAuthor);
        }
        let relay_list = parse_nip65_relay_list(&event, now, event_limits, relay_limits)
            .map_err(|_| RelayListPublicationIntentError::InvalidSourceEvent)?;
        let publication_relays = relay_list
            .relays
            .iter()
            .filter(|relay| relay.write)
            .map(|relay| relay.url.clone())
            .collect::<Vec<_>>();
        if publication_relays.is_empty() {
            return Err(RelayListPublicationIntentError::NoWritableRelays);
        }
        if required_acknowledgements == 0 || required_acknowledgements > publication_relays.len() {
            return Err(RelayListPublicationIntentError::InvalidAcknowledgementPolicy);
        }
        if acknowledged_relays
            .iter()
            .any(|relay| !publication_relays.contains(relay))
        {
            return Err(RelayListPublicationIntentError::UnknownRelay);
        }
        if acknowledged_relays.len() >= required_acknowledgements {
            return Err(RelayListPublicationIntentError::CompletedIntentPersisted);
        }
        Ok(Self {
            expected_public_key,
            event,
            relay_list,
            publication_relays,
            required_acknowledgements,
            acknowledged_relays,
        })
    }

    pub fn expected_public_key(&self) -> &[u8; 32] {
        &self.expected_public_key
    }

    pub fn event(&self) -> &SignedEvent {
        &self.event
    }

    pub fn relay_list(&self) -> &RelayList {
        &self.relay_list
    }

    pub fn publication_relays(&self) -> &[String] {
        &self.publication_relays
    }

    pub fn required_acknowledgements(&self) -> usize {
        self.required_acknowledgements
    }

    pub fn acknowledged_relays(&self) -> &BTreeSet<String> {
        &self.acknowledged_relays
    }

    fn progress(&self) -> RelayListPublicationProgress {
        RelayListPublicationProgress {
            event_id: self.event.id.clone(),
            acknowledged_relays: self.acknowledged_relays.iter().cloned().collect(),
            required_acknowledgements: self.required_acknowledgements,
            complete: self.acknowledged_relays.len() >= self.required_acknowledgements,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayListPublicationIntentState {
    Missing,
    Pending(Box<PendingRelayListPublication>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayListPublicationMutation {
    Stored,
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayListPublicationProgress {
    pub event_id: String,
    pub acknowledged_relays: Vec<String>,
    pub required_acknowledgements: usize,
    pub complete: bool,
}

#[derive(Debug)]
pub enum RelayListPublicationIntentError {
    Store(StoreError),
    InvalidEncoding,
    UnsupportedVersion(u16),
    IntentTooLarge,
    InvalidSourceEvent,
    UnexpectedAuthor,
    NoWritableRelays,
    InvalidAcknowledgementPolicy,
    PendingConflict,
    MissingIntent,
    EventMismatch,
    UnknownRelay,
    CompletedIntentPersisted,
}

impl fmt::Display for RelayListPublicationIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "sealed NIP-65 publication failed: {error}"),
            Self::InvalidEncoding => formatter.write_str("invalid NIP-65 publication encoding"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported NIP-65 publication version {version}"
                )
            }
            Self::IntentTooLarge => formatter.write_str("NIP-65 publication intent is too large"),
            Self::InvalidSourceEvent => formatter.write_str("NIP-65 publication event is invalid"),
            Self::UnexpectedAuthor => {
                formatter.write_str("NIP-65 publication author does not match the participant")
            }
            Self::NoWritableRelays => {
                formatter.write_str("NIP-65 publication has no write-capable relay")
            }
            Self::InvalidAcknowledgementPolicy => {
                formatter.write_str("NIP-65 acknowledgement policy is unsatisfiable")
            }
            Self::PendingConflict => {
                formatter.write_str("a different NIP-65 publication is already pending")
            }
            Self::MissingIntent => formatter.write_str("no NIP-65 publication is pending"),
            Self::EventMismatch => {
                formatter.write_str("NIP-65 acknowledgement targets a different event")
            }
            Self::UnknownRelay => {
                formatter.write_str("NIP-65 acknowledgement came from an unknown relay")
            }
            Self::CompletedIntentPersisted => {
                formatter.write_str("completed NIP-65 publication remained pending")
            }
        }
    }
}

impl Error for RelayListPublicationIntentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StoreError> for RelayListPublicationIntentError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRelayListPublicationIntent {
    version: u16,
    expected_public_key: String,
    event: SignedEvent,
    required_acknowledgements: usize,
    acknowledgement_count: usize,
    acknowledged_relays: Vec<String>,
}

fn decode_public_key(encoded: &str) -> Result<[u8; 32], RelayListPublicationIntentError> {
    let mut public_key = [0; 32];
    hex::decode_to_slice(encoded, &mut public_key)
        .map_err(|_| RelayListPublicationIntentError::InvalidEncoding)?;
    Ok(public_key)
}
