use crate::sealed::{SealedStore, StoreError};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

const OUTBOX_RECORD: &str = "nostr-outbox-v1";
const OUTBOX_MAX_PER_PEER: usize = 100;
const OUTBOX_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const OUTBOX_MAX_ATTEMPTS: u8 = 8;
const OUTBOX_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboxState {
    Pending,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboxMessage {
    pub id: String,
    pub peer: String,
    pub gift_wrap: String,
    pub created_at: u64,
    pub attempts: u8,
    pub last_attempt_at: Option<u64>,
    pub state: OutboxState,
    #[serde(default)]
    pub attempt_history: Vec<TransportAttempt>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboxTransport {
    Mesh,
    Nostr,
    Courier,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptOutcome {
    Sent,
    Acknowledged,
    Unavailable,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransportAttempt {
    pub transport: OutboxTransport,
    pub at: u64,
    pub outcome: AttemptOutcome,
}

#[derive(Default, Deserialize, Serialize)]
struct PersistedOutbox {
    messages: Vec<OutboxMessage>,
}

/// Sealed, ordered Nostr private-message retry queue.
pub struct NostrOutbox<'store> {
    store: &'store SealedStore,
    state: PersistedOutbox,
}

impl<'store> NostrOutbox<'store> {
    pub fn load(store: &'store SealedStore, now: u64) -> Result<Self, OutboxError> {
        let mut state = match store.read(OUTBOX_RECORD) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| OutboxError::Encoding)?,
            Err(StoreError::RecordNotFound) => PersistedOutbox::default(),
            Err(error) => return Err(OutboxError::Store(error)),
        };
        let old_length = state.messages.len();
        state
            .messages
            .retain(|message| !expired(message.created_at, now));
        let outbox = Self { store, state };
        if outbox.state.messages.len() != old_length {
            outbox.persist()?;
        }
        Ok(outbox)
    }

    pub fn enqueue(
        &mut self,
        id: impl Into<String>,
        peer: impl Into<String>,
        gift_wrap: impl Into<String>,
        now: u64,
    ) -> Result<(), OutboxError> {
        self.expire(now);
        let id = id.into();
        let peer = peer.into();
        let gift_wrap = gift_wrap.into();
        validate_outbox_field(&id)?;
        validate_outbox_field(&peer)?;
        if gift_wrap.len() > OUTBOX_MAX_PAYLOAD_BYTES {
            return Err(OutboxError::PayloadTooLarge);
        }
        if self.state.messages.iter().any(|message| message.id == id) {
            return Err(OutboxError::Duplicate);
        }
        if self
            .state
            .messages
            .iter()
            .filter(|message| message.peer == peer)
            .count()
            >= OUTBOX_MAX_PER_PEER
        {
            return Err(OutboxError::QueueFull);
        }
        self.state.messages.push(OutboxMessage {
            id,
            peer,
            gift_wrap,
            created_at: now,
            attempts: 0,
            last_attempt_at: None,
            state: OutboxState::Pending,
            attempt_history: Vec::new(),
        });
        self.persist()
    }

    #[must_use]
    pub fn messages(&self) -> &[OutboxMessage] {
        &self.state.messages
    }

    #[must_use]
    pub fn next_pending(&self) -> Option<&OutboxMessage> {
        self.state
            .messages
            .iter()
            .find(|message| message.state == OutboxState::Pending)
    }

    pub fn record_attempt(
        &mut self,
        id: &str,
        acknowledged: bool,
        now: u64,
    ) -> Result<OutboxState, OutboxError> {
        let index = self
            .state
            .messages
            .iter()
            .position(|message| message.id == id)
            .ok_or(OutboxError::UnknownMessage)?;
        if acknowledged {
            self.state.messages.remove(index);
            self.persist()?;
            return Ok(OutboxState::Pending);
        }
        let message = &mut self.state.messages[index];
        if message.state == OutboxState::Failed {
            return Ok(OutboxState::Failed);
        }
        message.attempts = message.attempts.saturating_add(1);
        message.last_attempt_at = Some(now);
        if message.attempts >= OUTBOX_MAX_ATTEMPTS {
            message.state = OutboxState::Failed;
        }
        let state = message.state;
        self.persist()?;
        Ok(state)
    }

    pub fn record_transport_attempt(
        &mut self,
        id: &str,
        transport: OutboxTransport,
        outcome: AttemptOutcome,
        now: u64,
    ) -> Result<OutboxState, OutboxError> {
        let message = self
            .state
            .messages
            .iter_mut()
            .find(|message| message.id == id)
            .ok_or(OutboxError::UnknownMessage)?;
        if message.attempt_history.len() == 32 {
            message.attempt_history.remove(0);
        }
        message.attempt_history.push(TransportAttempt {
            transport,
            at: now,
            outcome,
        });
        if outcome == AttemptOutcome::Acknowledged {
            self.state.messages.retain(|message| message.id != id);
            self.persist()?;
            return Ok(OutboxState::Pending);
        }
        if matches!(
            outcome,
            AttemptOutcome::Unavailable | AttemptOutcome::Rejected
        ) {
            message.attempts = message.attempts.saturating_add(1);
            message.last_attempt_at = Some(now);
            if message.attempts >= OUTBOX_MAX_ATTEMPTS {
                message.state = OutboxState::Failed;
            }
        }
        let state = message.state;
        self.persist()?;
        Ok(state)
    }

    pub fn retry_failed(&mut self, id: &str) -> Result<(), OutboxError> {
        let message = self
            .state
            .messages
            .iter_mut()
            .find(|message| message.id == id)
            .ok_or(OutboxError::UnknownMessage)?;
        message.attempts = 0;
        message.last_attempt_at = None;
        message.state = OutboxState::Pending;
        self.persist()
    }

    fn expire(&mut self, now: u64) {
        self.state
            .messages
            .retain(|message| !expired(message.created_at, now));
    }

    fn persist(&self) -> Result<(), OutboxError> {
        let bytes = serde_json::to_vec(&self.state).map_err(|_| OutboxError::Encoding)?;
        self.store
            .write(OUTBOX_RECORD, &bytes)
            .map_err(OutboxError::Store)
    }
}

fn expired(created_at: u64, now: u64) -> bool {
    now.saturating_sub(created_at) >= OUTBOX_MAX_AGE_SECONDS
}

fn validate_outbox_field(value: &str) -> Result<(), OutboxError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(OutboxError::InvalidField)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum OutboxError {
    Store(StoreError),
    Encoding,
    InvalidField,
    PayloadTooLarge,
    Duplicate,
    QueueFull,
    UnknownMessage,
}

impl fmt::Display for OutboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "outbox storage failed: {error}"),
            Self::Encoding => formatter.write_str("outbox encoding is invalid"),
            Self::InvalidField => formatter.write_str("outbox identifier is invalid"),
            Self::PayloadTooLarge => formatter.write_str("outbox payload exceeds the size limit"),
            Self::Duplicate => formatter.write_str("outbox message already exists"),
            Self::QueueFull => formatter.write_str("outbox peer queue is full"),
            Self::UnknownMessage => formatter.write_str("outbox message does not exist"),
        }
    }
}

impl Error for OutboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}
