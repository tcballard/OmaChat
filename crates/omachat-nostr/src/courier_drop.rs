//! Relay courier drops with rotating routing tags and throwaway signers.

use crate::event::{EventError, EventLimits, SignedEvent, UnsignedEvent, xonly_public_key};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    fmt,
};

pub const COURIER_DROP_KIND: u32 = 1_401;
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
pub const LOOKBACK_SECONDS: u64 = 48 * 60 * 60;

pub fn create(
    envelope: &[u8],
    routing_tag: &[u8; 16],
    expiration: u64,
    created_at: u64,
    throwaway_secret: &[u8; 32],
    signature_aux: &[u8; 32],
    limits: &EventLimits,
) -> Result<SignedEvent, DropError> {
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE_BYTES || expiration <= created_at {
        return Err(DropError::Invalid);
    }
    Ok(UnsignedEvent::new(
        hex::encode(xonly_public_key(throwaway_secret)?),
        created_at,
        COURIER_DROP_KIND,
        vec![
            vec!["x".into(), hex::encode(routing_tag)],
            vec!["expiration".into(), expiration.to_string()],
        ],
        STANDARD.encode(envelope),
        limits,
    )?
    .sign_with_aux(throwaway_secret, signature_aux, limits)?)
}

pub fn parse(
    event: &SignedEvent,
    expected_tags: &[[u8; 16]],
    now: u64,
    limits: &EventLimits,
) -> Result<Vec<u8>, DropError> {
    event.verify(now, limits)?;
    if event.kind != COURIER_DROP_KIND
        || event.created_at > now.saturating_add(15 * 60)
        || now.saturating_sub(event.created_at) > LOOKBACK_SECONDS
        || event.tags.len() != 2
    {
        return Err(DropError::Invalid);
    }
    let routing = event
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|value| value == "x"))
        .filter(|tag| tag.len() == 2)
        .ok_or(DropError::Invalid)?;
    let routing: [u8; 16] = hex::decode(&routing[1])
        .map_err(|_| DropError::Invalid)?
        .try_into()
        .map_err(|_| DropError::Invalid)?;
    if !expected_tags.contains(&routing) {
        return Err(DropError::WrongRecipient);
    }
    let expiration = event
        .tags
        .iter()
        .find(|tag| tag.first().is_some_and(|value| value == "expiration"))
        .filter(|tag| tag.len() == 2)
        .and_then(|tag| tag[1].parse::<u64>().ok())
        .ok_or(DropError::Invalid)?;
    if now > expiration {
        return Err(DropError::Expired);
    }
    if event.content.len() > (MAX_ENVELOPE_BYTES * 4).div_ceil(3) + 4 {
        return Err(DropError::TooLarge);
    }
    let envelope = STANDARD
        .decode(&event.content)
        .map_err(|_| DropError::Base64)?;
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(DropError::TooLarge);
    }
    Ok(envelope)
}

pub struct DropDedup {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}
impl DropDedup {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }
    pub fn accept(&mut self, event_id: &str) -> bool {
        if self.capacity == 0 || !self.seen.insert(event_id.to_owned()) {
            return false;
        }
        self.order.push_back(event_id.to_owned());
        if self.order.len() > self.capacity
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        true
    }
}

#[derive(Debug)]
pub enum DropError {
    Event(EventError),
    Invalid,
    WrongRecipient,
    Expired,
    TooLarge,
    Base64,
}
impl From<EventError> for DropError {
    fn from(value: EventError) -> Self {
        Self::Event(value)
    }
}
impl fmt::Display for DropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "courier drop error: {self:?}")
    }
}
impl Error for DropError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(e) => Some(e),
            _ => None,
        }
    }
}
