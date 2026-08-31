//! Bitchat-compatible private relay mailbox policy.

use crate::{
    envelope::{EnvelopeError, OpenedEnvelope, open_gift_wrap},
    event::{EventLimits, SignedEvent},
    pool::{RelayPool, RelayPoolError, RelayPublishOutcome},
};
use serde_json::{Value, json};
use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    fmt,
};

pub const PRIVATE_RELAY_PROFILE_ID: &str = "bitchat-private-swift-v1.7.1+android-v2.0.1";
pub const SWIFT_PRIVATE_RELAYS: [&str; 4] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://offchain.pub",
];
pub const ANDROID_PRIVATE_RELAYS: [&str; 4] = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://offchain.pub",
    "wss://nostr21.com",
];
pub const COMPATIBILITY_LOOKBACK_SECONDS: u64 = 48 * 60 * 60 + 15 * 60;
pub const DEFAULT_MAILBOX_FETCH_LIMIT: usize = 100;

/// Immutable private-relay profile spanning both pinned mobile releases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateRelayProfile {
    pub profile_id: &'static str,
    pub urls: Vec<&'static str>,
}

impl PrivateRelayProfile {
    #[must_use]
    pub fn pinned() -> Self {
        let mut urls = Vec::new();
        for url in SWIFT_PRIVATE_RELAYS
            .into_iter()
            .chain(ANDROID_PRIVATE_RELAYS)
        {
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
        Self {
            profile_id: PRIVATE_RELAY_PROFILE_ID,
            urls,
        }
    }
}

/// Explicit resource and compatibility limits for one private mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxConfig {
    pub lookback_seconds: u64,
    pub fetch_limit: usize,
    pub dedup_capacity: usize,
    pub dedup_ttl_seconds: u64,
    pub event_limits: EventLimits,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            lookback_seconds: COMPATIBILITY_LOOKBACK_SECONDS,
            fetch_limit: DEFAULT_MAILBOX_FETCH_LIMIT,
            dedup_capacity: 10_000,
            dedup_ttl_seconds: COMPATIBILITY_LOOKBACK_SECONDS,
            event_limits: EventLimits::default(),
        }
    }
}

/// Authenticated message metadata safe to surface even when the sender is blocked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateMessageMetadata {
    pub gift_wrap_id: String,
    pub sender_pubkey: String,
    pub true_created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateMessage {
    pub metadata: PrivateMessageMetadata,
    pub content: String,
}

/// Outcome of processing one relay-delivered gift wrap. Blocking is applied
/// only after both encrypted layers and the sender's signed seal authenticate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxReceive {
    Message(PrivateMessage),
    Blocked(PrivateMessageMetadata),
    Duplicate { gift_wrap_id: String },
}

/// Bounded mailbox state. Event IDs enter the dedup cache only after the full
/// private envelope has authenticated successfully.
pub struct PrivateMailbox {
    config: MailboxConfig,
    blocked_senders: HashSet<String>,
    seen: HashSet<String>,
    seen_order: VecDeque<(u64, String)>,
}

impl PrivateMailbox {
    pub fn new(config: MailboxConfig) -> Result<Self, MailboxError> {
        if config.lookback_seconds == 0
            || config.fetch_limit == 0
            || config.dedup_capacity == 0
            || config.dedup_ttl_seconds == 0
        {
            return Err(MailboxError::InvalidConfig);
        }
        Ok(Self {
            config,
            blocked_senders: HashSet::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        })
    }

    #[must_use]
    pub fn config(&self) -> MailboxConfig {
        self.config
    }

    /// Build the exact outer-`p` filter used for offline mailbox recovery.
    pub fn subscription_filter(
        &self,
        recipient_xonly_public_key: &str,
        now: u64,
    ) -> Result<Value, MailboxError> {
        validate_xonly(recipient_xonly_public_key)?;
        Ok(json!({
            "kinds": [crate::envelope::GIFT_WRAP_KIND],
            "#p": [recipient_xonly_public_key],
            "since": now.saturating_sub(self.config.lookback_seconds),
            "limit": self.config.fetch_limit,
        }))
    }

    pub fn block_sender(&mut self, sender_xonly_public_key: &str) -> Result<(), MailboxError> {
        validate_xonly(sender_xonly_public_key)?;
        self.blocked_senders
            .insert(sender_xonly_public_key.to_owned());
        Ok(())
    }

    pub fn unblock_sender(&mut self, sender_xonly_public_key: &str) -> Result<(), MailboxError> {
        validate_xonly(sender_xonly_public_key)?;
        self.blocked_senders.remove(sender_xonly_public_key);
        Ok(())
    }

    pub fn receive(
        &mut self,
        gift_wrap: &SignedEvent,
        recipient_secret_key: &[u8; 32],
        now: u64,
    ) -> Result<MailboxReceive, MailboxError> {
        let opened = open_gift_wrap(
            gift_wrap,
            recipient_secret_key,
            now,
            &self.config.event_limits,
        )?;
        if !self.remember(&gift_wrap.id, now) {
            return Ok(MailboxReceive::Duplicate {
                gift_wrap_id: gift_wrap.id.clone(),
            });
        }
        Ok(self.apply_sender_policy(gift_wrap, opened))
    }

    fn apply_sender_policy(
        &self,
        gift_wrap: &SignedEvent,
        opened: OpenedEnvelope,
    ) -> MailboxReceive {
        let metadata = PrivateMessageMetadata {
            gift_wrap_id: gift_wrap.id.clone(),
            sender_pubkey: opened.sender_pubkey.clone(),
            true_created_at: opened.true_created_at,
        };
        if self.blocked_senders.contains(&opened.sender_pubkey) {
            MailboxReceive::Blocked(metadata)
        } else {
            MailboxReceive::Message(PrivateMessage {
                metadata,
                content: opened.content,
            })
        }
    }

    fn remember(&mut self, event_id: &str, now: u64) -> bool {
        while let Some((seen_at, oldest)) = self.seen_order.front() {
            if now.saturating_sub(*seen_at) < self.config.dedup_ttl_seconds {
                break;
            }
            self.seen.remove(oldest);
            self.seen_order.pop_front();
        }
        if self.seen.contains(event_id) {
            return false;
        }
        while self.seen.len() >= self.config.dedup_capacity {
            let Some((_, oldest)) = self.seen_order.pop_front() else {
                break;
            };
            self.seen.remove(&oldest);
        }
        self.seen.insert(event_id.to_owned());
        self.seen_order.push_back((now, event_id.to_owned()));
        true
    }
}

/// Durable-relay result model for one private send. `Stored` means the pool's
/// configured acknowledgement threshold was met, not merely that bytes were
/// written to WebSockets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrivatePublishResult {
    Stored {
        gift_wrap_id: String,
        accepted: usize,
        attempted: usize,
        outcomes: Vec<RelayPublishOutcome>,
    },
    NotStored {
        gift_wrap_id: String,
        accepted: usize,
        required: usize,
        attempted: usize,
    },
    Failed {
        gift_wrap_id: String,
        error: RelayPoolError,
    },
}

pub async fn publish_gift_wrap(pool: &RelayPool, gift_wrap: SignedEvent) -> PrivatePublishResult {
    let gift_wrap_id = gift_wrap.id.clone();
    match pool.publish(gift_wrap).await {
        Ok(result) => PrivatePublishResult::Stored {
            gift_wrap_id,
            accepted: result.accepted,
            attempted: result.attempted,
            outcomes: result.outcomes,
        },
        Err(RelayPoolError::AcknowledgementThreshold {
            accepted,
            required,
            attempted,
        }) => PrivatePublishResult::NotStored {
            gift_wrap_id,
            accepted,
            required,
            attempted,
        },
        Err(error) => PrivatePublishResult::Failed {
            gift_wrap_id,
            error,
        },
    }
}

#[derive(Debug)]
pub enum MailboxError {
    InvalidConfig,
    InvalidPublicKey,
    Envelope(EnvelopeError),
}

impl fmt::Display for MailboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("mailbox bounds must be non-zero"),
            Self::InvalidPublicKey => formatter.write_str("invalid x-only mailbox public key"),
            Self::Envelope(error) => write!(formatter, "private mailbox envelope failed: {error}"),
        }
    }
}

impl Error for MailboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Envelope(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EnvelopeError> for MailboxError {
    fn from(error: EnvelopeError) -> Self {
        Self::Envelope(error)
    }
}

fn validate_xonly(value: &str) -> Result<(), MailboxError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(MailboxError::InvalidPublicKey)
    }
}
