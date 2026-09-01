//! Authenticated standard NIP-17/NIP-59 direct-message receive boundary.

use crate::{
    event::{EventLimits, SignedEvent, Tag, xonly_public_key},
    gift_wrap::{CHAT_MESSAGE_KIND, GIFT_WRAP_KIND, GiftWrapError, OpenedGiftWrap, open_gift_wrap},
};
use serde_json::{Value, json};
use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    fmt,
};

pub const DEFAULT_DM_LOOKBACK_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const DEFAULT_DM_FETCH_LIMIT: usize = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmInboxConfig {
    pub lookback_seconds: u64,
    pub fetch_limit: usize,
    pub dedup_capacity: usize,
    pub dedup_ttl_seconds: u64,
    pub event_limits: EventLimits,
}

impl Default for DmInboxConfig {
    fn default() -> Self {
        Self {
            lookback_seconds: DEFAULT_DM_LOOKBACK_SECONDS,
            fetch_limit: DEFAULT_DM_FETCH_LIMIT,
            dedup_capacity: 10_000,
            dedup_ttl_seconds: DEFAULT_DM_LOOKBACK_SECONDS,
            event_limits: EventLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmMessageMetadata {
    pub gift_wrap_id: String,
    pub seal_id: String,
    pub rumor_id: String,
    pub author_pubkey: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmMessage {
    pub metadata: DmMessageMetadata,
    pub tags: Vec<Tag>,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DmInboxReceive {
    Message(DmMessage),
    Blocked(DmMessageMetadata),
    Duplicate { gift_wrap_id: String },
}

/// Bounded in-memory processing state. Relay delivery is untrusted until the
/// outer event, seal, and rumor have all passed `open_gift_wrap`.
pub struct DmInbox {
    config: DmInboxConfig,
    blocked_authors: HashSet<String>,
    seen: HashSet<String>,
    seen_order: VecDeque<(u64, String)>,
}

impl DmInbox {
    pub fn new(config: DmInboxConfig) -> Result<Self, DmInboxError> {
        if config.lookback_seconds == 0
            || config.fetch_limit == 0
            || config.dedup_capacity == 0
            || config.dedup_ttl_seconds == 0
        {
            return Err(DmInboxError::InvalidConfig);
        }
        Ok(Self {
            config,
            blocked_authors: HashSet::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        })
    }

    #[must_use]
    pub fn config(&self) -> DmInboxConfig {
        self.config
    }

    /// Build the exact persistent gift-wrap filter for one recipient.
    pub fn subscription_filter(
        &self,
        recipient_xonly_public_key: &str,
        now: u64,
    ) -> Result<Value, DmInboxError> {
        validate_xonly(recipient_xonly_public_key)?;
        Ok(json!({
            "kinds": [GIFT_WRAP_KIND],
            "#p": [recipient_xonly_public_key],
            "since": now.saturating_sub(self.config.lookback_seconds),
            "limit": self.config.fetch_limit,
        }))
    }

    pub fn block_author(&mut self, author_xonly_public_key: &str) -> Result<(), DmInboxError> {
        validate_xonly(author_xonly_public_key)?;
        self.blocked_authors
            .insert(author_xonly_public_key.to_owned());
        Ok(())
    }

    pub fn unblock_author(&mut self, author_xonly_public_key: &str) -> Result<(), DmInboxError> {
        validate_xonly(author_xonly_public_key)?;
        self.blocked_authors.remove(author_xonly_public_key);
        Ok(())
    }

    pub fn receive(
        &mut self,
        gift_wrap: &SignedEvent,
        recipient_secret_key: &[u8; 32],
        now: u64,
    ) -> Result<DmInboxReceive, DmInboxError> {
        if gift_wrap.kind != GIFT_WRAP_KIND {
            return Err(DmInboxError::UnexpectedGiftWrapKind {
                actual: gift_wrap.kind,
            });
        }
        let recipient_public_key =
            xonly_public_key(recipient_secret_key).map_err(|_| DmInboxError::InvalidSecretKey)?;
        let recipient_hex = hex::encode(recipient_public_key);
        require_exact_outer_recipient(gift_wrap, &recipient_hex)?;

        let opened = open_gift_wrap(
            gift_wrap,
            recipient_secret_key,
            now,
            &self.config.event_limits,
        )?;
        if opened.rumor.kind != CHAT_MESSAGE_KIND {
            return Err(DmInboxError::UnexpectedRumorKind {
                actual: opened.rumor.kind,
            });
        }
        if !self.remember(&gift_wrap.id, now) {
            return Ok(DmInboxReceive::Duplicate {
                gift_wrap_id: gift_wrap.id.clone(),
            });
        }
        Ok(self.apply_author_policy(gift_wrap, opened))
    }

    fn apply_author_policy(
        &self,
        gift_wrap: &SignedEvent,
        opened: OpenedGiftWrap,
    ) -> DmInboxReceive {
        let metadata = DmMessageMetadata {
            gift_wrap_id: gift_wrap.id.clone(),
            seal_id: opened.seal.id,
            rumor_id: opened.rumor.id,
            author_pubkey: opened.rumor.pubkey.clone(),
            created_at: opened.rumor.created_at,
        };
        if self.blocked_authors.contains(&opened.rumor.pubkey) {
            DmInboxReceive::Blocked(metadata)
        } else {
            DmInboxReceive::Message(DmMessage {
                metadata,
                tags: opened.rumor.tags,
                content: opened.rumor.content,
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

fn require_exact_outer_recipient(
    gift_wrap: &SignedEvent,
    recipient_hex: &str,
) -> Result<(), DmInboxError> {
    let recipients: Vec<&str> = gift_wrap
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "p"))
        .filter_map(|tag| tag.get(1).map(String::as_str))
        .collect();
    if recipients.len() == 1 && recipients[0] == recipient_hex {
        Ok(())
    } else {
        Err(DmInboxError::WrongRecipient)
    }
}

fn validate_xonly(value: &str) -> Result<(), DmInboxError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(DmInboxError::InvalidPublicKey)
    }
}

#[derive(Debug)]
pub enum DmInboxError {
    InvalidConfig,
    InvalidPublicKey,
    InvalidSecretKey,
    WrongRecipient,
    UnexpectedGiftWrapKind { actual: u32 },
    UnexpectedRumorKind { actual: u32 },
    GiftWrap(GiftWrapError),
}

impl fmt::Display for DmInboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("DM inbox bounds must be non-zero"),
            Self::InvalidPublicKey => formatter.write_str("invalid x-only DM inbox public key"),
            Self::InvalidSecretKey => formatter.write_str("invalid DM inbox secret key"),
            Self::WrongRecipient => {
                formatter.write_str("gift wrap is not routed to exactly this recipient")
            }
            Self::UnexpectedGiftWrapKind { actual } => {
                write!(
                    formatter,
                    "expected persistent gift-wrap kind {GIFT_WRAP_KIND}, got {actual}"
                )
            }
            Self::UnexpectedRumorKind { actual } => {
                write!(
                    formatter,
                    "expected chat rumor kind {CHAT_MESSAGE_KIND}, got {actual}"
                )
            }
            Self::GiftWrap(error) => write!(formatter, "NIP-59 gift wrap failed: {error}"),
        }
    }
}

impl Error for DmInboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::GiftWrap(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GiftWrapError> for DmInboxError {
    fn from(error: GiftWrapError) -> Self {
        Self::GiftWrap(error)
    }
}
