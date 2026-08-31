//! Signed geohash chat, presence, and captured NIP-13 policy.

use crate::event::{EventError, EventLimits, SignedEvent, Tag, UnsignedEvent, xonly_public_key};
use omachat_proto::geohash::{Geohash, GeohashError};
use serde_json::{Value, json};
use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    fmt,
    time::{Duration, Instant},
};

pub const CHAT_KIND: u32 = 20_000;
pub const PRESENCE_KIND: u32 = 20_001;
pub const POW_TARGET_BITS: u16 = 8;
pub const POW_RATE_LIMIT_BYPASS_BITS: u16 = 8;
pub const POW_MAIN_TIME_CAP: Duration = Duration::from_secs(2);
pub const POW_FALLBACK_TIME_CAP: Duration = Duration::from_millis(150);
const POW_DEADLINE_CHECK_INTERVAL: u64 = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatInput<'a> {
    pub secret_key: &'a [u8; 32],
    pub created_at: u64,
    pub geohash: &'a Geohash,
    pub nickname: Option<&'a str>,
    pub teleported: bool,
    pub content: &'a str,
    pub signature_aux: &'a [u8; 32],
}

/// Create and sign an unmined kind-20000 event. This remains interoperable:
/// the pinned inbound policy scores missing work as zero instead of rejecting.
pub fn create_chat(
    input: &ChatInput<'_>,
    limits: &EventLimits,
) -> Result<SignedEvent, GeoEventError> {
    sign_chat(input, chat_tags(input)?, limits)
}

/// Mine with the captured 2-second target-8 policy, halving the committed
/// target under 150 ms fallback budgets until a bounded attempt succeeds.
/// Callers supply a random starting nonce in production.
pub fn create_mined_chat(
    input: &ChatInput<'_>,
    starting_nonce: u64,
    limits: &EventLimits,
) -> Result<SignedEvent, GeoEventError> {
    let mut tags = chat_tags(input)?;
    let pubkey = hex::encode(xonly_public_key(input.secret_key)?);
    let nonce = mine_nonce_tag(
        &UnsignedEvent::new(
            pubkey,
            input.created_at,
            CHAT_KIND,
            tags.clone(),
            input.content.to_owned(),
            limits,
        )?,
        POW_TARGET_BITS,
        starting_nonce,
        POW_MAIN_TIME_CAP,
        POW_FALLBACK_TIME_CAP,
    )?;
    tags.push(nonce);
    sign_chat(input, tags, limits)
}

pub fn create_presence(
    secret_key: &[u8; 32],
    created_at: u64,
    geohash: &Geohash,
    signature_aux: &[u8; 32],
    limits: &EventLimits,
) -> Result<SignedEvent, GeoEventError> {
    Ok(UnsignedEvent::new(
        hex::encode(xonly_public_key(secret_key)?),
        created_at,
        PRESENCE_KIND,
        vec![vec!["g".into(), geohash.as_str().into()]],
        String::new(),
        limits,
    )?
    .sign_with_aux(secret_key, signature_aux, limits)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedGeoEvent {
    Chat {
        event_id: String,
        sender_pubkey: String,
        created_at: u64,
        geohash: Geohash,
        nickname: Option<String>,
        teleported: bool,
        content: String,
        validated_pow_bits: u16,
    },
    Presence {
        event_id: String,
        sender_pubkey: String,
        created_at: u64,
        geohash: Geohash,
    },
}

pub fn parse_geo_event(
    event: &SignedEvent,
    now: u64,
    limits: &EventLimits,
) -> Result<ParsedGeoEvent, GeoEventError> {
    event.verify(now, limits)?;
    match event.kind {
        CHAT_KIND => parse_chat(event),
        PRESENCE_KIND => parse_presence(event),
        actual => Err(GeoEventError::WrongKind(actual)),
    }
}

fn parse_chat(event: &SignedEvent) -> Result<ParsedGeoEvent, GeoEventError> {
    let mut geohash = None;
    let mut nickname = None;
    let mut teleported = false;
    let mut nonce_count = 0;
    for tag in &event.tags {
        match tag.first().map(String::as_str) {
            Some("g") if tag.len() == 2 && geohash.is_none() => {
                geohash = Some(Geohash::parse(&tag[1])?);
            }
            Some("n") if tag.len() == 2 && nickname.is_none() => {
                let normalized = tag[1].trim();
                if normalized.is_empty() {
                    return Err(GeoEventError::InvalidNickname);
                }
                nickname = Some(normalized.to_owned());
            }
            Some("t") if tag.len() == 2 && tag[1] == "teleport" && !teleported => {
                teleported = true;
            }
            Some("nonce") => {
                nonce_count += 1;
                if nonce_count > 1 {
                    return Err(GeoEventError::DuplicateTag("nonce"));
                }
            }
            Some("g") => return Err(GeoEventError::DuplicateTag("g")),
            Some("n") => return Err(GeoEventError::DuplicateTag("n")),
            Some("t") => return Err(GeoEventError::DuplicateTag("t")),
            _ => return Err(GeoEventError::UnsupportedTag),
        }
    }
    Ok(ParsedGeoEvent::Chat {
        event_id: event.id.clone(),
        sender_pubkey: event.pubkey.clone(),
        created_at: event.created_at,
        geohash: geohash.ok_or(GeoEventError::MissingGeohash)?,
        nickname,
        teleported,
        content: event.content.clone(),
        validated_pow_bits: validated_pow_difficulty(&event.id, &event.tags),
    })
}

fn parse_presence(event: &SignedEvent) -> Result<ParsedGeoEvent, GeoEventError> {
    if !event.content.is_empty() {
        return Err(GeoEventError::PresenceContent);
    }
    if event.tags.len() != 1 || event.tags[0].len() != 2 || event.tags[0][0] != "g" {
        return Err(GeoEventError::PresenceTags);
    }
    Ok(ParsedGeoEvent::Presence {
        event_id: event.id.clone(),
        sender_pubkey: event.pubkey.clone(),
        created_at: event.created_at,
        geohash: Geohash::parse(&event.tags[0][1])?,
    })
}

#[must_use]
pub fn subscription_filter(geohash: &Geohash, since: u64, limit: usize) -> Value {
    json!({
        "kinds": [CHAT_KIND, PRESENCE_KIND],
        "#g": [geohash.as_str()],
        "since": since,
        "limit": limit,
    })
}

/// The committed NIP-13 target counts only when the event ID actually meets
/// it. Missing, malformed, duplicated, zero, or overclaimed work scores zero;
/// extra leading zeroes do not increase the committed score.
#[must_use]
pub fn validated_pow_difficulty(event_id: &str, tags: &[Tag]) -> u16 {
    let nonce_tags = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|field| field == "nonce"))
        .collect::<Vec<_>>();
    let [tag] = nonce_tags.as_slice() else {
        return 0;
    };
    if tag.len() != 3
        || tag[1].len() != 16
        || !tag[1]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return 0;
    }
    let Ok(committed) = tag[2].parse::<u16>() else {
        return 0;
    };
    if !(1..=256).contains(&committed) {
        return 0;
    }
    let Ok(bytes) = hex::decode(event_id) else {
        return 0;
    };
    if bytes.len() != 32 || leading_zero_bits(&bytes) < committed {
        0
    } else {
        committed
    }
}

#[must_use]
pub fn leading_zero_bits(bytes: &[u8]) -> u16 {
    let mut total = 0;
    for byte in bytes {
        if *byte == 0 {
            total += 8;
        } else {
            total += byte.leading_zeros() as u16;
            break;
        }
    }
    total
}

/// Deterministic entry point used by conformance tests. Production uses the
/// same function with the captured wall-clock budgets and a random nonce.
pub fn mine_nonce_tag(
    base_event: &UnsignedEvent,
    initial_target: u16,
    starting_nonce: u64,
    main_budget: Duration,
    fallback_budget: Duration,
) -> Result<Tag, GeoEventError> {
    let mut target = initial_target.min(256);
    let mut nonce = starting_nonce;
    let mut budget = main_budget;
    loop {
        let deadline = Instant::now() + budget;
        let mut attempts = 0_u64;
        loop {
            let nonce_tag = vec!["nonce".into(), format!("{nonce:016x}"), target.to_string()];
            let mut tags = base_event.tags.clone();
            tags.push(nonce_tag.clone());
            let candidate = UnsignedEvent::new(
                base_event.pubkey.clone(),
                base_event.created_at,
                base_event.kind,
                tags,
                base_event.content.clone(),
                &EventLimits {
                    max_tags: usize::MAX,
                    ..EventLimits::default()
                },
            )?;
            if leading_zero_bits(&candidate.id()?) >= target {
                return Ok(nonce_tag);
            }
            nonce = nonce.wrapping_add(1);
            attempts += 1;
            if attempts.is_multiple_of(POW_DEADLINE_CHECK_INTERVAL) && Instant::now() >= deadline {
                break;
            }
        }
        if target == 0 {
            return Err(GeoEventError::Mining);
        }
        target /= 2;
        budget = fallback_budget;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeoInboxReceive {
    Event(ParsedGeoEvent),
    Blocked {
        event_id: String,
        sender_pubkey: String,
    },
    Duplicate {
        event_id: String,
    },
}

pub struct GeoInbox {
    capacity: usize,
    ttl_seconds: u64,
    blocked: HashSet<String>,
    seen: HashSet<String>,
    seen_order: VecDeque<(u64, String)>,
}

impl GeoInbox {
    pub fn new(capacity: usize, ttl_seconds: u64) -> Result<Self, GeoEventError> {
        if capacity == 0 || ttl_seconds == 0 {
            return Err(GeoEventError::InvalidInboxBounds);
        }
        Ok(Self {
            capacity,
            ttl_seconds,
            blocked: HashSet::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        })
    }

    pub fn block_sender(&mut self, sender_pubkey: &str) -> Result<(), GeoEventError> {
        validate_pubkey(sender_pubkey)?;
        self.blocked.insert(sender_pubkey.to_owned());
        Ok(())
    }

    pub fn receive(
        &mut self,
        event: &SignedEvent,
        now: u64,
        limits: &EventLimits,
    ) -> Result<GeoInboxReceive, GeoEventError> {
        let parsed = parse_geo_event(event, now, limits)?;
        if !self.remember(&event.id, now) {
            return Ok(GeoInboxReceive::Duplicate {
                event_id: event.id.clone(),
            });
        }
        if self.blocked.contains(&event.pubkey) {
            Ok(GeoInboxReceive::Blocked {
                event_id: event.id.clone(),
                sender_pubkey: event.pubkey.clone(),
            })
        } else {
            Ok(GeoInboxReceive::Event(parsed))
        }
    }

    fn remember(&mut self, event_id: &str, now: u64) -> bool {
        while let Some((seen_at, oldest)) = self.seen_order.front() {
            if now.saturating_sub(*seen_at) < self.ttl_seconds {
                break;
            }
            self.seen.remove(oldest);
            self.seen_order.pop_front();
        }
        if self.seen.contains(event_id) {
            return false;
        }
        while self.seen.len() >= self.capacity {
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

fn sign_chat(
    input: &ChatInput<'_>,
    tags: Vec<Tag>,
    limits: &EventLimits,
) -> Result<SignedEvent, GeoEventError> {
    Ok(UnsignedEvent::new(
        hex::encode(xonly_public_key(input.secret_key)?),
        input.created_at,
        CHAT_KIND,
        tags,
        input.content.to_owned(),
        limits,
    )?
    .sign_with_aux(input.secret_key, input.signature_aux, limits)?)
}

fn chat_tags(input: &ChatInput<'_>) -> Result<Vec<Tag>, GeoEventError> {
    let mut tags = vec![vec!["g".into(), input.geohash.as_str().into()]];
    if let Some(nickname) = input.nickname {
        let nickname = nickname.trim();
        if nickname.is_empty() {
            return Err(GeoEventError::InvalidNickname);
        }
        tags.push(vec!["n".into(), nickname.into()]);
    }
    if input.teleported {
        tags.push(vec!["t".into(), "teleport".into()]);
    }
    Ok(tags)
}

fn validate_pubkey(value: &str) -> Result<(), GeoEventError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(GeoEventError::InvalidPublicKey)
    }
}

#[derive(Debug)]
pub enum GeoEventError {
    Event(EventError),
    Geohash(GeohashError),
    WrongKind(u32),
    MissingGeohash,
    InvalidNickname,
    DuplicateTag(&'static str),
    UnsupportedTag,
    PresenceContent,
    PresenceTags,
    InvalidPublicKey,
    InvalidInboxBounds,
    Mining,
}

impl fmt::Display for GeoEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid geohash Nostr event: {error}"),
            Self::Geohash(error) => write!(formatter, "invalid geohash tag: {error}"),
            Self::WrongKind(kind) => write!(formatter, "unsupported geohash event kind {kind}"),
            Self::MissingGeohash => formatter.write_str("geohash event is missing its g tag"),
            Self::InvalidNickname => formatter.write_str("geohash nickname is empty"),
            Self::DuplicateTag(tag) => write!(formatter, "invalid or duplicate {tag} tag"),
            Self::UnsupportedTag => formatter.write_str("unsupported geohash event tag"),
            Self::PresenceContent => formatter.write_str("presence content must be empty"),
            Self::PresenceTags => formatter.write_str("presence must contain exactly one g tag"),
            Self::InvalidPublicKey => formatter.write_str("invalid x-only sender public key"),
            Self::InvalidInboxBounds => {
                formatter.write_str("geohash inbox bounds must be non-zero")
            }
            Self::Mining => formatter.write_str("bounded NIP-13 mining failed"),
        }
    }
}

impl Error for GeoEventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::Geohash(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EventError> for GeoEventError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

impl From<GeohashError> for GeoEventError {
    fn from(error: GeohashError) -> Self {
        Self::Geohash(error)
    }
}
