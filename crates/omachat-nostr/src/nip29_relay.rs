//! Relay-key-bound NIP-29 room identity and reconnect-safe room subscriptions.
//!
//! A room is identified by the relay's verified public key plus the group ID,
//! never by the relay URL alone. Identity comes from the relay's NIP-11
//! document; where it is missing the binding fails closed. Once a URL has
//! been bound to a key, a different key presented at that URL is surfaced as
//! a possible relay replacement or fork with the evidence needed to explain
//! it, and is never silently adopted.
//!
//! Subscriptions are one logical NIP-29 subscription per relay pool whose
//! filters cover the configured rooms. Replacement goes through the pool's
//! serialized subscribe path, which replays on reconnect; a rejected
//! replacement is rolled back to the last filters every relay accepted.

use crate::{nip11::RelayInformation, pool::RelayPool, relay::RelayError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    future::Future,
};
use url::Url;

pub const ROOM_SUBSCRIPTION_ID: &str = "omachat-nip29-rooms";

/// User and moderation kinds carried with an `h` tag.
pub const ROOM_EVENT_KINDS: [u32; 11] = [
    9, 9000, 9001, 9002, 9005, 9007, 9008, 9009, 9010, 9021, 9022,
];

/// Relay-authored addressable state kinds carried with a `d` tag.
pub const ROOM_STATE_KINDS: [u32; 5] = [39000, 39001, 39002, 39003, 39005];

/// Relay-key-bound room coordinate.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RoomCoordinate {
    relay_pubkey: String,
    group_id: String,
}

impl RoomCoordinate {
    pub fn new(relay_pubkey: String, group_id: String) -> Result<Self, RoomIdentityError> {
        if !is_lowercase_hex(&relay_pubkey, 64) {
            return Err(RoomIdentityError::InvalidRelayIdentity);
        }
        if group_id.is_empty() {
            return Err(RoomIdentityError::EmptyGroupId);
        }
        Ok(Self {
            relay_pubkey,
            group_id,
        })
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }
}

/// One relay URL bound to the public key its NIP-11 document declared.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayIdentityBinding {
    url: String,
    relay_pubkey: String,
    first_verified_at: u64,
    last_verified_at: u64,
    software: Option<String>,
    version: Option<String>,
}

impl RelayIdentityBinding {
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub const fn first_verified_at(&self) -> u64 {
        self.first_verified_at
    }

    #[must_use]
    pub const fn last_verified_at(&self) -> u64 {
        self.last_verified_at
    }

    #[must_use]
    pub fn software(&self) -> Option<&str> {
        self.software.as_deref()
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayIdentityObservation {
    /// First key seen for this URL; the binding is now trusted.
    Bound,
    /// The presented key matches the trusted binding.
    Confirmed,
}

/// Trusted relay-URL-to-key bindings for room identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedRelayIdentities {
    bindings: BTreeMap<String, RelayIdentityBinding>,
}

impl TrustedRelayIdentities {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind or confirm a relay URL against its presented NIP-11 identity.
    ///
    /// A document without a key cannot bind. A key that differs from the
    /// trusted one is a conflict carrying both keys and the trust history,
    /// and the trusted binding is left untouched.
    pub fn observe(
        &mut self,
        relay_url: &str,
        information: &RelayInformation,
        now: u64,
    ) -> Result<RelayIdentityObservation, RoomIdentityError> {
        let url = normalize_relay_url(relay_url)?;
        let presented = information
            .pubkey()
            .ok_or_else(|| RoomIdentityError::MissingRelayIdentity { url: url.clone() })?;
        if !is_lowercase_hex(presented, 64) {
            return Err(RoomIdentityError::InvalidRelayIdentity);
        }
        match self.bindings.get_mut(&url) {
            None => {
                self.bindings.insert(
                    url.clone(),
                    RelayIdentityBinding {
                        url,
                        relay_pubkey: presented.to_owned(),
                        first_verified_at: now,
                        last_verified_at: now,
                        software: information.software().map(str::to_owned),
                        version: information.version().map(str::to_owned),
                    },
                );
                Ok(RelayIdentityObservation::Bound)
            }
            Some(binding) if binding.relay_pubkey == presented => {
                binding.last_verified_at = binding.last_verified_at.max(now);
                binding.software = information.software().map(str::to_owned);
                binding.version = information.version().map(str::to_owned);
                Ok(RelayIdentityObservation::Confirmed)
            }
            Some(binding) => Err(RoomIdentityError::IdentityConflict(Box::new(
                RelayIdentityConflict {
                    url: binding.url.clone(),
                    trusted_pubkey: binding.relay_pubkey.clone(),
                    presented_pubkey: presented.to_owned(),
                    first_verified_at: binding.first_verified_at,
                    last_verified_at: binding.last_verified_at,
                    observed_at: now,
                    trusted_software: binding.software.clone(),
                    presented_software: information.software().map(str::to_owned),
                    presented_version: information.version().map(str::to_owned),
                },
            ))),
        }
    }

    #[must_use]
    pub fn binding(&self, relay_url: &str) -> Option<&RelayIdentityBinding> {
        let url = normalize_relay_url(relay_url).ok()?;
        self.bindings.get(&url)
    }

    /// The trusted key for a URL, failing closed when none is bound.
    pub fn relay_pubkey(&self, relay_url: &str) -> Result<&str, RoomIdentityError> {
        let url = normalize_relay_url(relay_url)?;
        self.bindings
            .get(&url)
            .map(|binding| binding.relay_pubkey.as_str())
            .ok_or(RoomIdentityError::RelayNotBound { url })
    }

    /// The relay-key-bound coordinate for a group reached through a URL.
    pub fn coordinate(
        &self,
        relay_url: &str,
        group_id: &str,
    ) -> Result<RoomCoordinate, RoomIdentityError> {
        RoomCoordinate::new(
            self.relay_pubkey(relay_url)?.to_owned(),
            group_id.to_owned(),
        )
    }

    /// Every URL currently bound to one relay key, in lexical order.
    #[must_use]
    pub fn urls_for(&self, relay_pubkey: &str) -> Vec<&str> {
        self.bindings
            .values()
            .filter(|binding| binding.relay_pubkey == relay_pubkey)
            .map(|binding| binding.url.as_str())
            .collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Every binding in URL order, for persistence.
    pub fn bindings(&self) -> impl Iterator<Item = &RelayIdentityBinding> {
        self.bindings.values()
    }

    /// Rebuild trusted bindings, refusing malformed or duplicate entries.
    pub fn restore(bindings: Vec<RelayIdentityBinding>) -> Result<Self, RoomIdentityError> {
        let mut trusted = Self::new();
        for binding in bindings {
            if normalize_relay_url(&binding.url)? != binding.url
                || !is_lowercase_hex(&binding.relay_pubkey, 64)
                || binding.last_verified_at < binding.first_verified_at
            {
                return Err(RoomIdentityError::InvalidRelayIdentity);
            }
            if trusted
                .bindings
                .insert(binding.url.clone(), binding)
                .is_some()
            {
                return Err(RoomIdentityError::InvalidRelayIdentity);
            }
        }
        Ok(trusted)
    }
}

/// Evidence that a relay URL presented a key other than its trusted one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayIdentityConflict {
    pub url: String,
    pub trusted_pubkey: String,
    pub presented_pubkey: String,
    pub first_verified_at: u64,
    pub last_verified_at: u64,
    pub observed_at: u64,
    pub trusted_software: Option<String>,
    pub presented_software: Option<String>,
    pub presented_version: Option<String>,
}

impl fmt::Display for RelayIdentityConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "relay {} presented key {} at {} but key {} was trusted there from {} through {}; \
             treat this as a possible relay replacement or fork, not the same room authority",
            self.url,
            self.presented_pubkey,
            self.observed_at,
            self.trusted_pubkey,
            self.first_verified_at,
            self.last_verified_at
        )
    }
}

/// Canonical relay URL: `ws`/`wss` only, lowercase host, no fragment.
pub fn normalize_relay_url(relay_url: &str) -> Result<String, RoomIdentityError> {
    let mut url = Url::parse(relay_url).map_err(|_| RoomIdentityError::InvalidRelayUrl)?;
    if !matches!(url.scheme(), "ws" | "wss") || url.host_str().is_none() {
        return Err(RoomIdentityError::InvalidRelayUrl);
    }
    url.set_fragment(None);
    if url.path() == "/" {
        url.set_path("");
    }
    let mut text = url.to_string();
    if text.ends_with('/') {
        text.pop();
    }
    Ok(text)
}

/// Filters covering the configured rooms on one verified relay.
///
/// Relay-authored state kinds are restricted to the verified relay key, so a
/// forged `39xxx` event from another author is never requested.
#[must_use]
pub fn room_subscription_filters(
    relay_pubkey: &str,
    group_ids: &BTreeSet<String>,
    since: Option<u64>,
) -> Vec<Value> {
    if group_ids.is_empty() {
        return Vec::new();
    }
    let groups = group_ids.iter().cloned().collect::<Vec<_>>();
    let mut events = json!({
        "kinds": ROOM_EVENT_KINDS,
        "#h": groups,
    });
    if let Some(since) = since {
        events["since"] = json!(since);
    }
    let state = json!({
        "kinds": ROOM_STATE_KINDS,
        "authors": [relay_pubkey],
        "#d": groups,
    });
    vec![events, state]
}

/// Where room subscriptions are sent. [`RelayPool`] is the production sink.
pub trait RoomSubscriptionSink {
    fn subscribe(
        &mut self,
        subscription_id: String,
        filters: Vec<Value>,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send;

    fn close_subscription(
        &mut self,
        subscription_id: String,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send;
}

impl RoomSubscriptionSink for RelayPool {
    fn subscribe(
        &mut self,
        subscription_id: String,
        filters: Vec<Value>,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send {
        Self::subscribe(self, subscription_id, filters)
    }

    fn close_subscription(
        &mut self,
        subscription_id: String,
    ) -> impl Future<Output = Vec<Result<(), RelayError>>> + Send {
        Self::close_subscription(self, subscription_id)
    }
}

/// The configured room set for one verified relay and its applied filters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoomSubscriptions {
    relay_pubkey: String,
    subscription_id: String,
    since: Option<u64>,
    desired: BTreeSet<String>,
    applied: BTreeSet<String>,
}

impl RoomSubscriptions {
    pub fn new(relay_pubkey: String, since: Option<u64>) -> Result<Self, RoomIdentityError> {
        if !is_lowercase_hex(&relay_pubkey, 64) {
            return Err(RoomIdentityError::InvalidRelayIdentity);
        }
        Ok(Self {
            relay_pubkey,
            subscription_id: ROOM_SUBSCRIPTION_ID.to_owned(),
            since,
            desired: BTreeSet::new(),
            applied: BTreeSet::new(),
        })
    }

    /// Add a room to the desired set. Returns whether the set changed.
    pub fn join(&mut self, group_id: &str) -> Result<bool, RoomIdentityError> {
        if group_id.is_empty() {
            return Err(RoomIdentityError::EmptyGroupId);
        }
        Ok(self.desired.insert(group_id.to_owned()))
    }

    /// Remove a room from the desired set. Returns whether the set changed.
    pub fn leave(&mut self, group_id: &str) -> bool {
        self.desired.remove(group_id)
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    #[must_use]
    pub fn desired_rooms(&self) -> &BTreeSet<String> {
        &self.desired
    }

    /// Rooms whose filters every relay last accepted.
    #[must_use]
    pub fn applied_rooms(&self) -> &BTreeSet<String> {
        &self.applied
    }

    #[must_use]
    pub fn desired_filters(&self) -> Vec<Value> {
        room_subscription_filters(&self.relay_pubkey, &self.desired, self.since)
    }

    /// Make the sink match the desired room set.
    ///
    /// If any relay rejects the replacement, the desired set is reverted to
    /// the applied set and the previously accepted filters are re-issued so
    /// the pool never keeps a half-applied room set.
    pub async fn sync<S: RoomSubscriptionSink>(
        &mut self,
        sink: &mut S,
    ) -> Result<RoomSubscriptionSync, RoomSubscriptionError> {
        if self.desired == self.applied {
            return Ok(RoomSubscriptionSync::Unchanged);
        }
        let results = if self.desired.is_empty() {
            sink.close_subscription(self.subscription_id.clone()).await
        } else {
            sink.subscribe(self.subscription_id.clone(), self.desired_filters())
                .await
        };
        let rejections = collect_rejections(&results);
        if rejections.is_empty() {
            self.applied = self.desired.clone();
            return Ok(if self.applied.is_empty() {
                RoomSubscriptionSync::Closed
            } else {
                RoomSubscriptionSync::Replaced {
                    rooms: self.applied.len(),
                }
            });
        }

        self.desired = self.applied.clone();
        let restore = if self.applied.is_empty() {
            sink.close_subscription(self.subscription_id.clone()).await
        } else {
            sink.subscribe(self.subscription_id.clone(), self.desired_filters())
                .await
        };
        let restore_failures = collect_rejections(&restore);
        if restore_failures.is_empty() {
            Err(RoomSubscriptionError::Rejected { rejections })
        } else {
            Err(RoomSubscriptionError::RollbackFailed {
                rejections,
                restore_failures,
            })
        }
    }
}

fn collect_rejections(results: &[Result<(), RelayError>]) -> Vec<(usize, RelayError)> {
    results
        .iter()
        .enumerate()
        .filter_map(|(relay_index, result)| {
            result
                .as_ref()
                .err()
                .map(|error| (relay_index, error.clone()))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoomSubscriptionSync {
    Unchanged,
    Replaced { rooms: usize },
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoomSubscriptionError {
    /// The replacement was rejected and the previous filters were restored.
    Rejected {
        rejections: Vec<(usize, RelayError)>,
    },
    /// The replacement was rejected and restoring the previous filters also
    /// failed on some relay; the pool will replay the stored filters on the
    /// next reconnect.
    RollbackFailed {
        rejections: Vec<(usize, RelayError)>,
        restore_failures: Vec<(usize, RelayError)>,
    },
}

impl fmt::Display for RoomSubscriptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { rejections } => write!(
                formatter,
                "room subscription replacement rejected by {} relay(s); previous filters restored",
                rejections.len()
            ),
            Self::RollbackFailed {
                rejections,
                restore_failures,
            } => write!(
                formatter,
                "room subscription replacement rejected by {} relay(s) and rollback failed on {}",
                rejections.len(),
                restore_failures.len()
            ),
        }
    }
}

impl Error for RoomSubscriptionError {}

fn is_lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoomIdentityError {
    InvalidRelayUrl,
    InvalidRelayIdentity,
    EmptyGroupId,
    MissingRelayIdentity { url: String },
    RelayNotBound { url: String },
    IdentityConflict(Box<RelayIdentityConflict>),
}

impl fmt::Display for RoomIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayUrl => formatter.write_str("relay URL must be ws:// or wss://"),
            Self::InvalidRelayIdentity => {
                formatter.write_str("relay identity must be a lowercase 32-byte public key")
            }
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::MissingRelayIdentity { url } => write!(
                formatter,
                "relay {url} declares no public key in its NIP-11 document; rooms cannot bind"
            ),
            Self::RelayNotBound { url } => {
                write!(formatter, "relay {url} has no verified identity binding")
            }
            Self::IdentityConflict(conflict) => conflict.fmt(formatter),
        }
    }
}

impl Error for RoomIdentityError {}
