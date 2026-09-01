//! Strict NIP-29 kind `9005` delete-event requests and accepted deletion state.
//!
//! Three things are kept apart on purpose:
//!
//! 1. A [`GroupDeleteRequest`] proves only that its signer asked for the
//!    listed events to be removed from one room.
//! 2. An [`AcceptedGroupDeletion`] records that the verified authoritative
//!    relay path accepted the action under its room policy. Target authorship
//!    and broad administrator labels are not capability evidence.
//! 3. [`GroupDeletionState`] reduces accepted deletions into deterministic,
//!    order-independent state. Deleted events are marked, not erased; the
//!    request, its author, targets, timestamp, relay identity, and group stay
//!    on record as provenance.

use crate::event::{EventError, EventLimits, SignedEvent, Tag, UnsignedEvent};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt};

pub const DELETE_EVENT_KIND: u32 = 9005;

/// A signed delete-event request whose room authorization is not implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupDeleteRequest {
    event: SignedEvent,
    group_id: String,
    targets: Vec<String>,
    previous: Vec<String>,
}

impl GroupDeleteRequest {
    /// Authenticate a request without claiming its author may delete anything.
    pub fn verify(
        event: SignedEvent,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, GroupDeleteError> {
        event.verify(now, limits).map_err(GroupDeleteError::Event)?;
        if event.kind != DELETE_EVENT_KIND {
            return Err(GroupDeleteError::UnsupportedKind(event.kind));
        }
        let group_id =
            unique_pair_tag(&event.tags, "h")?.ok_or(GroupDeleteError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(GroupDeleteError::EmptyGroupId);
        }
        let targets = target_references(&event.tags)?;
        if targets.contains(&event.id) {
            return Err(GroupDeleteError::SelfReferentialTarget);
        }
        let previous = timeline_references(&event.tags)?;
        Ok(Self {
            event,
            group_id,
            targets,
            previous,
        })
    }

    #[must_use]
    pub fn event(&self) -> &SignedEvent {
        &self.event
    }

    /// The principal that asked for deletion, taken from its own signature.
    #[must_use]
    pub fn author(&self) -> &str {
        &self.event.pubkey
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    /// Event IDs named for deletion, in signed order and without duplicates.
    #[must_use]
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Optional deletion reason carried in the event content.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        if self.event.content.is_empty() {
            None
        } else {
            Some(&self.event.content)
        }
    }

    #[must_use]
    pub fn previous(&self) -> &[String] {
        &self.previous
    }
}

/// Build a NIP-29 kind `9005` delete request without changing its author.
pub fn delete_event_request(
    pubkey: String,
    created_at: u64,
    group_id: &str,
    targets: &[String],
    reason: String,
    previous: &[String],
    limits: &EventLimits,
) -> Result<UnsignedEvent, GroupDeleteError> {
    if group_id.is_empty() {
        return Err(GroupDeleteError::EmptyGroupId);
    }
    if group_id.len() > limits.max_tag_field_bytes {
        return Err(GroupDeleteError::TagFieldTooLarge {
            bytes: group_id.len(),
            maximum: limits.max_tag_field_bytes,
        });
    }
    if targets.is_empty() {
        return Err(GroupDeleteError::MissingTarget);
    }

    let mut tags = Vec::with_capacity(targets.len() + 2);
    tags.push(vec!["h".to_owned(), group_id.to_owned()]);
    for (index, target) in targets.iter().enumerate() {
        validate_event_id(target)?;
        if targets[..index].contains(target) {
            return Err(GroupDeleteError::DuplicateTarget);
        }
        tags.push(vec!["e".to_owned(), target.clone()]);
    }
    if !previous.is_empty() {
        let mut tag = Vec::with_capacity(previous.len() + 1);
        tag.push("previous".to_owned());
        for reference in previous {
            validate_timeline_reference(reference)?;
            tag.push(reference.clone());
        }
        tags.push(tag);
    }

    UnsignedEvent::new(pubkey, created_at, DELETE_EVENT_KIND, tags, reason, limits)
        .map_err(GroupDeleteError::Event)
}

/// Why an accepted deletion was authorized under the room's policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeletionAuthority {
    /// The verified authoritative relay path accepted and replayed the action.
    AuthoritativeRelay,
}

/// A delete request paired with explicit evidence that it is authorized.
///
/// This is the only input the deletion reducer accepts. Constructing one
/// requires evidence beyond the request itself, so a merely valid signed
/// request can never become accepted state on its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedGroupDeletion {
    request: GroupDeleteRequest,
    relay_pubkey: String,
    authority: DeletionAuthority,
}

impl AcceptedGroupDeletion {
    /// Record acceptance by the room's verified authoritative relay path.
    ///
    /// Callers must use the relay identity bound to the transport that replayed
    /// this request. The request signature remains the only author identity.
    pub fn from_authoritative_relay(
        request: GroupDeleteRequest,
        source_relay_pubkey: &str,
    ) -> Result<Self, DeletionAuthorizationError> {
        validate_relay_pubkey(source_relay_pubkey)?;
        Ok(Self {
            request,
            relay_pubkey: source_relay_pubkey.to_owned(),
            authority: DeletionAuthority::AuthoritativeRelay,
        })
    }

    #[must_use]
    pub fn request(&self) -> &GroupDeleteRequest {
        &self.request
    }

    /// The relay whose room policy this deletion was accepted under.
    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn authority(&self) -> &DeletionAuthority {
        &self.authority
    }
}

/// Accepted deletions for one group on one authoritative relay.
///
/// Deletion is monotone: once an event ID is recorded as deleted it stays
/// deleted. When several accepted requests name the same target, the record
/// kept is the earliest request by `created_at`, tie-broken by lowest event
/// ID, so the reduced state does not depend on arrival order. The same
/// request delivered through several relay paths reduces once because it
/// carries one Nostr event ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupDeletionState {
    relay_pubkey: String,
    group_id: String,
    records: BTreeMap<String, DeletionRecord>,
}

impl GroupDeletionState {
    pub fn new(relay_pubkey: String, group_id: String) -> Result<Self, DeletionStateError> {
        if validate_event_id(&relay_pubkey).is_err() {
            return Err(DeletionStateError::InvalidRelayPublicKey);
        }
        if group_id.is_empty() {
            return Err(DeletionStateError::EmptyGroupId);
        }
        Ok(Self {
            relay_pubkey,
            group_id,
            records: BTreeMap::new(),
        })
    }

    /// Reduce one accepted deletion into this group's state.
    ///
    /// The relay identity bound into the accepted deletion must match this
    /// state's relay; another relay's acceptance is not this room's policy.
    pub fn apply_accepted(
        &mut self,
        accepted: &AcceptedGroupDeletion,
    ) -> Result<DeletionApplyResult, DeletionStateError> {
        if accepted.relay_pubkey() != self.relay_pubkey {
            return Err(DeletionStateError::RelayMismatch);
        }
        let request = accepted.request();
        if request.group_id() != self.group_id {
            return Err(DeletionStateError::GroupMismatch);
        }

        let event = request.event();
        let mut newly_deleted = 0;
        let mut already_deleted = 0;
        for target in request.targets() {
            match self.records.get(target) {
                Some(current) if current.source_event_id == event.id => already_deleted += 1,
                Some(current)
                    if !is_earlier(
                        event.created_at,
                        &event.id,
                        current.created_at,
                        &current.source_event_id,
                    ) =>
                {
                    already_deleted += 1;
                }
                Some(_) => {
                    self.insert(accepted, target.clone());
                    already_deleted += 1;
                }
                None => {
                    self.insert(accepted, target.clone());
                    newly_deleted += 1;
                }
            }
        }
        Ok(DeletionApplyResult {
            newly_deleted,
            already_deleted,
        })
    }

    fn insert(&mut self, accepted: &AcceptedGroupDeletion, target: String) {
        let event = accepted.request().event();
        self.records.insert(
            target.clone(),
            DeletionRecord {
                event_id: target,
                requester_pubkey: event.pubkey.clone(),
                source_event_id: event.id.clone(),
                source_event: event.clone(),
                created_at: event.created_at,
                authority: accepted.authority().clone(),
            },
        );
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn record(&self, event_id: &str) -> Option<&DeletionRecord> {
        self.records.get(event_id)
    }

    #[must_use]
    pub fn is_deleted(&self, event_id: &str) -> bool {
        self.records.contains_key(event_id)
    }

    /// Deleted event IDs in lexical order.
    pub fn deleted_event_ids(&self) -> impl Iterator<Item = &str> {
        self.records.keys().map(String::as_str)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Persisted form: the deletion records, which are the evidence.
    #[must_use]
    pub fn snapshot(&self) -> GroupDeletionSnapshot {
        GroupDeletionSnapshot {
            relay_pubkey: self.relay_pubkey.clone(),
            group_id: self.group_id.clone(),
            records: self.records.values().cloned().collect(),
        }
    }

    /// Rebuild state from a snapshot, refusing malformed or duplicate records.
    pub fn restore(
        snapshot: GroupDeletionSnapshot,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, DeletionStateError> {
        let mut state = Self::new(snapshot.relay_pubkey, snapshot.group_id)?;
        for record in snapshot.records {
            let request = GroupDeleteRequest::verify(record.source_event.clone(), now, limits)
                .map_err(|_| DeletionStateError::InvalidRecord)?;
            if validate_event_id(&record.event_id).is_err()
                || validate_event_id(&record.requester_pubkey).is_err()
                || validate_event_id(&record.source_event_id).is_err()
                || record.event_id == record.source_event_id
                || request.group_id() != state.group_id
                || request.author() != record.requester_pubkey
                || request.event().id != record.source_event_id
                || request.event().created_at != record.created_at
                || !request.targets().contains(&record.event_id)
                || record.authority != DeletionAuthority::AuthoritativeRelay
            {
                return Err(DeletionStateError::InvalidRecord);
            }
            if state
                .records
                .insert(record.event_id.clone(), record)
                .is_some()
            {
                return Err(DeletionStateError::InvalidRecord);
            }
        }
        Ok(state)
    }
}

/// Serializable deletion state for one relay group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupDeletionSnapshot {
    relay_pubkey: String,
    group_id: String,
    records: Vec<DeletionRecord>,
}

impl GroupDeletionSnapshot {
    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn records(&self) -> &[DeletionRecord] {
        &self.records
    }
}

/// Provenance for one deleted event. The deleted event itself is untouched.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeletionRecord {
    event_id: String,
    requester_pubkey: String,
    source_event_id: String,
    source_event: SignedEvent,
    created_at: u64,
    authority: DeletionAuthority,
}

impl DeletionRecord {
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// The signer of the accepted request, not an asserted room role.
    #[must_use]
    pub fn requester_pubkey(&self) -> &str {
        &self.requester_pubkey
    }

    #[must_use]
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    #[must_use]
    pub fn source_event(&self) -> &SignedEvent {
        &self.source_event
    }

    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    #[must_use]
    pub fn authority(&self) -> &DeletionAuthority {
        &self.authority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionApplyResult {
    pub newly_deleted: usize,
    pub already_deleted: usize,
}

fn is_earlier(created_at: u64, id: &str, current_created_at: u64, current_id: &str) -> bool {
    created_at < current_created_at || (created_at == current_created_at && id < current_id)
}

fn target_references(tags: &[Tag]) -> Result<Vec<String>, GroupDeleteError> {
    let mut targets = Vec::new();
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "e"))
    {
        if tag.len() != 2 {
            return Err(GroupDeleteError::MalformedTag("e"));
        }
        validate_event_id(&tag[1])?;
        if targets.contains(&tag[1]) {
            return Err(GroupDeleteError::DuplicateTarget);
        }
        targets.push(tag[1].clone());
    }
    if targets.is_empty() {
        return Err(GroupDeleteError::MissingTarget);
    }
    Ok(targets)
}

fn unique_pair_tag(tags: &[Tag], name: &'static str) -> Result<Option<String>, GroupDeleteError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if value.is_some() {
            return Err(GroupDeleteError::DuplicateTag(name));
        }
        if tag.len() != 2 {
            return Err(GroupDeleteError::MalformedTag(name));
        }
        value = Some(tag[1].clone());
    }
    Ok(value)
}

fn timeline_references(tags: &[Tag]) -> Result<Vec<String>, GroupDeleteError> {
    let mut previous = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "previous"))
    {
        if previous.is_some() {
            return Err(GroupDeleteError::DuplicateTag("previous"));
        }
        let references = tag.iter().skip(1).cloned().collect::<Vec<_>>();
        for reference in &references {
            validate_timeline_reference(reference)?;
        }
        previous = Some(references);
    }
    Ok(previous.unwrap_or_default())
}

fn is_lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_event_id(value: &str) -> Result<(), GroupDeleteError> {
    if !is_lowercase_hex(value, 64) {
        return Err(GroupDeleteError::InvalidEventId);
    }
    Ok(())
}

fn validate_relay_pubkey(value: &str) -> Result<(), DeletionAuthorizationError> {
    if !is_lowercase_hex(value, 64) {
        return Err(DeletionAuthorizationError::InvalidRelayPublicKey);
    }
    Ok(())
}

fn validate_timeline_reference(reference: &str) -> Result<(), GroupDeleteError> {
    if !is_lowercase_hex(reference, 8) {
        return Err(GroupDeleteError::InvalidTimelineReference);
    }
    Ok(())
}

#[derive(Debug)]
pub enum GroupDeleteError {
    Event(EventError),
    UnsupportedKind(u32),
    MissingGroupId,
    EmptyGroupId,
    DuplicateTag(&'static str),
    MalformedTag(&'static str),
    MissingTarget,
    DuplicateTarget,
    SelfReferentialTarget,
    InvalidEventId,
    InvalidTimelineReference,
    TagFieldTooLarge { bytes: usize, maximum: usize },
}

impl fmt::Display for GroupDeleteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid NIP-29 delete request: {error}"),
            Self::UnsupportedKind(kind) => {
                write!(formatter, "unsupported NIP-29 delete kind {kind}")
            }
            Self::MissingGroupId => {
                formatter.write_str("NIP-29 delete request is missing its h tag")
            }
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::DuplicateTag(name) => write!(formatter, "duplicate NIP-29 {name} tag"),
            Self::MalformedTag(name) => write!(formatter, "malformed NIP-29 {name} tag"),
            Self::MissingTarget => {
                formatter.write_str("NIP-29 delete request must name at least one event")
            }
            Self::DuplicateTarget => formatter.write_str("duplicate NIP-29 delete target"),
            Self::SelfReferentialTarget => {
                formatter.write_str("NIP-29 delete request must not target itself")
            }
            Self::InvalidEventId => {
                formatter.write_str("NIP-29 delete target must be a lowercase 32-byte event ID")
            }
            Self::InvalidTimelineReference => formatter.write_str(
                "NIP-29 timeline reference must be the lowercase first 8 hex characters of an event ID",
            ),
            Self::TagFieldTooLarge { bytes, maximum } => write!(
                formatter,
                "NIP-29 tag field is {bytes} bytes but at most {maximum} are allowed"
            ),
        }
    }
}

impl Error for GroupDeleteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionAuthorizationError {
    InvalidRelayPublicKey,
}

impl fmt::Display for DeletionAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
        }
    }
}

impl Error for DeletionAuthorizationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionStateError {
    InvalidRelayPublicKey,
    EmptyGroupId,
    RelayMismatch,
    GroupMismatch,
    InvalidRecord,
}

impl fmt::Display for DeletionStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::RelayMismatch => {
                formatter.write_str("accepted deletion is bound to another relay authority")
            }
            Self::GroupMismatch => {
                formatter.write_str("accepted deletion belongs to another group")
            }
            Self::InvalidRecord => {
                formatter.write_str("persisted deletion record is malformed or duplicated")
            }
        }
    }
}

impl Error for DeletionStateError {}
