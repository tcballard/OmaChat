//! Strict NIP-29 group lifecycle: kinds `9007`, `9008`, and `9009`.
//!
//! # Lifecycle transitions
//!
//! Each group on one relay is `Unknown`, `Active`, or `Deleted`. Accepted
//! actions are folded in canonical `(created_at, event ID)` order:
//!
//! | State     | create-group `9007` | delete-group `9008` | create-invite `9009` |
//! |-----------|---------------------|---------------------|----------------------|
//! | Unknown   | becomes Active      | rejected            | rejected             |
//! | Active    | rejected (kept)     | becomes Deleted     | invite recorded      |
//! | Deleted   | rejected (terminal) | rejected            | rejected             |
//!
//! The first accepted creation is the creation of record; a later creation
//! for the same ID is a recorded rejection, not a conflict. Deletion is
//! terminal in this implementation: recreation after an accepted deletion is
//! refused until an explicit policy says otherwise. Nothing is erased: the
//! creation, the deletion, and every invite stay on record as provenance.
//!
//! # Standards gaps
//!
//! NIP-29 lists these kinds with only the shared `h` scope tag and, for
//! `9009`, an optional `code`; it does not define recreation after deletion,
//! invitation expiry, transfer, or usage counts. None of those are invented
//! here. An invitation is a relay-scoped code record, never membership; the
//! relay decides what a `9021` join request carrying that code earns.
//! Host-qualified group IDs (`<host>'<id>`) are refused because room identity
//! here is bound to the relay key, not to a hostname inside the ID.

use crate::{
    event::{EventError, EventLimits, SignedEvent, Tag, UnsignedEvent},
    nip29::{GroupMetadata, GroupRoster, GroupRosterKind},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt};

pub const CREATE_GROUP_KIND: u32 = 9007;
pub const DELETE_GROUP_KIND: u32 = 9008;
pub const CREATE_INVITE_KIND: u32 = 9009;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleAction {
    CreateGroup,
    DeleteGroup,
    CreateInvite { code: String },
}

/// A signed lifecycle request whose room authorization is not implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupLifecycleRequest {
    event: SignedEvent,
    group_id: String,
    action: LifecycleAction,
    previous: Vec<String>,
}

impl GroupLifecycleRequest {
    /// Authenticate a request without claiming its author may perform it.
    pub fn verify(
        event: SignedEvent,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, LifecycleRequestError> {
        event
            .verify(now, limits)
            .map_err(LifecycleRequestError::Event)?;
        let group_id =
            unique_pair_tag(&event.tags, "h")?.ok_or(LifecycleRequestError::MissingGroupId)?;
        validate_group_id(&group_id)?;
        let code = unique_pair_tag(&event.tags, "code")?;
        let action = match event.kind {
            CREATE_GROUP_KIND | DELETE_GROUP_KIND => {
                if code.is_some() {
                    return Err(LifecycleRequestError::CodeOutsideInvite);
                }
                if event.kind == CREATE_GROUP_KIND {
                    LifecycleAction::CreateGroup
                } else {
                    LifecycleAction::DeleteGroup
                }
            }
            CREATE_INVITE_KIND => {
                let code = code.ok_or(LifecycleRequestError::MissingInviteCode)?;
                if code.is_empty() {
                    return Err(LifecycleRequestError::EmptyInviteCode);
                }
                LifecycleAction::CreateInvite { code }
            }
            kind => return Err(LifecycleRequestError::UnsupportedKind(kind)),
        };
        let previous = timeline_references(&event.tags)?;
        Ok(Self {
            event,
            group_id,
            action,
            previous,
        })
    }

    #[must_use]
    pub fn event(&self) -> &SignedEvent {
        &self.event
    }

    #[must_use]
    pub fn author(&self) -> &str {
        &self.event.pubkey
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn action(&self) -> &LifecycleAction {
        &self.action
    }

    #[must_use]
    pub fn previous(&self) -> &[String] {
        &self.previous
    }
}

/// Build a kind `9007` create-group request without changing its author.
pub fn create_group_request(
    pubkey: String,
    created_at: u64,
    group_id: &str,
    limits: &EventLimits,
) -> Result<UnsignedEvent, LifecycleRequestError> {
    build(
        pubkey,
        created_at,
        CREATE_GROUP_KIND,
        group_id,
        None,
        limits,
    )
}

/// Build a kind `9008` delete-group request without changing its author.
pub fn delete_group_request(
    pubkey: String,
    created_at: u64,
    group_id: &str,
    limits: &EventLimits,
) -> Result<UnsignedEvent, LifecycleRequestError> {
    build(
        pubkey,
        created_at,
        DELETE_GROUP_KIND,
        group_id,
        None,
        limits,
    )
}

/// Build a kind `9009` create-invite request carrying an explicit code.
pub fn create_invite_request(
    pubkey: String,
    created_at: u64,
    group_id: &str,
    code: &str,
    limits: &EventLimits,
) -> Result<UnsignedEvent, LifecycleRequestError> {
    if code.is_empty() {
        return Err(LifecycleRequestError::EmptyInviteCode);
    }
    build(
        pubkey,
        created_at,
        CREATE_INVITE_KIND,
        group_id,
        Some(code),
        limits,
    )
}

fn build(
    pubkey: String,
    created_at: u64,
    kind: u32,
    group_id: &str,
    code: Option<&str>,
    limits: &EventLimits,
) -> Result<UnsignedEvent, LifecycleRequestError> {
    validate_group_id(group_id)?;
    let mut tags = vec![vec!["h".to_owned(), group_id.to_owned()]];
    if let Some(code) = code {
        tags.push(vec!["code".to_owned(), code.to_owned()]);
    }
    UnsignedEvent::new(pubkey, created_at, kind, tags, String::new(), limits)
        .map_err(LifecycleRequestError::Event)
}

/// Why an accepted lifecycle action was authorized under the room's policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleAuthority {
    /// The relay published kind `39000` metadata for the created group.
    RelayMetadata,
    /// The relay-published administrator snapshot lists the requester.
    Administrator { roles: Vec<String> },
}

/// A lifecycle request paired with explicit evidence that it is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedLifecycleAction {
    request: GroupLifecycleRequest,
    relay_pubkey: String,
    authority: LifecycleAuthority,
}

impl AcceptedLifecycleAction {
    /// Accept a creation because the relay published the group's metadata.
    ///
    /// Only creation can be accepted this way: the relay's kind `39000` for
    /// the same group ID is the observable sign that it honoured the request.
    pub fn by_relay_metadata(
        request: GroupLifecycleRequest,
        metadata: &GroupMetadata,
        relay_pubkey: &str,
    ) -> Result<Self, LifecycleAuthorizationError> {
        validate_relay_pubkey(relay_pubkey)?;
        if request.action() != &LifecycleAction::CreateGroup {
            return Err(LifecycleAuthorizationError::MetadataOnlyProvesCreation);
        }
        if metadata.event().pubkey != relay_pubkey {
            return Err(LifecycleAuthorizationError::MetadataRelayMismatch);
        }
        if metadata.group_id() != request.group_id() {
            return Err(LifecycleAuthorizationError::MetadataGroupMismatch);
        }
        Ok(Self {
            request,
            relay_pubkey: relay_pubkey.to_owned(),
            authority: LifecycleAuthority::RelayMetadata,
        })
    }

    /// Accept because the relay's administrator snapshot lists the requester.
    pub fn by_administrator(
        request: GroupLifecycleRequest,
        admins: &GroupRoster,
        relay_pubkey: &str,
    ) -> Result<Self, LifecycleAuthorizationError> {
        validate_relay_pubkey(relay_pubkey)?;
        if admins.kind() != GroupRosterKind::Admins {
            return Err(LifecycleAuthorizationError::NotAdministratorRoster);
        }
        if admins.event().pubkey != relay_pubkey {
            return Err(LifecycleAuthorizationError::RosterRelayMismatch);
        }
        if admins.group_id() != request.group_id() {
            return Err(LifecycleAuthorizationError::RosterGroupMismatch);
        }
        let roles = admins
            .principals()
            .iter()
            .find(|principal| principal.pubkey() == request.author())
            .map(|principal| principal.roles().to_vec())
            .ok_or(LifecycleAuthorizationError::RequesterNotAdministrator)?;
        Ok(Self {
            request,
            relay_pubkey: relay_pubkey.to_owned(),
            authority: LifecycleAuthority::Administrator { roles },
        })
    }

    /// Rebuild an accepted action from sealed evidence. Crate-private so that
    /// only persistence restore, never a caller, can bypass the checks.
    pub(crate) fn from_evidence(
        request: GroupLifecycleRequest,
        relay_pubkey: String,
        authority: LifecycleAuthority,
    ) -> Self {
        Self {
            request,
            relay_pubkey,
            authority,
        }
    }

    #[must_use]
    pub fn request(&self) -> &GroupLifecycleRequest {
        &self.request
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn authority(&self) -> &LifecycleAuthority {
        &self.authority
    }
}

/// Lifecycle status and invitations for every group on one relay identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayLifecycleState {
    relay_pubkey: String,
    inputs: BTreeMap<InputKey, AcceptedLifecycleAction>,
    groups: BTreeMap<String, GroupLifecycle>,
    rejected: Vec<RejectedLifecycleAction>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InputKey {
    created_at: u64,
    event_id: String,
}

impl RelayLifecycleState {
    pub fn new(relay_pubkey: String) -> Result<Self, LifecycleStateError> {
        if !is_lowercase_hex(&relay_pubkey, 64) {
            return Err(LifecycleStateError::InvalidRelayPublicKey);
        }
        Ok(Self {
            relay_pubkey,
            inputs: BTreeMap::new(),
            groups: BTreeMap::new(),
            rejected: Vec::new(),
        })
    }

    /// Record one accepted action and re-fold every group's lifecycle.
    pub fn apply_accepted(
        &mut self,
        accepted: &AcceptedLifecycleAction,
    ) -> Result<LifecycleApplyResult, LifecycleStateError> {
        if accepted.relay_pubkey() != self.relay_pubkey {
            return Err(LifecycleStateError::RelayMismatch);
        }
        let event = accepted.request().event();
        let key = InputKey {
            created_at: event.created_at,
            event_id: event.id.clone(),
        };
        if self.inputs.contains_key(&key) {
            return Ok(LifecycleApplyResult::Duplicate);
        }
        self.inputs.insert(key, accepted.clone());
        self.refold();
        Ok(LifecycleApplyResult::Recorded)
    }

    fn refold(&mut self) {
        let mut groups: BTreeMap<String, GroupLifecycle> = BTreeMap::new();
        let mut rejected = Vec::new();
        for (key, accepted) in &self.inputs {
            let request = accepted.request();
            let provenance = LifecycleProvenance {
                source_event_id: key.event_id.clone(),
                created_at: key.created_at,
                author: request.author().to_owned(),
                authority: accepted.authority().clone(),
            };
            let group_id = request.group_id();
            let outcome = match (request.action(), groups.get_mut(group_id)) {
                (LifecycleAction::CreateGroup, None) => {
                    groups.insert(
                        group_id.to_owned(),
                        GroupLifecycle {
                            group_id: group_id.to_owned(),
                            status: GroupStatus::Active,
                            creation: provenance,
                            deletion: None,
                            invites: BTreeMap::new(),
                        },
                    );
                    Ok(())
                }
                (LifecycleAction::CreateGroup, Some(group)) => Err(match group.status {
                    GroupStatus::Active => LifecycleRejection::AlreadyActive,
                    GroupStatus::Deleted => LifecycleRejection::GroupDeleted,
                }),
                (LifecycleAction::DeleteGroup | LifecycleAction::CreateInvite { .. }, None) => {
                    Err(LifecycleRejection::GroupUnknown)
                }
                (_, Some(group)) if group.status == GroupStatus::Deleted => {
                    Err(LifecycleRejection::GroupDeleted)
                }
                (LifecycleAction::DeleteGroup, Some(group)) => {
                    group.status = GroupStatus::Deleted;
                    group.deletion = Some(provenance);
                    Ok(())
                }
                (LifecycleAction::CreateInvite { code }, Some(group)) => {
                    if group.invites.contains_key(code) {
                        Err(LifecycleRejection::DuplicateInviteCode)
                    } else {
                        group.invites.insert(
                            code.clone(),
                            InviteRecord {
                                code: code.clone(),
                                provenance,
                            },
                        );
                        Ok(())
                    }
                }
            };
            if let Err(reason) = outcome {
                rejected.push(RejectedLifecycleAction {
                    source_event_id: key.event_id.clone(),
                    group_id: group_id.to_owned(),
                    reason,
                });
            }
        }
        self.groups = groups;
        self.rejected = rejected;
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn group(&self, group_id: &str) -> Option<&GroupLifecycle> {
        self.groups.get(group_id)
    }

    /// `None` for a group this relay has never been seen to create.
    #[must_use]
    pub fn status(&self, group_id: &str) -> Option<GroupStatus> {
        self.groups.get(group_id).map(|group| group.status)
    }

    /// Fail closed unless the group is known and active.
    pub fn require_active(&self, group_id: &str) -> Result<(), LifecycleStateError> {
        match self.status(group_id) {
            Some(GroupStatus::Active) => Ok(()),
            Some(GroupStatus::Deleted) => Err(LifecycleStateError::GroupDeleted),
            None => Err(LifecycleStateError::GroupUnknown),
        }
    }

    /// Look up an invite code issued for one active group on this relay.
    #[must_use]
    pub fn invite(&self, group_id: &str, code: &str) -> Option<&InviteRecord> {
        self.groups
            .get(group_id)
            .filter(|group| group.status == GroupStatus::Active)
            .and_then(|group| group.invites.get(code))
    }

    /// Group IDs with lifecycle state, in lexical order.
    pub fn group_ids(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(String::as_str)
    }

    /// Accepted actions the canonical fold refused, with the reason.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedLifecycleAction] {
        &self.rejected
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Every accepted action in canonical fold order, for persistence.
    pub fn inputs(&self) -> impl Iterator<Item = &AcceptedLifecycleAction> {
        self.inputs.values()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupStatus {
    Active,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupLifecycle {
    group_id: String,
    status: GroupStatus,
    creation: LifecycleProvenance,
    deletion: Option<LifecycleProvenance>,
    invites: BTreeMap<String, InviteRecord>,
}

impl GroupLifecycle {
    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub const fn status(&self) -> GroupStatus {
        self.status
    }

    #[must_use]
    pub fn creation(&self) -> &LifecycleProvenance {
        &self.creation
    }

    #[must_use]
    pub fn deletion(&self) -> Option<&LifecycleProvenance> {
        self.deletion.as_ref()
    }

    /// Every invite ever accepted for this group, including after deletion.
    #[must_use]
    pub fn invites(&self) -> &BTreeMap<String, InviteRecord> {
        &self.invites
    }
}

/// An accepted invitation code. It is scope and provenance, not membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InviteRecord {
    code: String,
    provenance: LifecycleProvenance,
}

impl InviteRecord {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn provenance(&self) -> &LifecycleProvenance {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleProvenance {
    source_event_id: String,
    created_at: u64,
    author: String,
    authority: LifecycleAuthority,
}

impl LifecycleProvenance {
    #[must_use]
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The signer of the request, never an asserted role.
    #[must_use]
    pub fn author(&self) -> &str {
        &self.author
    }

    #[must_use]
    pub fn authority(&self) -> &LifecycleAuthority {
        &self.authority
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedLifecycleAction {
    pub source_event_id: String,
    pub group_id: String,
    pub reason: LifecycleRejection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRejection {
    AlreadyActive,
    GroupUnknown,
    GroupDeleted,
    DuplicateInviteCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleApplyResult {
    Recorded,
    Duplicate,
}

fn validate_group_id(group_id: &str) -> Result<(), LifecycleRequestError> {
    if group_id.is_empty() {
        return Err(LifecycleRequestError::EmptyGroupId);
    }
    if group_id.contains('\'') || group_id.contains("://") {
        return Err(LifecycleRequestError::HostQualifiedGroupId);
    }
    if group_id
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(LifecycleRequestError::InvalidGroupId);
    }
    Ok(())
}

fn validate_relay_pubkey(value: &str) -> Result<(), LifecycleAuthorizationError> {
    if !is_lowercase_hex(value, 64) {
        return Err(LifecycleAuthorizationError::InvalidRelayPublicKey);
    }
    Ok(())
}

fn unique_pair_tag(
    tags: &[Tag],
    name: &'static str,
) -> Result<Option<String>, LifecycleRequestError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if value.is_some() {
            return Err(LifecycleRequestError::DuplicateTag(name));
        }
        if tag.len() != 2 {
            return Err(LifecycleRequestError::MalformedTag(name));
        }
        value = Some(tag[1].clone());
    }
    Ok(value)
}

fn timeline_references(tags: &[Tag]) -> Result<Vec<String>, LifecycleRequestError> {
    let mut previous = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "previous"))
    {
        if previous.is_some() {
            return Err(LifecycleRequestError::DuplicateTag("previous"));
        }
        let references = tag.iter().skip(1).cloned().collect::<Vec<_>>();
        if references
            .iter()
            .any(|reference| !is_lowercase_hex(reference, 8))
        {
            return Err(LifecycleRequestError::InvalidTimelineReference);
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

#[derive(Debug)]
pub enum LifecycleRequestError {
    Event(EventError),
    UnsupportedKind(u32),
    MissingGroupId,
    EmptyGroupId,
    HostQualifiedGroupId,
    InvalidGroupId,
    DuplicateTag(&'static str),
    MalformedTag(&'static str),
    CodeOutsideInvite,
    MissingInviteCode,
    EmptyInviteCode,
    InvalidTimelineReference,
}

impl fmt::Display for LifecycleRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid NIP-29 lifecycle request: {error}"),
            Self::UnsupportedKind(kind) => {
                write!(formatter, "unsupported NIP-29 lifecycle kind {kind}")
            }
            Self::MissingGroupId => {
                formatter.write_str("NIP-29 lifecycle request is missing its h tag")
            }
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::HostQualifiedGroupId => {
                formatter.write_str("NIP-29 group ID must not embed a relay host")
            }
            Self::InvalidGroupId => {
                formatter.write_str("NIP-29 group ID must not contain whitespace or controls")
            }
            Self::DuplicateTag(name) => write!(formatter, "duplicate NIP-29 {name} tag"),
            Self::MalformedTag(name) => write!(formatter, "malformed NIP-29 {name} tag"),
            Self::CodeOutsideInvite => {
                formatter.write_str("NIP-29 invite code is only valid on a create-invite request")
            }
            Self::MissingInviteCode => {
                formatter.write_str("NIP-29 create-invite request must carry a code tag")
            }
            Self::EmptyInviteCode => formatter.write_str("NIP-29 invite code must not be empty"),
            Self::InvalidTimelineReference => formatter.write_str(
                "NIP-29 timeline reference must be the lowercase first 8 hex characters of an event ID",
            ),
        }
    }
}

impl Error for LifecycleRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAuthorizationError {
    InvalidRelayPublicKey,
    MetadataOnlyProvesCreation,
    MetadataRelayMismatch,
    MetadataGroupMismatch,
    NotAdministratorRoster,
    RosterRelayMismatch,
    RosterGroupMismatch,
    RequesterNotAdministrator,
}

impl fmt::Display for LifecycleAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
            Self::MetadataOnlyProvesCreation => {
                formatter.write_str("NIP-29 relay metadata only evidences group creation")
            }
            Self::MetadataRelayMismatch => {
                formatter.write_str("NIP-29 group metadata was signed by another relay")
            }
            Self::MetadataGroupMismatch => {
                formatter.write_str("NIP-29 group metadata belongs to another group")
            }
            Self::NotAdministratorRoster => {
                formatter.write_str("NIP-29 lifecycle authority requires the administrator roster")
            }
            Self::RosterRelayMismatch => {
                formatter.write_str("NIP-29 administrator roster was signed by another relay")
            }
            Self::RosterGroupMismatch => {
                formatter.write_str("NIP-29 administrator roster belongs to another group")
            }
            Self::RequesterNotAdministrator => {
                formatter.write_str("NIP-29 lifecycle requester is not a listed administrator")
            }
        }
    }
}

impl Error for LifecycleAuthorizationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleStateError {
    InvalidRelayPublicKey,
    RelayMismatch,
    GroupUnknown,
    GroupDeleted,
}

impl fmt::Display for LifecycleStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
            Self::RelayMismatch => {
                formatter.write_str("lifecycle action is bound to another relay authority")
            }
            Self::GroupUnknown => formatter.write_str("NIP-29 group is not known on this relay"),
            Self::GroupDeleted => formatter.write_str("NIP-29 group has been deleted"),
        }
    }
}

impl Error for LifecycleStateError {}
