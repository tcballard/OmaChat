//! Aggregate NIP-29 room state for one verified relay, with a snapshot form
//! that restores by re-verifying every persisted event.
//!
//! The snapshot carries accepted evidence, not derived conclusions, wherever
//! the reducer keeps evidence: metadata and lifecycle inputs are the signed
//! events plus the authority ground they were accepted under, and relay
//! snapshots (rosters, roles, pins) are the relay-signed events themselves.
//! Restore re-verifies each event against the relay key and re-folds, so a
//! persisted state can always be compared with a freshly reduced one.

use crate::{
    event::{EventLimits, SignedEvent},
    nip29::{GroupMembershipAction, GroupMetadata, GroupRoster, GroupRosterKind},
    nip29_delete::{
        AcceptedGroupDeletion, DeletionApplyResult, DeletionStateError, GroupDeletionSnapshot,
        GroupDeletionState,
    },
    nip29_lifecycle::{
        AcceptedLifecycleAction, GroupLifecycleRequest, LifecycleAuthority, LifecycleStateError,
        RelayLifecycleState,
    },
    nip29_metadata::{
        AcceptedMetadataEdit, GroupMetadataEdit, MetadataInput, MetadataStateError,
        RelayMetadataState,
    },
    nip29_pins::GroupPinList,
    nip29_relay::{RelayIdentityBinding, RoomIdentityError, TrustedRelayIdentities},
    nip29_roles::GroupRoles,
    nip29_state::{
        GroupMembershipSnapshot, GroupMembershipState, MembershipApplyResult, MembershipStateError,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt};

/// Schema version of [`RelayRoomStateSnapshot`]. Future versions are refused.
pub const ROOM_STATE_SCHEMA_VERSION: u16 = 1;

/// Everything OmaChat holds about rooms on one relay identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRoomState {
    relay_pubkey: String,
    identities: TrustedRelayIdentities,
    metadata: RelayMetadataState,
    lifecycle: RelayLifecycleState,
    groups: BTreeMap<String, GroupRoomState>,
}

impl RelayRoomState {
    pub fn new(relay_pubkey: String) -> Result<Self, RoomStateError> {
        if !is_lowercase_hex(&relay_pubkey, 64) {
            return Err(RoomStateError::InvalidRelayPublicKey);
        }
        Ok(Self {
            metadata: RelayMetadataState::new(relay_pubkey.clone())?,
            lifecycle: RelayLifecycleState::new(relay_pubkey.clone())?,
            relay_pubkey,
            identities: TrustedRelayIdentities::new(),
            groups: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn identities(&self) -> &TrustedRelayIdentities {
        &self.identities
    }

    pub fn identities_mut(&mut self) -> &mut TrustedRelayIdentities {
        &mut self.identities
    }

    #[must_use]
    pub fn metadata(&self) -> &RelayMetadataState {
        &self.metadata
    }

    pub fn metadata_mut(&mut self) -> &mut RelayMetadataState {
        &mut self.metadata
    }

    #[must_use]
    pub fn lifecycle(&self) -> &RelayLifecycleState {
        &self.lifecycle
    }

    pub fn lifecycle_mut(&mut self) -> &mut RelayLifecycleState {
        &mut self.lifecycle
    }

    #[must_use]
    pub fn group(&self, group_id: &str) -> Option<&GroupRoomState> {
        self.groups.get(group_id)
    }

    /// Group IDs with per-group state, in lexical order.
    pub fn group_ids(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(String::as_str)
    }

    fn group_mut(&mut self, group_id: &str) -> Result<&mut GroupRoomState, RoomStateError> {
        if group_id.is_empty() {
            return Err(RoomStateError::EmptyGroupId);
        }
        if !self.groups.contains_key(group_id) {
            let group = GroupRoomState::new(&self.relay_pubkey, group_id)?;
            self.groups.insert(group_id.to_owned(), group);
        }
        Ok(self.groups.get_mut(group_id).expect("group inserted above"))
    }

    /// Apply a membership action observed through this relay's path.
    pub fn apply_membership(
        &mut self,
        action: &GroupMembershipAction,
    ) -> Result<MembershipApplyResult, RoomStateError> {
        let relay = self.relay_pubkey.clone();
        let group = self.group_mut(action.group_id())?;
        Ok(group
            .membership
            .apply_from_authoritative_relay(action, &relay)?)
    }

    /// Reduce an accepted deletion bound to this relay.
    pub fn apply_deletion(
        &mut self,
        accepted: &AcceptedGroupDeletion,
    ) -> Result<DeletionApplyResult, RoomStateError> {
        if accepted.relay_pubkey() != self.relay_pubkey {
            return Err(RoomStateError::RelayMismatch);
        }
        let group = self.group_mut(accepted.request().group_id())?;
        Ok(group.deletions.apply_accepted(accepted)?)
    }

    /// Keep the newest relay-signed admin or member snapshot for its group.
    pub fn observe_roster(&mut self, roster: &GroupRoster) -> Result<bool, RoomStateError> {
        if roster.event().pubkey != self.relay_pubkey {
            return Err(RoomStateError::RelayMismatch);
        }
        let group = self.group_mut(roster.group_id())?;
        let slot = match roster.kind() {
            GroupRosterKind::Admins => &mut group.admins,
            GroupRosterKind::PublishedMembers => &mut group.members,
        };
        Ok(replace_if_newer(slot, roster, |roster| roster.event()))
    }

    /// Keep the newest relay-signed role definitions for their group.
    pub fn observe_roles(&mut self, roles: &GroupRoles) -> Result<bool, RoomStateError> {
        if roles.event().pubkey != self.relay_pubkey {
            return Err(RoomStateError::RelayMismatch);
        }
        let group = self.group_mut(roles.group_id())?;
        Ok(replace_if_newer(&mut group.roles, roles, |roles| {
            roles.event()
        }))
    }

    /// Keep the newest relay-signed pin list for its group.
    pub fn observe_pins(&mut self, pins: &GroupPinList) -> Result<bool, RoomStateError> {
        if pins.event().pubkey != self.relay_pubkey {
            return Err(RoomStateError::RelayMismatch);
        }
        let group = self.group_mut(pins.group_id())?;
        Ok(replace_if_newer(&mut group.pins, pins, |pins| pins.event()))
    }

    /// Serializable evidence for everything held here.
    #[must_use]
    pub fn snapshot(&self) -> RelayRoomStateSnapshot {
        RelayRoomStateSnapshot {
            schema_version: ROOM_STATE_SCHEMA_VERSION,
            relay_pubkey: self.relay_pubkey.clone(),
            identities: self.identities.bindings().cloned().collect(),
            metadata_inputs: self
                .metadata
                .inputs()
                .map(|input| match input {
                    MetadataInput::Snapshot(snapshot) => MetadataInputSnapshot {
                        event: snapshot.event().clone(),
                        roles: None,
                    },
                    MetadataInput::Edit(edit) => MetadataInputSnapshot {
                        event: edit.edit().event().clone(),
                        roles: Some(edit.roles().to_vec()),
                    },
                })
                .collect(),
            lifecycle_inputs: self
                .lifecycle
                .inputs()
                .map(|action| LifecycleInputSnapshot {
                    event: action.request().event().clone(),
                    authority: action.authority().clone(),
                })
                .collect(),
            groups: self
                .groups
                .values()
                .map(|group| GroupRoomStateSnapshot {
                    group_id: group.group_id.clone(),
                    membership: group.membership.snapshot(),
                    deletions: group.deletions.snapshot(),
                    admins: group.admins.as_ref().map(|roster| roster.event().clone()),
                    members: group.members.as_ref().map(|roster| roster.event().clone()),
                    roles: group.roles.as_ref().map(|roles| roles.event().clone()),
                    pins: group.pins.as_ref().map(|pins| pins.event().clone()),
                })
                .collect(),
        }
    }

    /// Rebuild state from a snapshot, re-verifying every event it carries.
    ///
    /// Fails closed on an unsupported schema version, a relay mismatch, any
    /// event that no longer verifies against the relay key, and any input
    /// that would not have been accepted by the live reducers.
    pub fn restore(
        snapshot: RelayRoomStateSnapshot,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, RoomStateError> {
        if snapshot.schema_version != ROOM_STATE_SCHEMA_VERSION {
            return Err(RoomStateError::UnsupportedSchemaVersion(
                snapshot.schema_version,
            ));
        }
        let mut state = Self::new(snapshot.relay_pubkey)?;
        let relay = state.relay_pubkey.clone();
        state.identities = TrustedRelayIdentities::restore(snapshot.identities)?;

        for input in snapshot.metadata_inputs {
            match input.roles {
                None => {
                    let metadata = GroupMetadata::verify(input.event, &relay, now, limits)
                        .map_err(|error| RoomStateError::Event(error.to_string()))?;
                    state.metadata.observe_snapshot(&metadata)?;
                }
                Some(roles) => {
                    let edit = GroupMetadataEdit::verify(input.event, now, limits)
                        .map_err(|error| RoomStateError::Event(error.to_string()))?;
                    let accepted = AcceptedMetadataEdit::from_evidence(edit, relay.clone(), roles);
                    state.metadata.apply_accepted(&accepted)?;
                }
            }
        }
        for input in snapshot.lifecycle_inputs {
            let request = GroupLifecycleRequest::verify(input.event, now, limits)
                .map_err(|error| RoomStateError::Event(error.to_string()))?;
            let accepted =
                AcceptedLifecycleAction::from_evidence(request, relay.clone(), input.authority);
            state.lifecycle.apply_accepted(&accepted)?;
        }
        for group in snapshot.groups {
            if group.group_id.is_empty()
                || group.membership.group_id() != group.group_id
                || group.membership.relay_pubkey() != relay
                || group.deletions.group_id() != group.group_id
                || group.deletions.relay_pubkey() != relay
            {
                return Err(RoomStateError::InvalidSnapshot(
                    "group evidence is scoped to another group or relay",
                ));
            }
            if state.groups.contains_key(&group.group_id) {
                return Err(RoomStateError::InvalidSnapshot("duplicate group"));
            }
            let mut restored = GroupRoomState {
                group_id: group.group_id.clone(),
                membership: GroupMembershipState::restore(group.membership)?,
                deletions: GroupDeletionState::restore(group.deletions)?,
                admins: None,
                members: None,
                roles: None,
                pins: None,
            };
            for (event, expected) in [
                (group.admins, GroupRosterKind::Admins),
                (group.members, GroupRosterKind::PublishedMembers),
            ] {
                if let Some(event) = event {
                    let roster = GroupRoster::verify(event, &relay, now, limits)
                        .map_err(|error| RoomStateError::Event(error.to_string()))?;
                    if roster.kind() != expected || roster.group_id() != group.group_id {
                        return Err(RoomStateError::InvalidSnapshot(
                            "roster evidence is scoped to another group or kind",
                        ));
                    }
                    match expected {
                        GroupRosterKind::Admins => restored.admins = Some(roster),
                        GroupRosterKind::PublishedMembers => restored.members = Some(roster),
                    }
                }
            }
            if let Some(event) = group.roles {
                let roles = GroupRoles::verify(event, &relay, now, limits)
                    .map_err(|error| RoomStateError::Event(error.to_string()))?;
                if roles.group_id() != group.group_id {
                    return Err(RoomStateError::InvalidSnapshot(
                        "role evidence is scoped to another group",
                    ));
                }
                restored.roles = Some(roles);
            }
            if let Some(event) = group.pins {
                let pins = GroupPinList::verify(event, &relay, now, limits)
                    .map_err(|error| RoomStateError::Event(error.to_string()))?;
                if pins.group_id() != group.group_id {
                    return Err(RoomStateError::InvalidSnapshot(
                        "pin evidence is scoped to another group",
                    ));
                }
                restored.pins = Some(pins);
            }
            state.groups.insert(group.group_id.clone(), restored);
        }
        Ok(state)
    }
}

fn replace_if_newer<T: Clone>(
    slot: &mut Option<T>,
    candidate: &T,
    event: impl Fn(&T) -> &SignedEvent,
) -> bool {
    let newer = match slot.as_ref() {
        None => true,
        Some(current) => {
            let (current, incoming) = (event(current), event(candidate));
            incoming.created_at > current.created_at
                || (incoming.created_at == current.created_at && incoming.id < current.id)
        }
    };
    if newer {
        *slot = Some(candidate.clone());
    }
    newer
}

/// Per-group state on one relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRoomState {
    group_id: String,
    membership: GroupMembershipState,
    deletions: GroupDeletionState,
    admins: Option<GroupRoster>,
    members: Option<GroupRoster>,
    roles: Option<GroupRoles>,
    pins: Option<GroupPinList>,
}

impl GroupRoomState {
    fn new(relay_pubkey: &str, group_id: &str) -> Result<Self, RoomStateError> {
        Ok(Self {
            group_id: group_id.to_owned(),
            membership: GroupMembershipState::new(relay_pubkey.to_owned(), group_id.to_owned())?,
            deletions: GroupDeletionState::new(relay_pubkey.to_owned(), group_id.to_owned())?,
            admins: None,
            members: None,
            roles: None,
            pins: None,
        })
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn membership(&self) -> &GroupMembershipState {
        &self.membership
    }

    #[must_use]
    pub fn deletions(&self) -> &GroupDeletionState {
        &self.deletions
    }

    #[must_use]
    pub fn admins(&self) -> Option<&GroupRoster> {
        self.admins.as_ref()
    }

    #[must_use]
    pub fn members(&self) -> Option<&GroupRoster> {
        self.members.as_ref()
    }

    #[must_use]
    pub fn roles(&self) -> Option<&GroupRoles> {
        self.roles.as_ref()
    }

    #[must_use]
    pub fn pins(&self) -> Option<&GroupPinList> {
        self.pins.as_ref()
    }
}

/// Serializable evidence for one relay's rooms.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayRoomStateSnapshot {
    schema_version: u16,
    relay_pubkey: String,
    identities: Vec<RelayIdentityBinding>,
    metadata_inputs: Vec<MetadataInputSnapshot>,
    lifecycle_inputs: Vec<LifecycleInputSnapshot>,
    groups: Vec<GroupRoomStateSnapshot>,
}

impl RelayRoomStateSnapshot {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MetadataInputSnapshot {
    event: SignedEvent,
    /// `None` for a relay snapshot; the accepting roster's roles for an edit.
    roles: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LifecycleInputSnapshot {
    event: SignedEvent,
    authority: LifecycleAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GroupRoomStateSnapshot {
    group_id: String,
    membership: GroupMembershipSnapshot,
    deletions: GroupDeletionSnapshot,
    admins: Option<SignedEvent>,
    members: Option<SignedEvent>,
    roles: Option<SignedEvent>,
    pins: Option<SignedEvent>,
}

fn is_lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoomStateError {
    InvalidRelayPublicKey,
    EmptyGroupId,
    RelayMismatch,
    UnsupportedSchemaVersion(u16),
    InvalidSnapshot(&'static str),
    Event(String),
    Membership(MembershipStateError),
    Deletion(DeletionStateError),
    Metadata(MetadataStateError),
    Lifecycle(LifecycleStateError),
    Identity(RoomIdentityError),
}

impl fmt::Display for RoomStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::RelayMismatch => {
                formatter.write_str("room state input is bound to another relay authority")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported room state schema version {version}")
            }
            Self::InvalidSnapshot(reason) => {
                write!(formatter, "room state snapshot is invalid: {reason}")
            }
            Self::Event(error) => write!(
                formatter,
                "persisted room event failed verification: {error}"
            ),
            Self::Membership(error) => write!(formatter, "membership state: {error}"),
            Self::Deletion(error) => write!(formatter, "deletion state: {error}"),
            Self::Metadata(error) => write!(formatter, "metadata state: {error}"),
            Self::Lifecycle(error) => write!(formatter, "lifecycle state: {error}"),
            Self::Identity(error) => write!(formatter, "relay identity: {error}"),
        }
    }
}

impl Error for RoomStateError {}

impl From<MembershipStateError> for RoomStateError {
    fn from(error: MembershipStateError) -> Self {
        Self::Membership(error)
    }
}

impl From<DeletionStateError> for RoomStateError {
    fn from(error: DeletionStateError) -> Self {
        Self::Deletion(error)
    }
}

impl From<MetadataStateError> for RoomStateError {
    fn from(error: MetadataStateError) -> Self {
        Self::Metadata(error)
    }
}

impl From<LifecycleStateError> for RoomStateError {
    fn from(error: LifecycleStateError) -> Self {
        Self::Lifecycle(error)
    }
}

impl From<RoomIdentityError> for RoomStateError {
    fn from(error: RoomIdentityError) -> Self {
        Self::Identity(error)
    }
}
