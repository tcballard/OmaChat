//! Deterministic membership state for one authoritative NIP-29 relay group.

use crate::nip29::{GroupMembershipAction, MembershipAction};
use std::{collections::BTreeMap, error::Error, fmt};

/// Membership state is scoped by both relay identity and group ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMembershipState {
    relay_pubkey: String,
    group_id: String,
    records: BTreeMap<String, MembershipRecord>,
}

impl GroupMembershipState {
    pub fn new(relay_pubkey: String, group_id: String) -> Result<Self, MembershipStateError> {
        validate_pubkey(&relay_pubkey)?;
        if group_id.is_empty() {
            return Err(MembershipStateError::EmptyGroupId);
        }
        Ok(Self {
            relay_pubkey,
            group_id,
            records: BTreeMap::new(),
        })
    }

    /// Apply an event observed through this group's authoritative relay path.
    ///
    /// The source relay is room-policy authority under NIP-29. It does not
    /// become identity authority: the event's own verified pubkey remains the
    /// moderator author and the target remains its independent Nostr key.
    pub fn apply_from_authoritative_relay(
        &mut self,
        action: &GroupMembershipAction,
        source_relay_pubkey: &str,
    ) -> Result<MembershipApplyResult, MembershipStateError> {
        if source_relay_pubkey != self.relay_pubkey {
            return Err(MembershipStateError::RelayMismatch);
        }
        if action.group_id() != self.group_id {
            return Err(MembershipStateError::GroupMismatch);
        }

        let (target, member, roles) = match action.action() {
            MembershipAction::Put { pubkey, roles } => (pubkey, true, roles.clone()),
            MembershipAction::Remove { pubkey } => (pubkey, false, Vec::new()),
        };
        let event = action.event();

        if let Some(current) = self.records.get(target) {
            if current.source_event_id == event.id {
                return Ok(MembershipApplyResult::Idempotent);
            }
            if !is_newer(
                event.created_at,
                &event.id,
                current.created_at,
                &current.source_event_id,
            ) {
                return Ok(MembershipApplyResult::IgnoredOlder);
            }
        }

        self.records.insert(
            target.clone(),
            MembershipRecord {
                pubkey: target.clone(),
                member,
                roles,
                moderator_pubkey: action.author().to_owned(),
                source_event_id: event.id.clone(),
                created_at: event.created_at,
            },
        );
        Ok(MembershipApplyResult::Applied)
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
    pub fn record(&self, pubkey: &str) -> Option<&MembershipRecord> {
        self.records.get(pubkey)
    }

    #[must_use]
    pub fn is_member(&self, pubkey: &str) -> bool {
        self.record(pubkey).is_some_and(MembershipRecord::is_member)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRecord {
    pubkey: String,
    member: bool,
    roles: Vec<String>,
    moderator_pubkey: String,
    source_event_id: String,
    created_at: u64,
}

impl MembershipRecord {
    #[must_use]
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    #[must_use]
    pub const fn is_member(&self) -> bool {
        self.member
    }

    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    #[must_use]
    pub fn moderator_pubkey(&self) -> &str {
        &self.moderator_pubkey
    }

    #[must_use]
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipApplyResult {
    Applied,
    Idempotent,
    IgnoredOlder,
}

fn is_newer(created_at: u64, id: &str, current_created_at: u64, current_id: &str) -> bool {
    created_at > current_created_at || (created_at == current_created_at && id < current_id)
}

fn validate_pubkey(pubkey: &str) -> Result<(), MembershipStateError> {
    if pubkey.len() != 64
        || pubkey
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(MembershipStateError::InvalidRelayPublicKey);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipStateError {
    InvalidRelayPublicKey,
    EmptyGroupId,
    RelayMismatch,
    GroupMismatch,
}

impl fmt::Display for MembershipStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::RelayMismatch => {
                formatter.write_str("membership action came from another relay authority")
            }
            Self::GroupMismatch => {
                formatter.write_str("membership action belongs to another group")
            }
        }
    }
}

impl Error for MembershipStateError {}
