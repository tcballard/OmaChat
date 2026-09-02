//! Relay-authenticated NIP-29 role definitions without invented capabilities.

use crate::event::{EventError, EventLimits, SignedEvent, Tag};
use std::{error::Error, fmt};

pub const GROUP_ROLES_KIND: u32 = 39003;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRoles {
    event: SignedEvent,
    group_id: String,
    roles: Vec<GroupRoleDefinition>,
}

impl GroupRoles {
    /// Authenticate role labels against the relay identity obtained via NIP-11.
    ///
    /// NIP-29 does not standardize capabilities for these labels. Consumers
    /// must not infer permissions from a role name alone.
    pub fn verify(
        event: SignedEvent,
        expected_relay_pubkey: &str,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, GroupRolesError> {
        event.verify(now, limits).map_err(GroupRolesError::Event)?;
        if event.kind != GROUP_ROLES_KIND {
            return Err(GroupRolesError::UnsupportedKind(event.kind));
        }
        if event.pubkey != expected_relay_pubkey {
            return Err(GroupRolesError::RelayAuthorMismatch);
        }

        let group_id = unique_pair_tag(&event.tags, "d")?.ok_or(GroupRolesError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(GroupRolesError::EmptyGroupId);
        }

        let mut roles = Vec::new();
        for tag in event
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|part| part == "role"))
        {
            if !(2..=3).contains(&tag.len()) {
                return Err(GroupRolesError::MalformedRole);
            }
            if tag[1].is_empty() {
                return Err(GroupRolesError::EmptyRole);
            }
            if roles
                .iter()
                .any(|role: &GroupRoleDefinition| role.name == tag[1])
            {
                return Err(GroupRolesError::DuplicateRole);
            }
            roles.push(GroupRoleDefinition {
                name: tag[1].clone(),
                description: tag.get(2).cloned(),
            });
        }

        Ok(Self {
            event,
            group_id,
            roles,
        })
    }

    #[must_use]
    pub fn event(&self) -> &SignedEvent {
        &self.event
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn roles(&self) -> &[GroupRoleDefinition] {
        &self.roles
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRoleDefinition {
    name: String,
    description: Option<String>,
}

impl GroupRoleDefinition {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

fn unique_pair_tag(tags: &[Tag], name: &'static str) -> Result<Option<String>, GroupRolesError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if value.is_some() {
            return Err(GroupRolesError::DuplicateTag(name));
        }
        if tag.len() != 2 {
            return Err(GroupRolesError::MalformedTag(name));
        }
        value = Some(tag[1].clone());
    }
    Ok(value)
}

#[derive(Debug)]
pub enum GroupRolesError {
    Event(EventError),
    UnsupportedKind(u32),
    RelayAuthorMismatch,
    MissingGroupId,
    EmptyGroupId,
    DuplicateTag(&'static str),
    MalformedTag(&'static str),
    MalformedRole,
    EmptyRole,
    DuplicateRole,
}

impl fmt::Display for GroupRolesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid NIP-29 role event: {error}"),
            Self::UnsupportedKind(kind) => write!(formatter, "unsupported NIP-29 role kind {kind}"),
            Self::RelayAuthorMismatch => {
                formatter.write_str("NIP-29 role author does not match the expected relay")
            }
            Self::MissingGroupId => formatter.write_str("NIP-29 role event is missing its d tag"),
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::DuplicateTag(name) => write!(formatter, "duplicate NIP-29 {name} tag"),
            Self::MalformedTag(name) => write!(formatter, "malformed NIP-29 {name} tag"),
            Self::MalformedRole => formatter
                .write_str("NIP-29 role tag must contain a name and at most one description"),
            Self::EmptyRole => formatter.write_str("NIP-29 role name must not be empty"),
            Self::DuplicateRole => formatter.write_str("duplicate NIP-29 role name"),
        }
    }
}

impl Error for GroupRolesError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            _ => None,
        }
    }
}
