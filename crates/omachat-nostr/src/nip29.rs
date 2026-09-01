//! Strict client-side NIP-29 room event boundaries.

use crate::event::{EventError, EventLimits, SignedEvent, Tag, UnsignedEvent};
use std::{error::Error, fmt};

pub const GROUP_MESSAGE_KIND: u32 = 9;
pub const JOIN_REQUEST_KIND: u32 = 9021;
pub const LEAVE_REQUEST_KIND: u32 = 9022;
pub const GROUP_METADATA_KIND: u32 = 39000;
pub const GROUP_ADMINS_KIND: u32 = 39001;
pub const GROUP_MEMBERS_KIND: u32 = 39002;

/// A principal listed in relay-authenticated NIP-29 group state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPrincipal {
    pubkey: String,
    roles: Vec<String>,
}

impl GroupPrincipal {
    #[must_use]
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupRosterKind {
    Admins,
    PublishedMembers,
}

/// A relay-authenticated NIP-29 admin or published-member snapshot.
///
/// NIP-29 permits member snapshots to be absent, restricted, or partial, so a
/// `PublishedMembers` value must never be interpreted as a complete ACL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRoster {
    event: SignedEvent,
    group_id: String,
    kind: GroupRosterKind,
    principals: Vec<GroupPrincipal>,
}

impl GroupRoster {
    pub fn verify(
        event: SignedEvent,
        expected_relay_pubkey: &str,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, GroupEventError> {
        event.verify(now, limits).map_err(GroupEventError::Event)?;
        if event.pubkey != expected_relay_pubkey {
            return Err(GroupEventError::RelayAuthorMismatch);
        }
        let kind = match event.kind {
            GROUP_ADMINS_KIND => GroupRosterKind::Admins,
            GROUP_MEMBERS_KIND => GroupRosterKind::PublishedMembers,
            kind => return Err(GroupEventError::UnsupportedKind(kind)),
        };
        let group_id = unique_pair_tag(&event.tags, "d", GroupEventError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(GroupEventError::EmptyGroupId);
        }

        let mut principals = Vec::new();
        for tag in event
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|part| part == "p"))
        {
            let minimum_fields = if kind == GroupRosterKind::Admins {
                3
            } else {
                2
            };
            if tag.len() < minimum_fields
                || (kind == GroupRosterKind::PublishedMembers && tag.len() != 2)
            {
                return Err(GroupEventError::MalformedTag("p"));
            }
            validate_pubkey(&tag[1])?;
            if principals
                .iter()
                .any(|principal: &GroupPrincipal| principal.pubkey == tag[1])
            {
                return Err(GroupEventError::DuplicatePrincipal);
            }
            let roles = tag.iter().skip(2).cloned().collect::<Vec<_>>();
            if roles.iter().any(String::is_empty) {
                return Err(GroupEventError::EmptyRole);
            }
            principals.push(GroupPrincipal {
                pubkey: tag[1].clone(),
                roles,
            });
        }

        Ok(Self {
            event,
            group_id,
            kind,
            principals,
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
    pub const fn kind(&self) -> GroupRosterKind {
        self.kind
    }

    #[must_use]
    pub fn principals(&self) -> &[GroupPrincipal] {
        &self.principals
    }
}

/// Relay-authenticated NIP-29 room discovery metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMetadata {
    event: SignedEvent,
    group_id: String,
    name: Option<String>,
    picture: Option<String>,
    banner: Option<String>,
    about: Option<String>,
    private: bool,
    restricted: bool,
    hidden: bool,
    closed: bool,
    livekit: bool,
    supported_kinds: Option<Vec<u32>>,
    parent: Option<String>,
    children: Vec<String>,
}

impl GroupMetadata {
    /// Authenticate metadata against the relay identity obtained through NIP-11.
    pub fn verify(
        event: SignedEvent,
        expected_relay_pubkey: &str,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, GroupEventError> {
        event.verify(now, limits).map_err(GroupEventError::Event)?;
        if event.kind != GROUP_METADATA_KIND {
            return Err(GroupEventError::UnsupportedKind(event.kind));
        }
        if event.pubkey != expected_relay_pubkey {
            return Err(GroupEventError::RelayAuthorMismatch);
        }

        let group_id = unique_pair_tag(&event.tags, "d", GroupEventError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(GroupEventError::EmptyGroupId);
        }

        let supported_kinds = optional_list_tag(&event.tags, "supported_kinds")?
            .map(|values| {
                values
                    .into_iter()
                    .map(|value| {
                        value
                            .parse::<u32>()
                            .map_err(|_| GroupEventError::InvalidSupportedKind)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        Ok(Self {
            name: optional_pair_tag(&event.tags, "name")?,
            picture: optional_pair_tag(&event.tags, "picture")?,
            banner: optional_pair_tag(&event.tags, "banner")?,
            about: optional_pair_tag(&event.tags, "about")?,
            private: flag_tag(&event.tags, "private")?,
            restricted: flag_tag(&event.tags, "restricted")?,
            hidden: flag_tag(&event.tags, "hidden")?,
            closed: flag_tag(&event.tags, "closed")?,
            livekit: flag_tag(&event.tags, "livekit")?,
            parent: optional_pair_tag(&event.tags, "parent")?,
            children: repeated_pair_tags(&event.tags, "child")?,
            event,
            group_id,
            supported_kinds,
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
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn picture(&self) -> Option<&str> {
        self.picture.as_deref()
    }

    #[must_use]
    pub fn banner(&self) -> Option<&str> {
        self.banner.as_deref()
    }

    #[must_use]
    pub fn about(&self) -> Option<&str> {
        self.about.as_deref()
    }

    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.private
    }

    #[must_use]
    pub const fn is_restricted(&self) -> bool {
        self.restricted
    }

    #[must_use]
    pub const fn is_hidden(&self) -> bool {
        self.hidden
    }

    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    #[must_use]
    pub const fn supports_livekit(&self) -> bool {
        self.livekit
    }

    /// `None` means all kinds are permitted; `Some([])` is an AV-only room.
    #[must_use]
    pub fn supported_kinds(&self) -> Option<&[u32]> {
        self.supported_kinds.as_deref()
    }

    #[must_use]
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    #[must_use]
    pub fn children(&self) -> &[String] {
        &self.children
    }
}

/// A verified NIP-29 event authored by the event's own Nostr principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupUserEvent {
    event: SignedEvent,
    group_id: String,
    action: GroupUserAction,
    previous: Vec<String>,
}

impl GroupUserEvent {
    /// Authenticate and interpret a supported user-created NIP-29 event.
    pub fn verify(
        event: SignedEvent,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, GroupEventError> {
        event.verify(now, limits).map_err(GroupEventError::Event)?;

        let group_id = unique_pair_tag(&event.tags, "h", GroupEventError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(GroupEventError::EmptyGroupId);
        }
        let previous = timeline_references(&event.tags)?;
        let invite_code = optional_pair_tag(&event.tags, "code")?;

        let action = match event.kind {
            GROUP_MESSAGE_KIND => {
                if invite_code.is_some() {
                    return Err(GroupEventError::InviteCodeOutsideJoin);
                }
                GroupUserAction::Message
            }
            JOIN_REQUEST_KIND => GroupUserAction::Join { invite_code },
            LEAVE_REQUEST_KIND => {
                if invite_code.is_some() {
                    return Err(GroupEventError::InviteCodeOutsideJoin);
                }
                GroupUserAction::Leave
            }
            kind => return Err(GroupEventError::UnsupportedKind(kind)),
        };

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
    pub fn action(&self) -> &GroupUserAction {
        &self.action
    }

    #[must_use]
    pub fn previous(&self) -> &[String] {
        &self.previous
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupUserAction {
    Message,
    Join { invite_code: Option<String> },
    Leave,
}

/// Build a NIP-29 kind `9` room message without changing its author principal.
pub fn group_message(
    pubkey: String,
    created_at: u64,
    group_id: &str,
    content: String,
    previous: &[String],
    limits: &EventLimits,
) -> Result<UnsignedEvent, GroupEventError> {
    build_user_event(
        pubkey,
        created_at,
        GROUP_MESSAGE_KIND,
        group_id,
        content,
        None,
        previous,
        limits,
    )
}

/// Build a NIP-29 join request with an optional relay-issued invite code.
pub fn join_request(
    pubkey: String,
    created_at: u64,
    group_id: &str,
    reason: String,
    invite_code: Option<&str>,
    previous: &[String],
    limits: &EventLimits,
) -> Result<UnsignedEvent, GroupEventError> {
    build_user_event(
        pubkey,
        created_at,
        JOIN_REQUEST_KIND,
        group_id,
        reason,
        invite_code,
        previous,
        limits,
    )
}

/// Build a NIP-29 leave request.
pub fn leave_request(
    pubkey: String,
    created_at: u64,
    group_id: &str,
    reason: String,
    previous: &[String],
    limits: &EventLimits,
) -> Result<UnsignedEvent, GroupEventError> {
    build_user_event(
        pubkey,
        created_at,
        LEAVE_REQUEST_KIND,
        group_id,
        reason,
        None,
        previous,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_user_event(
    pubkey: String,
    created_at: u64,
    kind: u32,
    group_id: &str,
    content: String,
    invite_code: Option<&str>,
    previous: &[String],
    limits: &EventLimits,
) -> Result<UnsignedEvent, GroupEventError> {
    if group_id.is_empty() {
        return Err(GroupEventError::EmptyGroupId);
    }
    validate_tag_field(group_id, limits)?;

    let mut tags = vec![vec!["h".to_owned(), group_id.to_owned()]];
    if let Some(invite_code) = invite_code {
        if invite_code.is_empty() {
            return Err(GroupEventError::EmptyInviteCode);
        }
        validate_tag_field(invite_code, limits)?;
        tags.push(vec!["code".to_owned(), invite_code.to_owned()]);
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

    UnsignedEvent::new(pubkey, created_at, kind, tags, content, limits)
        .map_err(GroupEventError::Event)
}

fn unique_pair_tag(
    tags: &[Tag],
    name: &'static str,
    missing: GroupEventError,
) -> Result<String, GroupEventError> {
    optional_pair_tag(tags, name)?.ok_or(missing)
}

fn optional_pair_tag(tags: &[Tag], name: &'static str) -> Result<Option<String>, GroupEventError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if value.is_some() {
            return Err(GroupEventError::DuplicateTag(name));
        }
        if tag.len() != 2 {
            return Err(GroupEventError::MalformedTag(name));
        }
        value = Some(tag[1].clone());
    }
    Ok(value)
}

fn timeline_references(tags: &[Tag]) -> Result<Vec<String>, GroupEventError> {
    let mut previous = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "previous"))
    {
        if previous.is_some() {
            return Err(GroupEventError::DuplicateTag("previous"));
        }
        let references = tag.iter().skip(1).cloned().collect::<Vec<_>>();
        for reference in &references {
            validate_timeline_reference(reference)?;
        }
        previous = Some(references);
    }
    Ok(previous.unwrap_or_default())
}

fn optional_list_tag(
    tags: &[Tag],
    name: &'static str,
) -> Result<Option<Vec<String>>, GroupEventError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if value.is_some() {
            return Err(GroupEventError::DuplicateTag(name));
        }
        value = Some(tag.iter().skip(1).cloned().collect());
    }
    Ok(value)
}

fn flag_tag(tags: &[Tag], name: &'static str) -> Result<bool, GroupEventError> {
    let matching = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(GroupEventError::DuplicateTag(name));
    }
    if matching.first().is_some_and(|tag| tag.len() != 1) {
        return Err(GroupEventError::MalformedTag(name));
    }
    Ok(!matching.is_empty())
}

fn repeated_pair_tags(tags: &[Tag], name: &'static str) -> Result<Vec<String>, GroupEventError> {
    let mut values = Vec::new();
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if tag.len() != 2 {
            return Err(GroupEventError::MalformedTag(name));
        }
        if values.contains(&tag[1]) {
            return Err(GroupEventError::DuplicateTag(name));
        }
        values.push(tag[1].clone());
    }
    Ok(values)
}

fn validate_timeline_reference(reference: &str) -> Result<(), GroupEventError> {
    if reference.len() != 8
        || reference
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GroupEventError::InvalidTimelineReference);
    }
    Ok(())
}

fn validate_pubkey(pubkey: &str) -> Result<(), GroupEventError> {
    if pubkey.len() != 64
        || pubkey
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(GroupEventError::InvalidPrincipalPublicKey);
    }
    Ok(())
}

fn validate_tag_field(value: &str, limits: &EventLimits) -> Result<(), GroupEventError> {
    if value.len() > limits.max_tag_field_bytes {
        return Err(GroupEventError::TagFieldTooLarge {
            bytes: value.len(),
            maximum: limits.max_tag_field_bytes,
        });
    }
    Ok(())
}

#[derive(Debug)]
pub enum GroupEventError {
    Event(EventError),
    UnsupportedKind(u32),
    MissingGroupId,
    EmptyGroupId,
    EmptyInviteCode,
    DuplicateTag(&'static str),
    MalformedTag(&'static str),
    InviteCodeOutsideJoin,
    InvalidTimelineReference,
    RelayAuthorMismatch,
    InvalidSupportedKind,
    InvalidPrincipalPublicKey,
    DuplicatePrincipal,
    EmptyRole,
    TagFieldTooLarge { bytes: usize, maximum: usize },
}

impl fmt::Display for GroupEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid NIP-29 event: {error}"),
            Self::UnsupportedKind(kind) => write!(formatter, "unsupported NIP-29 user kind {kind}"),
            Self::MissingGroupId => formatter.write_str("NIP-29 event is missing its h tag"),
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::EmptyInviteCode => formatter.write_str("NIP-29 invite code must not be empty"),
            Self::DuplicateTag(name) => write!(formatter, "duplicate NIP-29 {name} tag"),
            Self::MalformedTag(name) => write!(formatter, "malformed NIP-29 {name} tag"),
            Self::InviteCodeOutsideJoin => {
                formatter.write_str("NIP-29 invite code is only valid on a join request")
            }
            Self::InvalidTimelineReference => formatter.write_str(
                "NIP-29 previous references must be lowercase four-byte event ID prefixes",
            ),
            Self::RelayAuthorMismatch => {
                formatter.write_str("NIP-29 metadata author does not match the expected relay")
            }
            Self::InvalidSupportedKind => {
                formatter.write_str("NIP-29 supported kind must be an unsigned decimal integer")
            }
            Self::InvalidPrincipalPublicKey => {
                formatter.write_str("NIP-29 group principal must be a lowercase 32-byte public key")
            }
            Self::DuplicatePrincipal => formatter.write_str("duplicate NIP-29 group principal"),
            Self::EmptyRole => formatter.write_str("NIP-29 group role must not be empty"),
            Self::TagFieldTooLarge { bytes, maximum } => write!(
                formatter,
                "NIP-29 tag field is {bytes} bytes; maximum is {maximum}"
            ),
        }
    }
}

impl Error for GroupEventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            _ => None,
        }
    }
}
