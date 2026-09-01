//! Strict NIP-29 kind `9002` metadata edits and cycle-safe room hierarchy.
//!
//! A [`GroupMetadataEdit`] proves only that its signer asked for listed
//! fields of one room to change. An [`AcceptedMetadataEdit`] records that the
//! verified authoritative relay path accepted the action under relay-specific
//! policy. [`RelayMetadataState`] then reduces relay
//! snapshots (kind `39000`) and accepted edits for every group on one relay.
//!
//! The reducer keeps every accepted input and re-folds them in canonical
//! `(created_at, event ID)` order on each change, so partial edits merge
//! per field, later edits win per field, and hierarchy edits that would
//! create a cycle are rejected identically whatever the delivery order.
//!
//! Standards note: NIP-29 defines `name`, `picture`, `about`, and the paired
//! `private`/`public`, `closed`/`open`, `hidden`/`unhidden` switches on kind
//! `9002`. `banner`, `restricted`/`unrestricted`, `supported_kinds`,
//! `parent`, and `child` mirror the kind `39000` fields already modelled and
//! are accepted here under the same names; a one-field `["parent"]` or
//! `["child"]` tag clears that relation. Hierarchy references must be bare
//! group IDs on the same relay; host-qualified references are refused.

use crate::{
    event::{EventError, EventLimits, SignedEvent, Tag},
    nip29::GroupMetadata,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

pub const EDIT_METADATA_KIND: u32 = 9002;

/// A signed metadata edit request whose room authorization is not implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMetadataEdit {
    event: SignedEvent,
    group_id: String,
    changes: MetadataChanges,
    previous: Vec<String>,
}

impl GroupMetadataEdit {
    /// Authenticate an edit without claiming its author may change anything.
    pub fn verify(
        event: SignedEvent,
        now: u64,
        limits: &EventLimits,
    ) -> Result<Self, MetadataEditError> {
        event
            .verify(now, limits)
            .map_err(MetadataEditError::Event)?;
        if event.kind != EDIT_METADATA_KIND {
            return Err(MetadataEditError::UnsupportedKind(event.kind));
        }
        let group_id =
            unique_pair_tag(&event.tags, "h")?.ok_or(MetadataEditError::MissingGroupId)?;
        if group_id.is_empty() {
            return Err(MetadataEditError::EmptyGroupId);
        }
        let changes = MetadataChanges::parse(&event.tags, &group_id)?;
        let previous = timeline_references(&event.tags)?;
        Ok(Self {
            event,
            group_id,
            changes,
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
    pub fn changes(&self) -> &MetadataChanges {
        &self.changes
    }

    #[must_use]
    pub fn previous(&self) -> &[String] {
        &self.previous
    }
}

/// The explicitly editable fields named by one edit. `None` means untouched.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetadataChanges {
    pub name: Option<String>,
    pub picture: Option<String>,
    pub banner: Option<String>,
    pub about: Option<String>,
    pub private: Option<bool>,
    pub restricted: Option<bool>,
    pub hidden: Option<bool>,
    pub closed: Option<bool>,
    pub supported_kinds: Option<Vec<u32>>,
    pub parent: Option<Option<String>>,
    pub children: Option<Vec<String>>,
}

impl MetadataChanges {
    fn parse(tags: &[Tag], group_id: &str) -> Result<Self, MetadataEditError> {
        let changes = Self {
            name: unique_pair_tag(tags, "name")?,
            picture: unique_pair_tag(tags, "picture")?,
            banner: unique_pair_tag(tags, "banner")?,
            about: unique_pair_tag(tags, "about")?,
            private: switch_tag(tags, "private", "public")?,
            restricted: switch_tag(tags, "restricted", "unrestricted")?,
            hidden: switch_tag(tags, "hidden", "unhidden")?,
            closed: switch_tag(tags, "closed", "open")?,
            supported_kinds: supported_kinds_tag(tags)?,
            parent: parent_tag(tags)?,
            children: children_tag(tags)?,
        };
        if changes == Self::default() {
            return Err(MetadataEditError::EmptyEdit);
        }
        if let Some(Some(parent)) = &changes.parent
            && parent == group_id
        {
            return Err(MetadataEditError::SelfParent);
        }
        if let Some(children) = &changes.children {
            if children.iter().any(|child| child == group_id) {
                return Err(MetadataEditError::SelfChild);
            }
            if let Some(Some(parent)) = &changes.parent
                && children.contains(parent)
            {
                return Err(MetadataEditError::HierarchyCycle);
            }
        }
        Ok(changes)
    }
}

/// A metadata edit paired with explicit evidence that it is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedMetadataEdit {
    edit: GroupMetadataEdit,
    relay_pubkey: String,
}

impl AcceptedMetadataEdit {
    /// Record acceptance by the room's verified authoritative relay path.
    ///
    /// NIP-29 role labels do not have universal capabilities, so a `39001`
    /// entry alone is deliberately insufficient evidence.
    pub fn from_authoritative_relay(
        edit: GroupMetadataEdit,
        source_relay_pubkey: &str,
    ) -> Result<Self, MetadataAuthorizationError> {
        if !is_lowercase_hex(source_relay_pubkey, 64) {
            return Err(MetadataAuthorizationError::InvalidRelayPublicKey);
        }
        Ok(Self {
            edit,
            relay_pubkey: source_relay_pubkey.to_owned(),
        })
    }

    #[must_use]
    pub fn edit(&self) -> &GroupMetadataEdit {
        &self.edit
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

}

/// Metadata and hierarchy for every group known on one relay identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayMetadataState {
    relay_pubkey: String,
    inputs: BTreeMap<InputKey, AcceptedInput>,
    groups: BTreeMap<String, GroupMetadataRevision>,
    rejected: Vec<RejectedEdit>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InputKey {
    created_at: u64,
    event_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AcceptedInput {
    Snapshot(GroupMetadata),
    Edit(AcceptedMetadataEdit),
}

impl RelayMetadataState {
    pub fn new(relay_pubkey: String) -> Result<Self, MetadataStateError> {
        if !is_lowercase_hex(&relay_pubkey, 64) {
            return Err(MetadataStateError::InvalidRelayPublicKey);
        }
        Ok(Self {
            relay_pubkey,
            inputs: BTreeMap::new(),
            groups: BTreeMap::new(),
            rejected: Vec::new(),
        })
    }

    /// Record a relay-signed kind `39000` snapshot for one group.
    pub fn observe_snapshot(
        &mut self,
        snapshot: &GroupMetadata,
    ) -> Result<MetadataApplyResult, MetadataStateError> {
        if snapshot.event().pubkey != self.relay_pubkey {
            return Err(MetadataStateError::RelayMismatch);
        }
        self.record(snapshot.event(), AcceptedInput::Snapshot(snapshot.clone()))
    }

    /// Record one accepted edit and re-fold the group state.
    pub fn apply_accepted(
        &mut self,
        accepted: &AcceptedMetadataEdit,
    ) -> Result<MetadataApplyResult, MetadataStateError> {
        if accepted.relay_pubkey() != self.relay_pubkey {
            return Err(MetadataStateError::RelayMismatch);
        }
        self.record(
            accepted.edit().event(),
            AcceptedInput::Edit(accepted.clone()),
        )
    }

    fn record(
        &mut self,
        event: &SignedEvent,
        input: AcceptedInput,
    ) -> Result<MetadataApplyResult, MetadataStateError> {
        let key = InputKey {
            created_at: event.created_at,
            event_id: event.id.clone(),
        };
        if self.inputs.contains_key(&key) {
            return Ok(MetadataApplyResult::Duplicate);
        }
        self.inputs.insert(key, input);
        self.refold();
        Ok(MetadataApplyResult::Recorded)
    }

    fn refold(&mut self) {
        let mut groups: BTreeMap<String, GroupMetadataRevision> = BTreeMap::new();
        let mut rejected = Vec::new();
        for (key, input) in &self.inputs {
            match input {
                AcceptedInput::Snapshot(snapshot) => {
                    let provenance = Provenance {
                        source_event_id: key.event_id.clone(),
                        created_at: key.created_at,
                        author: snapshot.event().pubkey.clone(),
                        authority: RevisionAuthority::RelaySnapshot,
                    };
                    let changes = MetadataChanges {
                        name: Some(snapshot.name().unwrap_or_default().to_owned()),
                        picture: Some(snapshot.picture().unwrap_or_default().to_owned()),
                        banner: Some(snapshot.banner().unwrap_or_default().to_owned()),
                        about: Some(snapshot.about().unwrap_or_default().to_owned()),
                        private: Some(snapshot.is_private()),
                        restricted: Some(snapshot.is_restricted()),
                        hidden: Some(snapshot.is_hidden()),
                        closed: Some(snapshot.is_closed()),
                        supported_kinds: Some(
                            snapshot.supported_kinds().unwrap_or_default().to_vec(),
                        ),
                        parent: Some(snapshot.parent().map(str::to_owned)),
                        children: Some(snapshot.children().to_vec()),
                    };
                    if let Err(reason) =
                        Self::fold_changes(&mut groups, snapshot.group_id(), &changes, provenance)
                    {
                        rejected.push(RejectedEdit {
                            source_event_id: key.event_id.clone(),
                            group_id: snapshot.group_id().to_owned(),
                            reason,
                        });
                    }
                }
                AcceptedInput::Edit(accepted) => {
                    let edit = accepted.edit();
                    let provenance = Provenance {
                        source_event_id: key.event_id.clone(),
                        created_at: key.created_at,
                        author: edit.author().to_owned(),
                        authority: RevisionAuthority::AuthoritativeRelay,
                    };
                    if let Err(reason) =
                        Self::fold_changes(&mut groups, edit.group_id(), edit.changes(), provenance)
                    {
                        rejected.push(RejectedEdit {
                            source_event_id: key.event_id.clone(),
                            group_id: edit.group_id().to_owned(),
                            reason,
                        });
                    }
                }
            }
        }
        self.groups = groups;
        self.rejected = rejected;
    }

    fn fold_changes(
        groups: &mut BTreeMap<String, GroupMetadataRevision>,
        group_id: &str,
        changes: &MetadataChanges,
        provenance: Provenance,
    ) -> Result<(), HierarchyRejection> {
        // Hierarchy edits are checked against the state as it stands at this
        // point of the canonical fold, before any field is written. A parent
        // link from `group_id` to `parent` is a cycle when walking upward from
        // `parent` reaches `group_id`; a child link is the same edge reversed.
        let parent_override = changes
            .parent
            .as_ref()
            .map(|parent| (group_id, parent.as_deref()));
        if let Some(Some(parent)) = &changes.parent {
            if parent == group_id {
                return Err(HierarchyRejection::SelfParent);
            }
            if Self::reaches_upward(groups, parent, group_id, parent_override) {
                return Err(HierarchyRejection::Cycle);
            }
        }
        if let Some(children) = &changes.children {
            for child in children {
                if child == group_id {
                    return Err(HierarchyRejection::SelfChild);
                }
                if Self::reaches_upward(groups, group_id, child, parent_override) {
                    return Err(HierarchyRejection::Cycle);
                }
            }
        }

        let revision = groups
            .entry(group_id.to_owned())
            .or_insert_with(|| GroupMetadataRevision::empty(group_id));
        macro_rules! set {
            ($field:ident, $name:literal) => {
                if let Some(value) = &changes.$field {
                    revision.$field = value.clone();
                    revision.provenance.insert($name, provenance.clone());
                }
            };
        }
        set!(name, "name");
        set!(picture, "picture");
        set!(banner, "banner");
        set!(about, "about");
        set!(private, "private");
        set!(restricted, "restricted");
        set!(hidden, "hidden");
        set!(closed, "closed");
        set!(supported_kinds, "supported_kinds");
        set!(parent, "parent");
        set!(children, "children");
        Ok(())
    }

    /// Does walking upward from `start` (through `parent` links and the
    /// inverse of `child` links) reach `target`, or is `start` itself `target`?
    ///
    /// `parent_override` substitutes one group's parent link with the value
    /// the edit under evaluation would set, so a replaced link is not walked.
    fn reaches_upward(
        groups: &BTreeMap<String, GroupMetadataRevision>,
        start: &str,
        target: &str,
        parent_override: Option<(&str, Option<&str>)>,
    ) -> bool {
        let mut seen = BTreeSet::new();
        let mut frontier = vec![start.to_owned()];
        while let Some(current) = frontier.pop() {
            if current == target {
                return true;
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            let parent = match parent_override {
                Some((group, parent)) if group == current => parent.map(str::to_owned),
                _ => groups.get(&current).and_then(|group| group.parent.clone()),
            };
            if let Some(parent) = parent {
                frontier.push(parent);
            }
            for (candidate, revision) in groups {
                if revision.children.contains(&current) {
                    frontier.push(candidate.clone());
                }
            }
        }
        false
    }

    #[must_use]
    pub fn relay_pubkey(&self) -> &str {
        &self.relay_pubkey
    }

    #[must_use]
    pub fn group(&self, group_id: &str) -> Option<&GroupMetadataRevision> {
        self.groups.get(group_id)
    }

    /// Group IDs with reduced metadata, in lexical order.
    pub fn group_ids(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(String::as_str)
    }

    /// Accepted inputs that the canonical fold refused, with the reason.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedEdit] {
        &self.rejected
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

/// Reduced metadata for one group with per-field provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMetadataRevision {
    group_id: String,
    name: String,
    picture: String,
    banner: String,
    about: String,
    private: bool,
    restricted: bool,
    hidden: bool,
    closed: bool,
    supported_kinds: Vec<u32>,
    parent: Option<String>,
    children: Vec<String>,
    provenance: BTreeMap<&'static str, Provenance>,
}

impl GroupMetadataRevision {
    fn empty(group_id: &str) -> Self {
        Self {
            group_id: group_id.to_owned(),
            name: String::new(),
            picture: String::new(),
            banner: String::new(),
            about: String::new(),
            private: false,
            restricted: false,
            hidden: false,
            closed: false,
            supported_kinds: Vec::new(),
            parent: None,
            children: Vec::new(),
            provenance: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn picture(&self) -> &str {
        &self.picture
    }

    #[must_use]
    pub fn banner(&self) -> &str {
        &self.banner
    }

    #[must_use]
    pub fn about(&self) -> &str {
        &self.about
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
    pub fn supported_kinds(&self) -> &[u32] {
        &self.supported_kinds
    }

    #[must_use]
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    #[must_use]
    pub fn children(&self) -> &[String] {
        &self.children
    }

    /// Which accepted input last set a field, by field name.
    #[must_use]
    pub fn provenance(&self, field: &str) -> Option<&Provenance> {
        self.provenance.get(field)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provenance {
    source_event_id: String,
    created_at: u64,
    author: String,
    authority: RevisionAuthority,
}

impl Provenance {
    #[must_use]
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The signer of the input, never an asserted role.
    #[must_use]
    pub fn author(&self) -> &str {
        &self.author
    }

    #[must_use]
    pub fn authority(&self) -> &RevisionAuthority {
        &self.authority
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevisionAuthority {
    RelaySnapshot,
    AuthoritativeRelay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedEdit {
    pub source_event_id: String,
    pub group_id: String,
    pub reason: HierarchyRejection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HierarchyRejection {
    SelfParent,
    SelfChild,
    Cycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataApplyResult {
    Recorded,
    Duplicate,
}

fn switch_tag(
    tags: &[Tag],
    on: &'static str,
    off: &'static str,
) -> Result<Option<bool>, MetadataEditError> {
    let on_set = flag_tag(tags, on)?;
    let off_set = flag_tag(tags, off)?;
    match (on_set, off_set) {
        (true, true) => Err(MetadataEditError::ConflictingSwitch(on, off)),
        (true, false) => Ok(Some(true)),
        (false, true) => Ok(Some(false)),
        (false, false) => Ok(None),
    }
}

fn flag_tag(tags: &[Tag], name: &'static str) -> Result<bool, MetadataEditError> {
    let mut found = false;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if found {
            return Err(MetadataEditError::DuplicateTag(name));
        }
        if tag.len() != 1 {
            return Err(MetadataEditError::MalformedTag(name));
        }
        found = true;
    }
    Ok(found)
}

fn supported_kinds_tag(tags: &[Tag]) -> Result<Option<Vec<u32>>, MetadataEditError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "supported_kinds"))
    {
        if value.is_some() {
            return Err(MetadataEditError::DuplicateTag("supported_kinds"));
        }
        let mut kinds = Vec::with_capacity(tag.len().saturating_sub(1));
        for field in tag.iter().skip(1) {
            let kind = field
                .parse::<u32>()
                .map_err(|_| MetadataEditError::InvalidSupportedKind)?;
            if field != &kind.to_string() {
                return Err(MetadataEditError::InvalidSupportedKind);
            }
            if kinds.contains(&kind) {
                return Err(MetadataEditError::InvalidSupportedKind);
            }
            kinds.push(kind);
        }
        value = Some(kinds);
    }
    Ok(value)
}

fn parent_tag(tags: &[Tag]) -> Result<Option<Option<String>>, MetadataEditError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "parent"))
    {
        if value.is_some() {
            return Err(MetadataEditError::DuplicateTag("parent"));
        }
        value = Some(match tag.len() {
            1 => None,
            2 => {
                validate_group_reference(&tag[1])?;
                Some(tag[1].clone())
            }
            _ => return Err(MetadataEditError::MalformedTag("parent")),
        });
    }
    Ok(value)
}

fn children_tag(tags: &[Tag]) -> Result<Option<Vec<String>>, MetadataEditError> {
    let mut children: Option<Vec<String>> = None;
    let mut cleared = false;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "child"))
    {
        match tag.len() {
            1 => {
                if cleared || children.is_some() {
                    return Err(MetadataEditError::MalformedTag("child"));
                }
                cleared = true;
                children = Some(Vec::new());
            }
            2 => {
                if cleared {
                    return Err(MetadataEditError::MalformedTag("child"));
                }
                validate_group_reference(&tag[1])?;
                let list = children.get_or_insert_with(Vec::new);
                if list.contains(&tag[1]) {
                    return Err(MetadataEditError::DuplicateChild);
                }
                list.push(tag[1].clone());
            }
            _ => return Err(MetadataEditError::MalformedTag("child")),
        }
    }
    Ok(children)
}

/// Hierarchy references must be bare same-relay group IDs.
fn validate_group_reference(value: &str) -> Result<(), MetadataEditError> {
    if value.is_empty() {
        return Err(MetadataEditError::EmptyGroupReference);
    }
    if value.contains('\'') || value.contains("://") {
        return Err(MetadataEditError::CrossRelayReference);
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    }) {
        return Err(MetadataEditError::InvalidGroupReference);
    }
    Ok(())
}

fn unique_pair_tag(tags: &[Tag], name: &'static str) -> Result<Option<String>, MetadataEditError> {
    let mut value = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == name))
    {
        if value.is_some() {
            return Err(MetadataEditError::DuplicateTag(name));
        }
        if tag.len() != 2 {
            return Err(MetadataEditError::MalformedTag(name));
        }
        value = Some(tag[1].clone());
    }
    Ok(value)
}

fn timeline_references(tags: &[Tag]) -> Result<Vec<String>, MetadataEditError> {
    let mut previous = None;
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|part| part == "previous"))
    {
        if previous.is_some() {
            return Err(MetadataEditError::DuplicateTag("previous"));
        }
        let references = tag.iter().skip(1).cloned().collect::<Vec<_>>();
        if references
            .iter()
            .any(|reference| !is_lowercase_hex(reference, 8))
        {
            return Err(MetadataEditError::InvalidTimelineReference);
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
pub enum MetadataEditError {
    Event(EventError),
    UnsupportedKind(u32),
    MissingGroupId,
    EmptyGroupId,
    EmptyEdit,
    DuplicateTag(&'static str),
    MalformedTag(&'static str),
    ConflictingSwitch(&'static str, &'static str),
    InvalidSupportedKind,
    EmptyGroupReference,
    InvalidGroupReference,
    CrossRelayReference,
    DuplicateChild,
    SelfParent,
    SelfChild,
    HierarchyCycle,
    InvalidTimelineReference,
}

impl fmt::Display for MetadataEditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Event(error) => write!(formatter, "invalid NIP-29 metadata edit: {error}"),
            Self::UnsupportedKind(kind) => {
                write!(formatter, "unsupported NIP-29 metadata edit kind {kind}")
            }
            Self::MissingGroupId => {
                formatter.write_str("NIP-29 metadata edit is missing its h tag")
            }
            Self::EmptyGroupId => formatter.write_str("NIP-29 group ID must not be empty"),
            Self::EmptyEdit => formatter.write_str("NIP-29 metadata edit changes no field"),
            Self::DuplicateTag(name) => write!(formatter, "duplicate NIP-29 {name} tag"),
            Self::MalformedTag(name) => write!(formatter, "malformed NIP-29 {name} tag"),
            Self::ConflictingSwitch(on, off) => {
                write!(formatter, "NIP-29 metadata edit sets both {on} and {off}")
            }
            Self::InvalidSupportedKind => {
                formatter.write_str("NIP-29 supported kinds must be distinct canonical integers")
            }
            Self::EmptyGroupReference => {
                formatter.write_str("NIP-29 hierarchy reference must not be empty")
            }
            Self::InvalidGroupReference => {
                formatter.write_str("NIP-29 hierarchy reference must be a bare group ID")
            }
            Self::CrossRelayReference => {
                formatter.write_str("NIP-29 hierarchy reference must not name another relay")
            }
            Self::DuplicateChild => formatter.write_str("duplicate NIP-29 child reference"),
            Self::SelfParent => formatter.write_str("NIP-29 group cannot be its own parent"),
            Self::SelfChild => formatter.write_str("NIP-29 group cannot be its own child"),
            Self::HierarchyCycle => {
                formatter.write_str("NIP-29 metadata edit would create a hierarchy cycle")
            }
            Self::InvalidTimelineReference => formatter.write_str(
                "NIP-29 timeline reference must be the lowercase first 8 hex characters of an event ID",
            ),
        }
    }
}

impl Error for MetadataEditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataAuthorizationError {
    InvalidRelayPublicKey,
}

impl fmt::Display for MetadataAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
        }
    }
}

impl Error for MetadataAuthorizationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataStateError {
    InvalidRelayPublicKey,
    RelayMismatch,
}

impl fmt::Display for MetadataStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelayPublicKey => {
                formatter.write_str("NIP-29 relay identity must be a lowercase 32-byte public key")
            }
            Self::RelayMismatch => {
                formatter.write_str("metadata input is bound to another relay authority")
            }
        }
    }
}

impl Error for MetadataStateError {}
