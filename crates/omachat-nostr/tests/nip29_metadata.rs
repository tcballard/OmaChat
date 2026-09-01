use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    nip29::{GroupMetadata, GroupRoster},
    nip29_metadata::{
        AcceptedMetadataEdit, EDIT_METADATA_KIND, GroupMetadataEdit, HierarchyRejection,
        MetadataApplyResult, MetadataAuthorizationError, MetadataEditError, MetadataStateError,
        RelayMetadataState, RevisionAuthority,
    },
};

const NOW: u64 = 1_800_000_000;
const RELAY_SECRET: [u8; 32] = [5; 32];
const MODERATOR_SECRET: [u8; 32] = [7; 32];
const AGENT_SECRET: [u8; 32] = [9; 32];
const OTHER_RELAY_SECRET: [u8; 32] = [11; 32];

fn limits() -> EventLimits {
    EventLimits::default()
}

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("valid key"))
}

fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn signed(secret: &[u8; 32], created_at: u64, kind: u32, tags: Vec<Vec<String>>) -> SignedEvent {
    UnsignedEvent::new(
        pubkey(secret),
        created_at,
        kind,
        tags,
        String::new(),
        &limits(),
    )
    .expect("event")
    .sign_with_aux(secret, &[3; 32], &limits())
    .expect("signed event")
}

fn edit_event(secret: &[u8; 32], group: &str, created_at: u64, tags: &[&[&str]]) -> SignedEvent {
    let mut all = vec![tag(&["h", group])];
    all.extend(tags.iter().map(|parts| tag(parts)));
    signed(secret, created_at, EDIT_METADATA_KIND, all)
}

fn edit(secret: &[u8; 32], group: &str, created_at: u64, tags: &[&[&str]]) -> GroupMetadataEdit {
    GroupMetadataEdit::verify(edit_event(secret, group, created_at, tags), NOW, &limits())
        .expect("verified edit")
}

fn admins(relay_secret: &[u8; 32], group: &str, admin: &str) -> GroupRoster {
    let event = signed(
        relay_secret,
        NOW - 100,
        39001,
        vec![tag(&["d", group]), tag(&["p", admin, "moderator"])],
    );
    GroupRoster::verify(event, &pubkey(relay_secret), NOW, &limits()).expect("admin roster")
}

fn accepted(group: &str, created_at: u64, tags: &[&[&str]]) -> AcceptedMetadataEdit {
    let relay = pubkey(&RELAY_SECRET);
    AcceptedMetadataEdit::by_administrator(
        edit(&MODERATOR_SECRET, group, created_at, tags),
        &admins(&RELAY_SECRET, group, &pubkey(&MODERATOR_SECRET)),
        &relay,
    )
    .expect("accepted edit")
}

fn snapshot(group: &str, created_at: u64, tags: &[&[&str]]) -> GroupMetadata {
    let mut all = vec![tag(&["d", group])];
    all.extend(tags.iter().map(|parts| tag(parts)));
    GroupMetadata::verify(
        signed(&RELAY_SECRET, created_at, 39000, all),
        &pubkey(&RELAY_SECRET),
        NOW,
        &limits(),
    )
    .expect("snapshot")
}

fn state() -> RelayMetadataState {
    RelayMetadataState::new(pubkey(&RELAY_SECRET)).expect("state")
}

#[test]
fn valid_edit_parses_every_editable_field() {
    let parsed = edit(
        &MODERATOR_SECRET,
        "omarchy",
        NOW - 1,
        &[
            &["name", "Omarchy"],
            &["picture", "https://example.test/p.png"],
            &["banner", "https://example.test/b.png"],
            &["about", "Linux talk"],
            &["private"],
            &["open"],
            &["unhidden"],
            &["restricted"],
            &["supported_kinds", "9", "11"],
            &["parent", "linux"],
            &["child", "install-help"],
            &["child", "showcase"],
            &["previous", "eb96c864"],
        ],
    );
    assert_eq!(parsed.author(), pubkey(&MODERATOR_SECRET));
    assert_eq!(parsed.group_id(), "omarchy");
    let changes = parsed.changes();
    assert_eq!(changes.name.as_deref(), Some("Omarchy"));
    assert_eq!(changes.about.as_deref(), Some("Linux talk"));
    assert_eq!(changes.private, Some(true));
    assert_eq!(changes.closed, Some(false));
    assert_eq!(changes.hidden, Some(false));
    assert_eq!(changes.restricted, Some(true));
    assert_eq!(changes.supported_kinds, Some(vec![9, 11]));
    assert_eq!(changes.parent, Some(Some("linux".to_owned())));
    assert_eq!(
        changes.children,
        Some(vec!["install-help".to_owned(), "showcase".to_owned()])
    );
    assert_eq!(parsed.previous(), ["eb96c864"]);

    // One-field parent and child tags clear those relations.
    let cleared = edit(
        &MODERATOR_SECRET,
        "omarchy",
        NOW - 1,
        &[&["parent"], &["child"]],
    );
    assert_eq!(cleared.changes().parent, Some(None));
    assert_eq!(cleared.changes().children, Some(Vec::new()));
}

#[test]
fn invalid_signature_and_malformed_edits_fail_closed() {
    let mut tampered = edit_event(&MODERATOR_SECRET, "omarchy", NOW, &[&["name", "x"]]);
    tampered.tags.push(tag(&["name", "y"]));
    assert!(matches!(
        GroupMetadataEdit::verify(tampered, NOW, &limits()),
        Err(MetadataEditError::Event(_))
    ));

    let verify = |tags: &[&[&str]]| {
        GroupMetadataEdit::verify(
            edit_event(&MODERATOR_SECRET, "omarchy", NOW, tags),
            NOW,
            &limits(),
        )
        .err()
    };
    assert!(matches!(
        GroupMetadataEdit::verify(
            signed(&MODERATOR_SECRET, NOW, 9001, vec![tag(&["h", "omarchy"])]),
            NOW,
            &limits()
        ),
        Err(MetadataEditError::UnsupportedKind(9001))
    ));
    assert!(matches!(
        GroupMetadataEdit::verify(
            signed(
                &MODERATOR_SECRET,
                NOW,
                EDIT_METADATA_KIND,
                vec![tag(&["name", "x"])]
            ),
            NOW,
            &limits()
        ),
        Err(MetadataEditError::MissingGroupId)
    ));
    assert!(matches!(verify(&[]), Some(MetadataEditError::EmptyEdit)));
    assert!(matches!(
        verify(&[&["name", "a"], &["name", "b"]]),
        Some(MetadataEditError::DuplicateTag("name"))
    ));
    // Invalid visibility values.
    assert!(matches!(
        verify(&[&["private"], &["public"]]),
        Some(MetadataEditError::ConflictingSwitch("private", "public"))
    ));
    assert!(matches!(
        verify(&[&["closed"], &["open"]]),
        Some(MetadataEditError::ConflictingSwitch("closed", "open"))
    ));
    assert!(matches!(
        verify(&[&["hidden", "yes"]]),
        Some(MetadataEditError::MalformedTag("hidden"))
    ));
    // Invalid supported kinds.
    for kinds in [
        &["supported_kinds", "nine"][..],
        &["supported_kinds", "09"],
        &["supported_kinds", "-1"],
        &["supported_kinds", "9", "9"],
    ] {
        assert!(matches!(
            verify(&[kinds]),
            Some(MetadataEditError::InvalidSupportedKind)
        ));
    }
    // Hierarchy references.
    assert!(matches!(
        verify(&[&["parent", "omarchy"]]),
        Some(MetadataEditError::SelfParent)
    ));
    assert!(matches!(
        verify(&[&["child", "omarchy"]]),
        Some(MetadataEditError::SelfChild)
    ));
    assert!(matches!(
        verify(&[&["parent", "linux"], &["child", "linux"]]),
        Some(MetadataEditError::HierarchyCycle)
    ));
    assert!(matches!(
        verify(&[&["parent", "relay.other.test'linux"]]),
        Some(MetadataEditError::CrossRelayReference)
    ));
    assert!(matches!(
        verify(&[&["child", "wss://relay.other.test/linux"]]),
        Some(MetadataEditError::CrossRelayReference)
    ));
    assert!(matches!(
        verify(&[&["parent", "Linux Talk"]]),
        Some(MetadataEditError::InvalidGroupReference)
    ));
    assert!(matches!(
        verify(&[&["parent", ""]]),
        Some(MetadataEditError::EmptyGroupReference)
    ));
    assert!(matches!(
        verify(&[&["child", "a"], &["child", "a"]]),
        Some(MetadataEditError::DuplicateChild)
    ));
    assert!(matches!(
        verify(&[&["child"], &["child", "a"]]),
        Some(MetadataEditError::MalformedTag("child"))
    ));
    assert!(matches!(
        verify(&[&["parent", "a", "b"]]),
        Some(MetadataEditError::MalformedTag("parent"))
    ));
}

#[test]
fn unauthorized_edits_have_no_effect_and_relay_origin_is_not_authority() {
    let relay = pubkey(&RELAY_SECRET);
    let agent_edit = edit(&AGENT_SECRET, "omarchy", NOW - 1, &[&["name", "Pwned"]]);
    let roster = admins(&RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET));

    assert_eq!(
        AcceptedMetadataEdit::by_administrator(agent_edit.clone(), &roster, &relay).err(),
        Some(MetadataAuthorizationError::EditorNotAdministrator)
    );
    // The same relay listing the agent as admin of another group proves nothing here.
    let other_group = admins(&RELAY_SECRET, "other", &pubkey(&AGENT_SECRET));
    assert_eq!(
        AcceptedMetadataEdit::by_administrator(agent_edit.clone(), &other_group, &relay).err(),
        Some(MetadataAuthorizationError::RosterGroupMismatch)
    );
    // Another relay vouching for the agent is not this relay's policy.
    let foreign = admins(&OTHER_RELAY_SECRET, "omarchy", &pubkey(&AGENT_SECRET));
    assert_eq!(
        AcceptedMetadataEdit::by_administrator(agent_edit.clone(), &foreign, &relay).err(),
        Some(MetadataAuthorizationError::RosterRelayMismatch)
    );
    // A member list is not moderation authority.
    let members = GroupRoster::verify(
        signed(
            &RELAY_SECRET,
            NOW - 100,
            39002,
            vec![tag(&["d", "omarchy"]), tag(&["p", &pubkey(&AGENT_SECRET)])],
        ),
        &relay,
        NOW,
        &limits(),
    )
    .expect("members");
    assert_eq!(
        AcceptedMetadataEdit::by_administrator(agent_edit, &members, &relay).err(),
        Some(MetadataAuthorizationError::NotAdministratorRoster)
    );

    // An edit signed by the relay key itself is judged as the relay's own
    // request: it still needs the roster to list that key.
    let relay_signed = edit(
        &RELAY_SECRET,
        "omarchy",
        NOW - 1,
        &[&["name", "Relay says"]],
    );
    assert_eq!(
        AcceptedMetadataEdit::by_administrator(relay_signed, &roster, &relay).err(),
        Some(MetadataAuthorizationError::EditorNotAdministrator)
    );

    let state = state();
    assert!(state.group("omarchy").is_none());
    assert_eq!(state.input_count(), 0);
}

#[test]
fn partial_edit_preserves_unrelated_fields_with_provenance() {
    let mut state = state();
    let base = snapshot(
        "omarchy",
        NOW - 50,
        &[
            &["name", "Omarchy"],
            &["about", "Linux talk"],
            &["private"],
            &["supported_kinds", "9"],
            &["parent", "linux"],
        ],
    );
    assert_eq!(
        state.observe_snapshot(&base).expect("snapshot"),
        MetadataApplyResult::Recorded
    );
    let rename = accepted(
        "omarchy",
        NOW - 10,
        &[&["name", "Omarchy Community"], &["public"]],
    );
    assert_eq!(
        state.apply_accepted(&rename).expect("edit"),
        MetadataApplyResult::Recorded
    );

    let group = state.group("omarchy").expect("group");
    assert_eq!(group.name(), "Omarchy Community");
    assert!(!group.is_private());
    assert_eq!(group.about(), "Linux talk");
    assert_eq!(group.supported_kinds(), [9]);
    assert_eq!(group.parent(), Some("linux"));
    assert!(group.children().is_empty());

    let name_source = group.provenance("name").expect("name provenance");
    assert_eq!(name_source.source_event_id(), rename.edit().event().id);
    assert_eq!(name_source.author(), pubkey(&MODERATOR_SECRET));
    assert_eq!(
        name_source.authority(),
        &RevisionAuthority::Administrator {
            roles: vec!["moderator".to_owned()]
        }
    );
    let about_source = group.provenance("about").expect("about provenance");
    assert_eq!(about_source.source_event_id(), base.event().id);
    assert_eq!(about_source.authority(), &RevisionAuthority::RelaySnapshot);
    assert!(state.rejected().is_empty());
}

#[test]
fn duplicate_delivery_is_idempotent() {
    let mut state = state();
    let change = accepted("omarchy", NOW - 10, &[&["name", "Once"]]);
    assert_eq!(
        state.apply_accepted(&change).expect("first"),
        MetadataApplyResult::Recorded
    );
    let before = state.clone();
    assert_eq!(
        state.apply_accepted(&change).expect("again"),
        MetadataApplyResult::Duplicate
    );
    assert_eq!(state, before);
    assert_eq!(state.input_count(), 1);
}

#[test]
fn conflicting_edits_resolve_deterministically_regardless_of_order() {
    let first = accepted(
        "omarchy",
        NOW - 20,
        &[&["name", "First"], &["about", "kept"]],
    );
    let second = accepted("omarchy", NOW - 10, &[&["name", "Second"]]);
    let tie_a = accepted("omarchy", NOW - 5, &[&["picture", "https://a.test/p"]]);
    let tie_b = accepted(
        "omarchy",
        NOW - 5,
        &[&["picture", "https://b.test/p"], &["closed"]],
    );
    let inputs = [&first, &second, &tie_a, &tie_b];

    let mut states = Vec::new();
    for order in [[0, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2]] {
        let mut state = state();
        for index in order {
            state.apply_accepted(inputs[index]).expect("apply");
        }
        states.push(state);
    }
    assert_eq!(states[0], states[1]);
    assert_eq!(states[1], states[2]);

    let group = states[0].group("omarchy").expect("group");
    assert_eq!(group.name(), "Second");
    assert_eq!(group.about(), "kept");
    assert!(group.is_closed());
    // Equal timestamps: the higher event ID folds later and wins the field.
    let winner = if tie_a.edit().event().id > tie_b.edit().event().id {
        &tie_a
    } else {
        &tie_b
    };
    assert_eq!(
        group
            .provenance("picture")
            .expect("picture")
            .source_event_id(),
        winner.edit().event().id
    );
}

#[test]
fn two_room_and_multi_level_cycles_are_rejected_in_any_order() {
    // linux <- omarchy <- install-help ; then install-help tries to adopt linux.
    let a = accepted("omarchy", NOW - 30, &[&["parent", "linux"]]);
    let b = accepted("install-help", NOW - 20, &[&["parent", "omarchy"]]);
    let cycle = accepted("linux", NOW - 10, &[&["parent", "install-help"]]);
    let child_cycle = accepted("install-help", NOW - 5, &[&["child", "linux"]]);
    let inputs = [&a, &b, &cycle, &child_cycle];

    let mut states = Vec::new();
    for order in [[0, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1]] {
        let mut state = state();
        for index in order {
            state.apply_accepted(inputs[index]).expect("apply");
        }
        states.push(state);
    }
    assert_eq!(states[0], states[1]);
    assert_eq!(states[1], states[2]);

    let state = &states[0];
    assert_eq!(
        state.group("omarchy").expect("omarchy").parent(),
        Some("linux")
    );
    assert_eq!(
        state.group("install-help").expect("install-help").parent(),
        Some("omarchy")
    );
    // The only input for linux was rejected, so it has no reduced revision.
    assert!(state.group("linux").is_none());
    assert!(
        state
            .group("install-help")
            .expect("install-help")
            .children()
            .is_empty()
    );
    let rejected = state.rejected();
    assert_eq!(rejected.len(), 2);
    assert_eq!(rejected[0].source_event_id, cycle.edit().event().id);
    assert_eq!(rejected[0].group_id, "linux");
    assert_eq!(rejected[0].reason, HierarchyRejection::Cycle);
    assert_eq!(rejected[1].source_event_id, child_cycle.edit().event().id);
    assert_eq!(rejected[1].reason, HierarchyRejection::Cycle);

    // Two-room cycle through mixed parent and child links.
    let mut two = self::state();
    two.apply_accepted(&accepted("a", NOW - 3, &[&["child", "b"]]))
        .expect("a adopts b");
    two.apply_accepted(&accepted("a", NOW - 2, &[&["parent", "b"]]))
        .expect("recorded");
    assert_eq!(two.group("a").expect("a").parent(), None);
    assert_eq!(two.rejected().len(), 1);
    assert_eq!(two.rejected()[0].reason, HierarchyRejection::Cycle);

    // Removing the offending link later makes a formerly rejected edit fold in.
    two.apply_accepted(&accepted("a", NOW - 1, &[&["child"]]))
        .expect("clear children");
    assert_eq!(two.rejected().len(), 1);
    two.apply_accepted(&accepted("a", NOW, &[&["parent", "b"]]))
        .expect("retry");
    assert_eq!(two.group("a").expect("a").parent(), Some("b"));
}

#[test]
fn cross_relay_inputs_are_rejected() {
    let relay = pubkey(&RELAY_SECRET);
    let other_relay = pubkey(&OTHER_RELAY_SECRET);
    assert_eq!(
        RelayMetadataState::new("relay".to_owned()).err(),
        Some(MetadataStateError::InvalidRelayPublicKey)
    );

    let mut state = state();
    let foreign_edit = AcceptedMetadataEdit::by_administrator(
        edit(
            &MODERATOR_SECRET,
            "omarchy",
            NOW - 1,
            &[&["parent", "linux"]],
        ),
        &admins(&OTHER_RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET)),
        &other_relay,
    )
    .expect("accepted under the other relay");
    assert_eq!(
        state.apply_accepted(&foreign_edit).err(),
        Some(MetadataStateError::RelayMismatch)
    );

    let foreign_snapshot = GroupMetadata::verify(
        signed(
            &OTHER_RELAY_SECRET,
            NOW - 1,
            39000,
            vec![tag(&["d", "omarchy"]), tag(&["parent", "linux"])],
        ),
        &other_relay,
        NOW,
        &limits(),
    )
    .expect("foreign snapshot");
    assert_eq!(
        state.observe_snapshot(&foreign_snapshot).err(),
        Some(MetadataStateError::RelayMismatch)
    );
    assert_eq!(state.input_count(), 0);
    assert_eq!(state.relay_pubkey(), relay);
    assert_eq!(state.group_ids().count(), 0);
}
