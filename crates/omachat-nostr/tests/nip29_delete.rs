use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    nip29::{GroupRoster, GroupUserEvent, group_message},
    nip29_delete::{
        AcceptedGroupDeletion, DELETE_EVENT_KIND, DeletionApplyResult, DeletionAuthority,
        DeletionAuthorizationError, DeletionStateError, GroupDeleteError, GroupDeleteRequest,
        GroupDeletionState, delete_event_request,
    },
};

const NOW: u64 = 1_800_000_000;
const RELAY_SECRET: [u8; 32] = [5; 32];
const MODERATOR_SECRET: [u8; 32] = [7; 32];
const AGENT_SECRET: [u8; 32] = [9; 32];
const OTHER_RELAY_SECRET: [u8; 32] = [11; 32];
const HUMAN_SECRET: [u8; 32] = [13; 32];
const TARGET_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn limits() -> EventLimits {
    EventLimits::default()
}

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("valid key"))
}

fn sign(unsigned: UnsignedEvent, secret: &[u8; 32]) -> SignedEvent {
    unsigned
        .sign_with_aux(secret, &[3; 32], &limits())
        .expect("signed event")
}

fn signed(secret: &[u8; 32], created_at: u64, kind: u32, tags: Vec<Vec<String>>) -> SignedEvent {
    sign(
        UnsignedEvent::new(
            pubkey(secret),
            created_at,
            kind,
            tags,
            "spam".to_owned(),
            &limits(),
        )
        .expect("event"),
        secret,
    )
}

fn message(secret: &[u8; 32], group_id: &str, created_at: u64) -> GroupUserEvent {
    let unsigned = group_message(
        pubkey(secret),
        created_at,
        group_id,
        "hello".to_owned(),
        &[],
        &limits(),
    )
    .expect("message");
    GroupUserEvent::verify(sign(unsigned, secret), NOW, &limits()).expect("verified message")
}

fn request_in(
    secret: &[u8; 32],
    group_id: &str,
    created_at: u64,
    targets: &[&str],
) -> GroupDeleteRequest {
    let unsigned = delete_event_request(
        pubkey(secret),
        created_at,
        group_id,
        &targets.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>(),
        "spam".to_owned(),
        &["eb96c864".to_owned()],
        &limits(),
    )
    .expect("delete request");
    GroupDeleteRequest::verify(sign(unsigned, secret), NOW, &limits()).expect("verified request")
}

fn request(secret: &[u8; 32], created_at: u64, targets: &[&str]) -> GroupDeleteRequest {
    request_in(secret, "omarchy", created_at, targets)
}

fn admins(relay_secret: &[u8; 32], group_id: &str, admin: &str) -> GroupRoster {
    let event = signed(
        relay_secret,
        NOW - 10,
        39001,
        vec![
            vec!["d".to_owned(), group_id.to_owned()],
            vec!["p".to_owned(), admin.to_owned(), "moderator".to_owned()],
        ],
    );
    GroupRoster::verify(event, &pubkey(relay_secret), NOW, &limits()).expect("admin roster")
}

#[test]
fn built_request_round_trips_and_keeps_its_author() {
    let parsed = request(&AGENT_SECRET, NOW - 1, &[TARGET_B, TARGET_A]);

    assert_eq!(parsed.event().kind, DELETE_EVENT_KIND);
    assert_eq!(parsed.author(), pubkey(&AGENT_SECRET));
    assert_eq!(parsed.group_id(), "omarchy");
    assert_eq!(parsed.targets(), [TARGET_B, TARGET_A]);
    assert_eq!(parsed.reason(), Some("spam"));
    assert_eq!(parsed.previous(), ["eb96c864"]);
}

#[test]
fn tampered_signature_is_rejected_regardless_of_origin() {
    let mut event = request(&MODERATOR_SECRET, NOW - 1, &[TARGET_A])
        .event()
        .clone();
    event.content = "edited after signing".to_owned();
    assert!(matches!(
        GroupDeleteRequest::verify(event.clone(), NOW, &limits()),
        Err(GroupDeleteError::Event(_))
    ));

    // Re-signing under the relay key does not launder the request either: it
    // becomes the relay's own request and is judged on that author.
    let relayed = signed(
        &RELAY_SECRET,
        NOW - 1,
        DELETE_EVENT_KIND,
        event.tags.clone(),
    );
    let relayed = GroupDeleteRequest::verify(relayed, NOW, &limits()).expect("relay-signed");
    assert_eq!(relayed.author(), pubkey(&RELAY_SECRET));
    assert_ne!(relayed.author(), pubkey(&MODERATOR_SECRET));
}

#[test]
fn malformed_requests_fail_closed() {
    let h = || vec!["h".to_owned(), "omarchy".to_owned()];
    let e = |id: &str| vec!["e".to_owned(), id.to_owned()];
    let verify = |tags: Vec<Vec<String>>| {
        GroupDeleteRequest::verify(
            signed(&MODERATOR_SECRET, NOW, DELETE_EVENT_KIND, tags),
            NOW,
            &limits(),
        )
    };

    assert!(matches!(
        GroupDeleteRequest::verify(
            signed(&MODERATOR_SECRET, NOW, 9001, vec![h(), e(TARGET_A)]),
            NOW,
            &limits()
        ),
        Err(GroupDeleteError::UnsupportedKind(9001))
    ));
    assert!(matches!(
        verify(vec![e(TARGET_A)]),
        Err(GroupDeleteError::MissingGroupId)
    ));
    assert!(matches!(
        verify(vec![vec!["h".to_owned(), String::new()], e(TARGET_A)]),
        Err(GroupDeleteError::EmptyGroupId)
    ));
    assert!(matches!(
        verify(vec![
            h(),
            vec!["h".to_owned(), "other".to_owned()],
            e(TARGET_A)
        ]),
        Err(GroupDeleteError::DuplicateTag("h"))
    ));
    assert!(matches!(
        verify(vec![
            vec!["h".to_owned(), "omarchy".to_owned(), "extra".to_owned()],
            e(TARGET_A)
        ]),
        Err(GroupDeleteError::MalformedTag("h"))
    ));
    assert!(matches!(
        verify(vec![h()]),
        Err(GroupDeleteError::MissingTarget)
    ));
    assert!(matches!(
        verify(vec![h(), e(TARGET_A), e(TARGET_A)]),
        Err(GroupDeleteError::DuplicateTarget)
    ));
    assert!(matches!(
        verify(vec![
            h(),
            vec![
                "e".to_owned(),
                TARGET_A.to_owned(),
                "wss://relay.example".to_owned()
            ]
        ]),
        Err(GroupDeleteError::MalformedTag("e"))
    ));
    for bad in ["not-an-event", &TARGET_A.to_uppercase(), &TARGET_A[..63]] {
        assert!(matches!(
            verify(vec![h(), e(bad)]),
            Err(GroupDeleteError::InvalidEventId)
        ));
    }
    assert!(matches!(
        verify(vec![
            h(),
            e(TARGET_A),
            vec!["previous".to_owned(), "xyz".to_owned()]
        ]),
        Err(GroupDeleteError::InvalidTimelineReference)
    ));

    let build = |group: &str, targets: &[&str]| {
        delete_event_request(
            pubkey(&MODERATOR_SECRET),
            NOW,
            group,
            &targets.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>(),
            String::new(),
            &[],
            &limits(),
        )
    };
    assert!(matches!(
        build("", &[TARGET_A]),
        Err(GroupDeleteError::EmptyGroupId)
    ));
    assert!(matches!(
        build("omarchy", &[]),
        Err(GroupDeleteError::MissingTarget)
    ));
    assert!(matches!(
        build("omarchy", &[TARGET_A, TARGET_A]),
        Err(GroupDeleteError::DuplicateTarget)
    ));
}

#[test]
fn unauthorized_requests_never_become_accepted_state() {
    let relay = pubkey(&RELAY_SECRET);
    let human_message = message(&HUMAN_SECRET, "omarchy", NOW - 5);
    let agent_request = request(&AGENT_SECRET, NOW - 1, &[&human_message.event().id]);
    let roster = admins(&RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET));

    // The agent is neither the author of the target nor a listed admin.
    assert_eq!(
        AcceptedGroupDeletion::by_target_author(
            agent_request.clone(),
            std::slice::from_ref(&human_message),
            &relay
        )
        .err(),
        Some(DeletionAuthorizationError::TargetNotAuthoredByRequester)
    );
    assert_eq!(
        AcceptedGroupDeletion::by_administrator(agent_request.clone(), &roster, &relay).err(),
        Some(DeletionAuthorizationError::RequesterNotAdministrator)
    );

    // Missing target evidence fails closed rather than trusting the ID.
    assert_eq!(
        AcceptedGroupDeletion::by_target_author(agent_request.clone(), &[], &relay).err(),
        Some(DeletionAuthorizationError::MissingTargetEvidence)
    );

    // A published member list is not moderation authority.
    let members = GroupRoster::verify(
        signed(
            &RELAY_SECRET,
            NOW - 10,
            39002,
            vec![
                vec!["d".to_owned(), "omarchy".to_owned()],
                vec!["p".to_owned(), pubkey(&AGENT_SECRET)],
            ],
        ),
        &relay,
        NOW,
        &limits(),
    )
    .expect("member roster");
    assert_eq!(
        AcceptedGroupDeletion::by_administrator(agent_request.clone(), &members, &relay).err(),
        Some(DeletionAuthorizationError::NotAdministratorRoster)
    );

    // An admin roster from another relay, or for another group, proves nothing here.
    let foreign = admins(&OTHER_RELAY_SECRET, "omarchy", &pubkey(&AGENT_SECRET));
    assert_eq!(
        AcceptedGroupDeletion::by_administrator(agent_request.clone(), &foreign, &relay).err(),
        Some(DeletionAuthorizationError::RosterRelayMismatch)
    );
    let other_group = admins(&RELAY_SECRET, "other", &pubkey(&AGENT_SECRET));
    assert_eq!(
        AcceptedGroupDeletion::by_administrator(agent_request, &other_group, &relay).err(),
        Some(DeletionAuthorizationError::RosterGroupMismatch)
    );

    let state = GroupDeletionState::new(relay, "omarchy".to_owned()).expect("state");
    assert!(state.is_empty());
    assert!(!state.is_deleted(&human_message.event().id));
}

#[test]
fn cross_group_targets_are_rejected() {
    let relay = pubkey(&RELAY_SECRET);
    let elsewhere = message(&AGENT_SECRET, "other-room", NOW - 5);
    let request = request(&AGENT_SECRET, NOW - 1, &[&elsewhere.event().id]);

    assert_eq!(
        AcceptedGroupDeletion::by_target_author(request, std::slice::from_ref(&elsewhere), &relay)
            .err(),
        Some(DeletionAuthorizationError::CrossGroupTarget)
    );
}

#[test]
fn authorized_deletions_mark_targets_and_preserve_provenance() {
    let relay = pubkey(&RELAY_SECRET);
    let own = message(&AGENT_SECRET, "omarchy", NOW - 6);
    let human = message(&HUMAN_SECRET, "omarchy", NOW - 5);
    let own_id = own.event().id.clone();
    let human_id = human.event().id.clone();
    let original_human = human.event().clone();

    let self_delete = AcceptedGroupDeletion::by_target_author(
        request(&AGENT_SECRET, NOW - 2, &[&own_id]),
        std::slice::from_ref(&own),
        &relay,
    )
    .expect("author may delete own message");
    let roster = admins(&RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET));
    let moderation = AcceptedGroupDeletion::by_administrator(
        request(&MODERATOR_SECRET, NOW - 1, &[&human_id, &own_id]),
        &roster,
        &relay,
    )
    .expect("listed admin may delete");
    assert_eq!(
        moderation.authority(),
        &DeletionAuthority::Administrator {
            roles: vec!["moderator".to_owned()]
        }
    );

    let mut state = GroupDeletionState::new(relay.clone(), "omarchy".to_owned()).expect("state");
    assert_eq!(
        state.apply_accepted(&self_delete).expect("self delete"),
        DeletionApplyResult {
            newly_deleted: 1,
            already_deleted: 0
        }
    );
    assert_eq!(
        state.apply_accepted(&moderation).expect("moderation"),
        DeletionApplyResult {
            newly_deleted: 1,
            already_deleted: 1
        }
    );
    assert!(state.is_deleted(&own_id));
    assert!(state.is_deleted(&human_id));
    assert_eq!(state.len(), 2);

    // The earliest accepted request keeps the record; provenance is complete.
    let record = state.record(&own_id).expect("record");
    assert_eq!(record.event_id(), own_id);
    assert_eq!(record.requester_pubkey(), pubkey(&AGENT_SECRET));
    assert_eq!(record.source_event_id(), self_delete.request().event().id);
    assert_eq!(record.created_at(), NOW - 2);
    assert_eq!(record.authority(), &DeletionAuthority::TargetAuthor);
    assert_eq!(state.relay_pubkey(), relay);
    assert_eq!(state.group_id(), "omarchy");
    let record = state.record(&human_id).expect("record");
    assert_eq!(record.requester_pubkey(), pubkey(&MODERATOR_SECRET));
    assert_eq!(record.source_event_id(), moderation.request().event().id);

    // Deletion is state; the historical event and its authorship are untouched.
    assert_eq!(human.event(), &original_human);
    assert_eq!(human.author(), pubkey(&HUMAN_SECRET));
    assert!(human.event().verify(NOW, &limits()).is_ok());
}

#[test]
fn replay_and_multi_relay_delivery_reduce_once() {
    let relay = pubkey(&RELAY_SECRET);
    let other_relay = pubkey(&OTHER_RELAY_SECRET);
    let roster = admins(&RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET));
    let request = request(&MODERATOR_SECRET, NOW - 1, &[TARGET_A, TARGET_B]);

    let via_primary =
        AcceptedGroupDeletion::by_administrator(request.clone(), &roster, &relay).expect("accept");
    // The same signed request seen again through another relay path carries the
    // same event ID and the same acceptance evidence.
    let via_mirror =
        AcceptedGroupDeletion::by_administrator(request.clone(), &roster, &relay).expect("accept");

    let mut state = GroupDeletionState::new(relay.clone(), "omarchy".to_owned()).expect("state");
    assert_eq!(
        state.apply_accepted(&via_primary).expect("first"),
        DeletionApplyResult {
            newly_deleted: 2,
            already_deleted: 0
        }
    );
    let before = state.clone();
    assert_eq!(
        state.apply_accepted(&via_mirror).expect("duplicate"),
        DeletionApplyResult {
            newly_deleted: 0,
            already_deleted: 2
        }
    );
    assert_eq!(state, before);

    // Acceptance under another relay's policy is not this room's policy.
    let foreign_roster = admins(&OTHER_RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET));
    let foreign = AcceptedGroupDeletion::by_administrator(request, &foreign_roster, &other_relay)
        .expect("accepted elsewhere");
    assert_eq!(
        state.apply_accepted(&foreign).err(),
        Some(DeletionStateError::RelayMismatch)
    );
    assert_eq!(state, before);
}

#[test]
fn reduction_is_independent_of_ingestion_order() {
    let relay = pubkey(&RELAY_SECRET);
    let roster = admins(&RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET));
    let own = message(&AGENT_SECRET, "omarchy", NOW - 6);
    let own_id = own.event().id.clone();

    let earlier = AcceptedGroupDeletion::by_target_author(
        request(&AGENT_SECRET, NOW - 2, &[&own_id]),
        std::slice::from_ref(&own),
        &relay,
    )
    .expect("author");
    let later = AcceptedGroupDeletion::by_administrator(
        request(&MODERATOR_SECRET, NOW - 1, &[&own_id, TARGET_B]),
        &roster,
        &relay,
    )
    .expect("admin");
    let same_second_a = AcceptedGroupDeletion::by_administrator(
        request(&MODERATOR_SECRET, NOW - 1, &[TARGET_A]),
        &roster,
        &relay,
    )
    .expect("admin");
    let same_second_b = AcceptedGroupDeletion::by_administrator(
        request_in(&MODERATOR_SECRET, "omarchy", NOW - 1, &[TARGET_A, TARGET_B]),
        &roster,
        &relay,
    )
    .expect("admin");

    let orders: [[&AcceptedGroupDeletion; 4]; 3] = [
        [&earlier, &later, &same_second_a, &same_second_b],
        [&same_second_b, &same_second_a, &later, &earlier],
        [&later, &same_second_b, &earlier, &same_second_a],
    ];
    let states = orders
        .iter()
        .map(|order| {
            let mut state =
                GroupDeletionState::new(relay.clone(), "omarchy".to_owned()).expect("state");
            for accepted in order {
                state.apply_accepted(accepted).expect("apply");
            }
            state
        })
        .collect::<Vec<_>>();
    assert_eq!(states[0], states[1]);
    assert_eq!(states[1], states[2]);

    let state = &states[0];
    let mut expected_ids = vec![TARGET_A, TARGET_B, own_id.as_str()];
    expected_ids.sort_unstable();
    assert_eq!(state.deleted_event_ids().collect::<Vec<_>>(), expected_ids);
    assert_eq!(
        state.record(&own_id).expect("own").authority(),
        &DeletionAuthority::TargetAuthor
    );
    // Equal timestamps resolve to the lowest request event ID.
    let expected = if same_second_a.request().event().id < same_second_b.request().event().id {
        &same_second_a
    } else {
        &same_second_b
    };
    assert_eq!(
        state.record(TARGET_A).expect("a").source_event_id(),
        expected.request().event().id
    );
}

#[test]
fn state_construction_and_scope_fail_closed() {
    let relay = pubkey(&RELAY_SECRET);
    assert_eq!(
        GroupDeletionState::new("relay".to_owned(), "omarchy".to_owned()).err(),
        Some(DeletionStateError::InvalidRelayPublicKey)
    );
    assert_eq!(
        GroupDeletionState::new(relay.clone(), String::new()).err(),
        Some(DeletionStateError::EmptyGroupId)
    );
    assert_eq!(
        AcceptedGroupDeletion::by_target_author(
            request(&AGENT_SECRET, NOW - 1, &[TARGET_A]),
            &[],
            "not-a-relay"
        )
        .err(),
        Some(DeletionAuthorizationError::InvalidRelayPublicKey)
    );

    let roster = admins(&RELAY_SECRET, "omarchy", &pubkey(&MODERATOR_SECRET));
    let accepted = AcceptedGroupDeletion::by_administrator(
        request(&MODERATOR_SECRET, NOW - 1, &[TARGET_A]),
        &roster,
        &relay,
    )
    .expect("accepted");
    let mut other_group = GroupDeletionState::new(relay, "other".to_owned()).expect("state");
    assert_eq!(
        other_group.apply_accepted(&accepted).err(),
        Some(DeletionStateError::GroupMismatch)
    );
    assert!(other_group.is_empty());
}
