use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    nip29_lifecycle::{
        AcceptedLifecycleAction, CREATE_GROUP_KIND, CREATE_INVITE_KIND, DELETE_GROUP_KIND,
        GroupLifecycleRequest, GroupStatus, LifecycleAction, LifecycleApplyResult,
        LifecycleAuthority, LifecycleAuthorizationError, LifecycleRejection, LifecycleRequestError,
        LifecycleStateError, RelayLifecycleState, create_group_request, create_invite_request,
        delete_group_request,
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

fn sign(unsigned: UnsignedEvent, secret: &[u8; 32]) -> SignedEvent {
    unsigned
        .sign_with_aux(secret, &[3; 32], &limits())
        .expect("signed")
}

fn signed(secret: &[u8; 32], created_at: u64, kind: u32, tags: Vec<Vec<String>>) -> SignedEvent {
    sign(
        UnsignedEvent::new(
            pubkey(secret),
            created_at,
            kind,
            tags,
            String::new(),
            &limits(),
        )
        .expect("event"),
        secret,
    )
}

fn verify(event: SignedEvent) -> Result<GroupLifecycleRequest, LifecycleRequestError> {
    GroupLifecycleRequest::verify(event, NOW, &limits())
}

fn create(secret: &[u8; 32], group: &str, created_at: u64) -> GroupLifecycleRequest {
    verify(sign(
        create_group_request(pubkey(secret), created_at, group, &limits()).expect("build"),
        secret,
    ))
    .expect("create request")
}

fn delete(secret: &[u8; 32], group: &str, created_at: u64) -> GroupLifecycleRequest {
    verify(sign(
        delete_group_request(pubkey(secret), created_at, group, &limits()).expect("build"),
        secret,
    ))
    .expect("delete request")
}

fn invite(secret: &[u8; 32], group: &str, created_at: u64, code: &str) -> GroupLifecycleRequest {
    verify(sign(
        create_invite_request(pubkey(secret), created_at, group, code, &limits()).expect("build"),
        secret,
    ))
    .expect("invite request")
}

fn accepted(request: GroupLifecycleRequest) -> AcceptedLifecycleAction {
    AcceptedLifecycleAction::from_authoritative_relay(request, &pubkey(&RELAY_SECRET))
        .expect("accepted creation")
}

fn state() -> RelayLifecycleState {
    RelayLifecycleState::new(pubkey(&RELAY_SECRET)).expect("state")
}

#[test]
fn requests_round_trip_and_keep_their_author() {
    let creation = create(&AGENT_SECRET, "omarchy", NOW - 3);
    assert_eq!(creation.event().kind, CREATE_GROUP_KIND);
    assert_eq!(creation.author(), pubkey(&AGENT_SECRET));
    assert_eq!(creation.group_id(), "omarchy");
    assert_eq!(creation.action(), &LifecycleAction::CreateGroup);

    let deletion = delete(&MODERATOR_SECRET, "omarchy", NOW - 2);
    assert_eq!(deletion.event().kind, DELETE_GROUP_KIND);
    assert_eq!(deletion.action(), &LifecycleAction::DeleteGroup);

    let invitation = invite(&MODERATOR_SECRET, "omarchy", NOW - 1, "welcome-2026");
    assert_eq!(invitation.event().kind, CREATE_INVITE_KIND);
    assert_eq!(
        invitation.action(),
        &LifecycleAction::CreateInvite {
            code: "welcome-2026".to_owned()
        }
    );
    assert!(invitation.previous().is_empty());
}

#[test]
fn malformed_and_forged_requests_fail_closed() {
    let h = || tag(&["h", "omarchy"]);
    assert!(matches!(
        verify(signed(&AGENT_SECRET, NOW, 9005, vec![h()])),
        Err(LifecycleRequestError::UnsupportedKind(9005))
    ));
    assert!(matches!(
        verify(signed(&AGENT_SECRET, NOW, CREATE_GROUP_KIND, vec![])),
        Err(LifecycleRequestError::MissingGroupId)
    ));
    assert!(matches!(
        verify(signed(
            &AGENT_SECRET,
            NOW,
            CREATE_GROUP_KIND,
            vec![tag(&["h", ""])]
        )),
        Err(LifecycleRequestError::EmptyGroupId)
    ));
    assert!(matches!(
        verify(signed(
            &AGENT_SECRET,
            NOW,
            CREATE_GROUP_KIND,
            vec![tag(&["h", "relay.other.test'omarchy"])]
        )),
        Err(LifecycleRequestError::HostQualifiedGroupId)
    ));
    assert!(matches!(
        verify(signed(
            &AGENT_SECRET,
            NOW,
            CREATE_GROUP_KIND,
            vec![tag(&["h", "om archy"])]
        )),
        Err(LifecycleRequestError::InvalidGroupId)
    ));
    assert!(matches!(
        verify(signed(
            &AGENT_SECRET,
            NOW,
            CREATE_GROUP_KIND,
            vec![h(), tag(&["h", "other"])]
        )),
        Err(LifecycleRequestError::DuplicateTag("h"))
    ));
    assert!(matches!(
        verify(signed(
            &AGENT_SECRET,
            NOW,
            DELETE_GROUP_KIND,
            vec![h(), tag(&["code", "x"])]
        )),
        Err(LifecycleRequestError::CodeOutsideInvite)
    ));
    assert!(matches!(
        verify(signed(&AGENT_SECRET, NOW, CREATE_INVITE_KIND, vec![h()])),
        Err(LifecycleRequestError::MissingInviteCode)
    ));
    assert!(matches!(
        verify(signed(
            &AGENT_SECRET,
            NOW,
            CREATE_INVITE_KIND,
            vec![h(), tag(&["code", ""])]
        )),
        Err(LifecycleRequestError::EmptyInviteCode)
    ));
    assert!(matches!(
        verify(signed(
            &AGENT_SECRET,
            NOW,
            CREATE_INVITE_KIND,
            vec![h(), tag(&["code", "a", "b"])]
        )),
        Err(LifecycleRequestError::MalformedTag("code"))
    ));
    assert!(matches!(
        create_invite_request(pubkey(&AGENT_SECRET), NOW, "omarchy", "", &limits()),
        Err(LifecycleRequestError::EmptyInviteCode)
    ));

    // A forged invitation: tampered after signing.
    let mut forged = invite(&MODERATOR_SECRET, "omarchy", NOW - 1, "real")
        .event()
        .clone();
    forged.tags[1][1] = "forged".to_owned();
    assert!(matches!(
        verify(forged),
        Err(LifecycleRequestError::Event(_))
    ));
}

#[test]
fn signed_actions_remain_inert_without_explicit_relay_policy_acceptance() {
    let relay = pubkey(&RELAY_SECRET);
    let request = create(&AGENT_SECRET, "omarchy", NOW - 3);
    assert_eq!(
        AcceptedLifecycleAction::from_authoritative_relay(request.clone(), "not-a-relay").err(),
        Some(LifecycleAuthorizationError::InvalidRelayPublicKey)
    );

    let mut state = state();
    assert_eq!(state.status("omarchy"), None);
    assert_eq!(state.input_count(), 0);
    assert_eq!(
        state.require_active("omarchy").err(),
        Some(LifecycleStateError::GroupUnknown)
    );

    state.apply_accepted(
        &AcceptedLifecycleAction::from_authoritative_relay(request, &relay)
            .expect("relay accepted exact request"),
    )
    .expect("apply");
    assert_eq!(state.status("omarchy"), Some(GroupStatus::Active));
}

#[test]
fn creation_is_idempotent_and_conflicts_resolve_deterministically() {
    let first = accepted(create(&AGENT_SECRET, "omarchy", NOW - 3));
    let rival = accepted(create(&MODERATOR_SECRET, "omarchy", NOW - 2));

    let mut state = state();
    assert_eq!(
        state.apply_accepted(&first).expect("first"),
        LifecycleApplyResult::Recorded
    );
    let before = state.clone();
    assert_eq!(
        state.apply_accepted(&first).expect("again"),
        LifecycleApplyResult::Duplicate
    );
    assert_eq!(state, before);

    let mut reversed = self::state();
    reversed.apply_accepted(&rival).expect("rival first");
    reversed.apply_accepted(&first).expect("then first");
    state.apply_accepted(&rival).expect("rival second");
    assert_eq!(state, reversed);

    let group = state.group("omarchy").expect("group");
    assert_eq!(group.status(), GroupStatus::Active);
    assert_eq!(group.creation().author(), pubkey(&AGENT_SECRET));
    assert_eq!(
        group.creation().source_event_id(),
        first.request().event().id
    );
    assert_eq!(
        group.creation().authority(),
        &LifecycleAuthority::AuthoritativeRelay
    );
    assert_eq!(state.rejected().len(), 1);
    assert_eq!(
        state.rejected()[0].source_event_id,
        rival.request().event().id
    );
    assert_eq!(
        state.rejected()[0].reason,
        LifecycleRejection::AlreadyActive
    );
}

#[test]
fn accepted_deletion_is_terminal_and_preserves_history() {
    let creation = accepted(create(&AGENT_SECRET, "omarchy", NOW - 5));
    let code = accepted(invite(&MODERATOR_SECRET, "omarchy", NOW - 4, "early"));
    let deletion = accepted(delete(&MODERATOR_SECRET, "omarchy", NOW - 3));
    let late_invite = accepted(invite(&MODERATOR_SECRET, "omarchy", NOW - 2, "late"));
    let recreate = accepted(create(&AGENT_SECRET, "omarchy", NOW - 1));

    let mut state = state();
    for action in [&creation, &code, &deletion, &late_invite, &recreate] {
        assert_eq!(
            state.apply_accepted(action).expect("recorded"),
            LifecycleApplyResult::Recorded
        );
    }

    let group = state.group("omarchy").expect("group");
    assert_eq!(group.status(), GroupStatus::Deleted);
    assert_eq!(state.status("omarchy"), Some(GroupStatus::Deleted));
    assert_eq!(
        state.require_active("omarchy").err(),
        Some(LifecycleStateError::GroupDeleted)
    );
    // History survives: creation, the early invite, and the deletion itself.
    assert_eq!(group.creation().author(), pubkey(&AGENT_SECRET));
    assert_eq!(
        group.deletion().expect("deletion").source_event_id(),
        deletion.request().event().id
    );
    assert_eq!(
        group.deletion().expect("deletion").authority(),
        &LifecycleAuthority::AuthoritativeRelay
    );
    assert!(group.invites().contains_key("early"));
    // But nothing after deletion is honoured, and invites stop resolving.
    assert!(state.invite("omarchy", "early").is_none());
    assert!(!group.invites().contains_key("late"));
    let rejected = state.rejected();
    assert_eq!(rejected.len(), 2);
    assert_eq!(
        rejected[0].source_event_id,
        late_invite.request().event().id
    );
    assert_eq!(rejected[0].reason, LifecycleRejection::GroupDeleted);
    assert_eq!(rejected[1].source_event_id, recreate.request().event().id);
    assert_eq!(rejected[1].reason, LifecycleRejection::GroupDeleted);
    assert_eq!(state.input_count(), 5);
}

#[test]
fn invitations_are_scoped_and_are_not_membership() {
    let mut state = state();
    state
        .apply_accepted(&accepted(create(
            &AGENT_SECRET,
            "omarchy",
            NOW - 5,
        )))
        .expect("create");
    let issued = accepted(invite(&MODERATOR_SECRET, "omarchy", NOW - 4, "welcome"));
    state.apply_accepted(&issued).expect("invite");
    let repeat = accepted(invite(&MODERATOR_SECRET, "omarchy", NOW - 3, "welcome"));
    state.apply_accepted(&repeat).expect("recorded");

    let record = state.invite("omarchy", "welcome").expect("invite");
    assert_eq!(record.code(), "welcome");
    assert_eq!(record.provenance().author(), pubkey(&MODERATOR_SECRET));
    assert_eq!(
        record.provenance().source_event_id(),
        issued.request().event().id
    );
    // Same code, different group or relay: no match.
    assert!(state.invite("other", "welcome").is_none());
    assert!(state.invite("omarchy", "WELCOME").is_none());
    // Re-issuing an identical code is recorded as rejected, first issue stands.
    assert_eq!(state.rejected().len(), 1);
    assert_eq!(
        state.rejected()[0].reason,
        LifecycleRejection::DuplicateInviteCode
    );
    // Invitations do not create members: lifecycle state has no roster at all,
    // and the invite record names only its issuer.
    assert_ne!(record.provenance().author(), pubkey(&AGENT_SECRET));

    // Deleting or inviting into an unknown group fails closed.
    state
        .apply_accepted(&accepted(delete(&MODERATOR_SECRET, "ghost", NOW - 2)))
        .expect("recorded");
    state
        .apply_accepted(&accepted(invite(
            &MODERATOR_SECRET,
            "ghost",
            NOW - 1,
            "boo",
        )))
        .expect("recorded");
    assert!(state.group("ghost").is_none());
    assert_eq!(state.rejected().len(), 3);
    assert!(
        state.rejected()[1..]
            .iter()
            .all(|rejected| rejected.reason == LifecycleRejection::GroupUnknown)
    );
}

#[test]
fn multi_relay_duplicates_and_foreign_relays_are_handled() {
    let relay = pubkey(&RELAY_SECRET);
    let other_relay = pubkey(&OTHER_RELAY_SECRET);
    assert_eq!(
        RelayLifecycleState::new("relay".to_owned()).err(),
        Some(LifecycleStateError::InvalidRelayPublicKey)
    );

    let request = create(&AGENT_SECRET, "omarchy", NOW - 3);
    let via_primary = accepted(request.clone());
    let via_mirror = accepted(request.clone());
    let mut state = state();
    state.apply_accepted(&via_primary).expect("first");
    let before = state.clone();
    assert_eq!(
        state.apply_accepted(&via_mirror).expect("mirror"),
        LifecycleApplyResult::Duplicate
    );
    assert_eq!(state, before);

    let foreign = AcceptedLifecycleAction::from_authoritative_relay(request, &other_relay)
    .expect("accepted elsewhere");
    assert_eq!(
        state.apply_accepted(&foreign).err(),
        Some(LifecycleStateError::RelayMismatch)
    );
    assert_eq!(state, before);
    assert_eq!(state.relay_pubkey(), relay);
    assert_eq!(state.group_ids().collect::<Vec<_>>(), ["omarchy"]);
}

#[test]
fn reduction_is_independent_of_ingestion_order() {
    let inputs = [
        accepted(create(&AGENT_SECRET, "omarchy", NOW - 9)),
        accepted(invite(&MODERATOR_SECRET, "omarchy", NOW - 8, "a")),
        accepted(create(&MODERATOR_SECRET, "omarchy", NOW - 7)),
        accepted(create(&AGENT_SECRET, "linux", NOW - 6)),
        accepted(delete(&MODERATOR_SECRET, "omarchy", NOW - 5)),
        accepted(invite(&MODERATOR_SECRET, "omarchy", NOW - 4, "b")),
        accepted(invite(&AGENT_SECRET, "linux", NOW - 3, "c")),
        accepted(create(&AGENT_SECRET, "omarchy", NOW - 2)),
    ];
    let orders = [
        [0, 1, 2, 3, 4, 5, 6, 7],
        [7, 6, 5, 4, 3, 2, 1, 0],
        [4, 0, 7, 3, 1, 6, 2, 5],
    ];
    let states = orders
        .iter()
        .map(|order| {
            let mut state = state();
            for index in order {
                state.apply_accepted(&inputs[*index]).expect("apply");
            }
            state
        })
        .collect::<Vec<_>>();
    assert_eq!(states[0], states[1]);
    assert_eq!(states[1], states[2]);

    let state = &states[0];
    assert_eq!(state.status("omarchy"), Some(GroupStatus::Deleted));
    assert_eq!(state.status("linux"), Some(GroupStatus::Active));
    assert!(state.invite("linux", "c").is_some());
    assert!(state.invite("omarchy", "a").is_none());
    assert_eq!(state.rejected().len(), 3);
}
