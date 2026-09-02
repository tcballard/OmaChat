use omachat_nostr::{
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    nip29::GroupMembershipAction,
    nip29_state::{GroupMembershipState, MembershipApplyResult, MembershipStateError},
};

const NOW: u64 = 1_800_000_000;
const RELAY_SECRET: [u8; 32] = [5; 32];
const MODERATOR_SECRET: [u8; 32] = [7; 32];
const AGENT_SECRET: [u8; 32] = [9; 32];

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("valid key"))
}

fn action(
    kind: u32,
    group_id: &str,
    target: &str,
    roles: &[&str],
    created_at: u64,
    content: &str,
) -> GroupMembershipAction {
    let limits = EventLimits::default();
    let mut principal = vec!["p".to_owned(), target.to_owned()];
    principal.extend(roles.iter().map(|role| (*role).to_owned()));
    let unsigned = UnsignedEvent::new(
        pubkey(&MODERATOR_SECRET),
        created_at,
        kind,
        vec![vec!["h".to_owned(), group_id.to_owned()], principal],
        content.to_owned(),
        &limits,
    )
    .expect("membership event");
    let signed = unsigned
        .sign_with_aux(&MODERATOR_SECRET, &[3; 32], &limits)
        .expect("signed action");
    GroupMembershipAction::verify(signed, NOW, &limits).expect("verified action")
}

#[test]
fn latest_membership_action_wins_independently_of_arrival_order() {
    let relay = pubkey(&RELAY_SECRET);
    let agent = pubkey(&AGENT_SECRET);
    let put = action(9000, "omarchy", &agent, &["agent"], NOW - 2, "put");
    let remove = action(9001, "omarchy", &agent, &[], NOW - 1, "remove");

    let mut first = GroupMembershipState::new(relay.clone(), "omarchy".to_owned()).expect("state");
    assert_eq!(
        first
            .apply_from_authoritative_relay(&remove, &relay)
            .expect("remove"),
        MembershipApplyResult::Applied
    );
    assert_eq!(
        first
            .apply_from_authoritative_relay(&put, &relay)
            .expect("older put"),
        MembershipApplyResult::IgnoredOlder
    );
    assert!(!first.is_member(&agent));

    let mut second = GroupMembershipState::new(relay.clone(), "omarchy".to_owned()).expect("state");
    second
        .apply_from_authoritative_relay(&put, &relay)
        .expect("put");
    second
        .apply_from_authoritative_relay(&remove, &relay)
        .expect("remove");
    assert_eq!(first.record(&agent), second.record(&agent));
}

#[test]
fn same_timestamp_uses_the_nip01_lowest_event_id() {
    let relay = pubkey(&RELAY_SECRET);
    let agent = pubkey(&AGENT_SECRET);
    let put = action(9000, "omarchy", &agent, &["agent"], NOW, "put");
    let remove = action(9001, "omarchy", &agent, &[], NOW, "remove");
    let expected_member = put.event().id < remove.event().id;
    let expected_id = if expected_member {
        put.event().id.as_str()
    } else {
        remove.event().id.as_str()
    };

    let mut state = GroupMembershipState::new(relay.clone(), "omarchy".to_owned()).expect("state");
    state
        .apply_from_authoritative_relay(&put, &relay)
        .expect("put");
    state
        .apply_from_authoritative_relay(&remove, &relay)
        .expect("remove");

    let record = state.record(&agent).expect("membership record");
    assert_eq!(record.is_member(), expected_member);
    assert_eq!(record.source_event_id(), expected_id);
}

#[test]
fn exact_replay_is_idempotent_and_preserves_provenance() {
    let relay = pubkey(&RELAY_SECRET);
    let agent = pubkey(&AGENT_SECRET);
    let put = action(9000, "omarchy", &agent, &["agent"], NOW, "put");
    let mut state = GroupMembershipState::new(relay.clone(), "omarchy".to_owned()).expect("state");

    assert_eq!(
        state
            .apply_from_authoritative_relay(&put, &relay)
            .expect("first"),
        MembershipApplyResult::Applied
    );
    assert_eq!(
        state
            .apply_from_authoritative_relay(&put, &relay)
            .expect("replay"),
        MembershipApplyResult::Idempotent
    );
    let record = state.record(&agent).expect("record");
    assert_eq!(record.pubkey(), agent);
    assert_eq!(record.roles(), ["agent"]);
    assert_eq!(record.moderator_pubkey(), pubkey(&MODERATOR_SECRET));
}

#[test]
fn relay_group_and_subgroup_boundaries_do_not_leak() {
    let relay = pubkey(&RELAY_SECRET);
    let other_relay = pubkey(&[11; 32]);
    let agent = pubkey(&AGENT_SECRET);
    let root_action = action(9000, "omarchy", &agent, &[], NOW, "root membership");
    let mut subgroup =
        GroupMembershipState::new(relay.clone(), "install-help".to_owned()).expect("subgroup");

    assert_eq!(
        subgroup.apply_from_authoritative_relay(&root_action, &relay),
        Err(MembershipStateError::GroupMismatch)
    );
    assert_eq!(
        subgroup.apply_from_authoritative_relay(&root_action, &other_relay),
        Err(MembershipStateError::RelayMismatch)
    );
    assert!(!subgroup.is_member(&agent));
}
