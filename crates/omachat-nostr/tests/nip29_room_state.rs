use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    nip29::{GroupMembershipAction, GroupRoster},
    nip29_delete::{AcceptedGroupDeletion, GroupDeleteRequest, delete_event_request},
    nip29_lifecycle::{AcceptedLifecycleAction, GroupLifecycleRequest, create_group_request},
    nip29_pins::GroupPinList,
    nip29_roles::GroupRoles,
    nip29_room_state::{ROOM_STATE_SCHEMA_VERSION, RelayRoomState, RoomStateError},
    nip29_state::MembershipApplyResult,
};
use serde_json::Value;

const NOW: u64 = 1_800_000_000;
const RELAY_SECRET: [u8; 32] = [5; 32];
const OTHER_RELAY_SECRET: [u8; 32] = [11; 32];
const MODERATOR_SECRET: [u8; 32] = [7; 32];
const AGENT_SECRET: [u8; 32] = [9; 32];
const TARGET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn limits() -> EventLimits {
    EventLimits::default()
}

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("key"))
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
    .expect("signed")
}

fn admins(relay: &[u8; 32], group: &str, admin: &str, created_at: u64) -> GroupRoster {
    GroupRoster::verify(
        signed(
            relay,
            created_at,
            39001,
            vec![tag(&["d", group]), tag(&["p", admin, "moderator"])],
        ),
        &pubkey(relay),
        NOW,
        &limits(),
    )
    .expect("roster")
}

fn roles(relay: &[u8; 32], group: &str, created_at: u64, name: &str) -> GroupRoles {
    GroupRoles::verify(
        signed(
            relay,
            created_at,
            39003,
            vec![tag(&["d", group]), tag(&["role", name, "Keeps order"])],
        ),
        &pubkey(relay),
        NOW,
        &limits(),
    )
    .expect("roles")
}

fn pins(relay: &[u8; 32], group: &str, created_at: u64) -> GroupPinList {
    GroupPinList::verify(
        signed(
            relay,
            created_at,
            39005,
            vec![tag(&["d", group]), tag(&["e", TARGET])],
        ),
        &pubkey(relay),
        NOW,
        &limits(),
    )
    .expect("pins")
}

#[test]
fn relay_snapshots_keep_the_newest_and_reject_other_relays() {
    let mut state = RelayRoomState::new(pubkey(&RELAY_SECRET)).expect("state");
    let moderator = pubkey(&MODERATOR_SECRET);

    assert!(
        state
            .observe_roster(&admins(&RELAY_SECRET, "omarchy", &moderator, NOW - 20))
            .expect("roster")
    );
    assert!(
        !state
            .observe_roster(&admins(&RELAY_SECRET, "omarchy", &moderator, NOW - 30))
            .expect("older")
    );
    assert!(
        state
            .observe_roster(&admins(&RELAY_SECRET, "omarchy", &moderator, NOW - 10))
            .expect("newer")
    );
    assert_eq!(
        state
            .group("omarchy")
            .expect("group")
            .admins()
            .expect("admins")
            .event()
            .created_at,
        NOW - 10
    );
    assert!(
        state
            .observe_roles(&roles(&RELAY_SECRET, "omarchy", NOW - 5, "moderator"))
            .expect("roles")
    );
    assert!(
        state
            .observe_pins(&pins(&RELAY_SECRET, "omarchy", NOW - 5))
            .expect("pins")
    );
    assert!(state.group("omarchy").expect("group").members().is_none());

    for error in [
        state.observe_roster(&admins(&OTHER_RELAY_SECRET, "omarchy", &moderator, NOW)),
        state.observe_roles(&roles(&OTHER_RELAY_SECRET, "omarchy", NOW, "x")),
        state.observe_pins(&pins(&OTHER_RELAY_SECRET, "omarchy", NOW)),
    ] {
        assert_eq!(error, Err(RoomStateError::RelayMismatch));
    }
    let foreign_request = GroupLifecycleRequest::verify(
        signed(
            &MODERATOR_SECRET,
            NOW - 1,
            9007,
            vec![tag(&["h", "omarchy"])],
        ),
        NOW,
        &limits(),
    )
    .expect("request");
    let foreign_deletion = GroupDeleteRequest::verify(
        signed(
            &MODERATOR_SECRET,
            NOW - 1,
            9005,
            vec![tag(&["h", "omarchy"]), tag(&["e", TARGET])],
        ),
        NOW,
        &limits(),
    )
    .expect("deletion");
    let accepted = AcceptedGroupDeletion::from_authoritative_relay(
        foreign_deletion,
        &pubkey(&OTHER_RELAY_SECRET),
    )
    .expect("accepted elsewhere");
    assert_eq!(
        state.apply_deletion(&accepted),
        Err(RoomStateError::RelayMismatch)
    );
    drop(foreign_request);
    assert_eq!(state.group_ids().collect::<Vec<_>>(), ["omarchy"]);
}

#[test]
fn snapshot_round_trips_and_matches_fresh_reduction() {
    let relay = pubkey(&RELAY_SECRET);
    let moderator = pubkey(&MODERATOR_SECRET);
    let mut state = RelayRoomState::new(relay.clone()).expect("state");
    let roster = admins(&RELAY_SECRET, "omarchy", &moderator, NOW - 100);
    state.observe_roster(&roster).expect("roster");
    state
        .observe_roles(&roles(&RELAY_SECRET, "omarchy", NOW - 90, "moderator"))
        .expect("roles");
    state
        .observe_pins(&pins(&RELAY_SECRET, "omarchy", NOW - 80))
        .expect("pins");

    let creation = GroupLifecycleRequest::verify(
        create_group_request(moderator.clone(), NOW - 70, "omarchy", &limits())
            .expect("create")
            .sign_with_aux(&MODERATOR_SECRET, &[3; 32], &limits())
            .expect("signed"),
        NOW,
        &limits(),
    )
    .expect("creation");
    state
        .lifecycle_mut()
        .apply_accepted(
            &AcceptedLifecycleAction::from_authoritative_relay(creation, &relay).expect("accepted"),
        )
        .expect("created");
    let put = GroupMembershipAction::verify(
        signed(
            &MODERATOR_SECRET,
            NOW - 60,
            9000,
            vec![
                tag(&["h", "omarchy"]),
                tag(&["p", &pubkey(&AGENT_SECRET), "agent"]),
            ],
        ),
        NOW,
        &limits(),
    )
    .expect("put");
    assert_eq!(
        state.apply_membership(&put).expect("put"),
        MembershipApplyResult::Applied
    );
    let deletion = GroupDeleteRequest::verify(
        delete_event_request(
            moderator,
            NOW - 50,
            "omarchy",
            &[TARGET.to_owned()],
            String::new(),
            &[],
            &limits(),
        )
        .expect("delete")
        .sign_with_aux(&MODERATOR_SECRET, &[3; 32], &limits())
        .expect("signed"),
        NOW,
        &limits(),
    )
    .expect("deletion");
    state
        .apply_deletion(
            &AcceptedGroupDeletion::from_authoritative_relay(deletion, &relay).expect("accepted"),
        )
        .expect("deleted");

    let snapshot = state.snapshot();
    assert_eq!(snapshot.schema_version(), ROOM_STATE_SCHEMA_VERSION);
    assert_eq!(snapshot.relay_pubkey(), relay);
    assert_eq!(snapshot.group_count(), 1);
    let restored = RelayRoomState::restore(snapshot.clone(), NOW, &limits()).expect("restored");
    assert_eq!(restored, state);
    assert_eq!(restored.snapshot(), snapshot);
    assert!(
        restored
            .group("omarchy")
            .expect("group")
            .deletions()
            .is_deleted(TARGET)
    );
    assert_eq!(
        restored
            .group("omarchy")
            .expect("group")
            .roles()
            .expect("roles")
            .roles()[0]
            .name(),
        "moderator"
    );

    // The JSON form is stable under a decode/encode cycle too.
    let json = serde_json::to_vec(&snapshot).expect("encode");
    let decoded = serde_json::from_slice(&json).expect("decode");
    assert_eq!(snapshot, decoded);
}

#[test]
fn tampered_or_foreign_snapshots_fail_closed() {
    let relay = pubkey(&RELAY_SECRET);
    let mut state = RelayRoomState::new(relay.clone()).expect("state");
    let roster = admins(
        &RELAY_SECRET,
        "omarchy",
        &pubkey(&MODERATOR_SECRET),
        NOW - 100,
    );
    state.observe_roster(&roster).expect("roster");
    let creation = GroupLifecycleRequest::verify(
        create_group_request(pubkey(&MODERATOR_SECRET), NOW - 70, "omarchy", &limits())
            .expect("create")
            .sign_with_aux(&MODERATOR_SECRET, &[3; 32], &limits())
            .expect("signed"),
        NOW,
        &limits(),
    )
    .expect("creation");
    state
        .lifecycle_mut()
        .apply_accepted(
            &AcceptedLifecycleAction::from_authoritative_relay(creation, &relay).expect("accepted"),
        )
        .expect("created");
    let mut json = serde_json::to_value(state.snapshot()).expect("value");

    let restore = |json: &Value| {
        RelayRoomState::restore(
            serde_json::from_value(json.clone()).expect("shape"),
            NOW,
            &limits(),
        )
    };
    assert!(restore(&json).is_ok());

    let mut future = json.clone();
    future["schema_version"] = Value::from(ROOM_STATE_SCHEMA_VERSION + 1);
    assert_eq!(
        restore(&future).err(),
        Some(RoomStateError::UnsupportedSchemaVersion(
            ROOM_STATE_SCHEMA_VERSION + 1
        ))
    );

    let mut other_relay = json.clone();
    other_relay["relay_pubkey"] = Value::from(pubkey(&OTHER_RELAY_SECRET));
    // Per-group evidence is scoped to the original relay, so the re-labelled
    // snapshot is refused before any relay-signed event is even checked.
    assert_eq!(
        restore(&other_relay).err(),
        Some(RoomStateError::RelayMismatch)
    );

    let mut tampered = json.clone();
    tampered["lifecycle_inputs"][0]["event"]["content"] = Value::from("edited");
    assert!(matches!(
        restore(&tampered).err(),
        Some(RoomStateError::Event(_))
    ));

    let mut escalated = json.clone();
    escalated["groups"][0]["membership"]["records"] = serde_json::json!([{
        "pubkey": pubkey(&AGENT_SECRET),
        "member": true,
        "roles": ["owner"],
        "moderator_pubkey": "not-a-key",
        "source_event_id": TARGET,
        "created_at": NOW
    }]);
    assert!(matches!(
        restore(&escalated).err(),
        Some(RoomStateError::Membership(_))
    ));

    json["groups"][0]["group_id"] = Value::from("other");
    assert!(matches!(
        restore(&json).err(),
        Some(RoomStateError::InvalidSnapshot(_))
    ));
}
