//! Replay a NIP-29 relay capture (see `conformance/relay/nip29_probe.py`)
//! through the room reducers exactly as the daemon would: relay-authored
//! state kinds verified against the relay key, user events accepted as
//! replayed by that relay path. Skips unless `OMACHAT_NIP29_CAPTURE` names a
//! capture file, so the ordinary test run stays hermetic.

use omachat_nostr::{
    event::{EventLimits, SignedEvent},
    nip29::{GroupMembershipAction, GroupMetadata, GroupRoster},
    nip29_delete::{AcceptedGroupDeletion, GroupDeleteRequest},
    nip29_lifecycle::{AcceptedLifecycleAction, GroupLifecycleRequest, GroupStatus},
    nip29_metadata::{AcceptedMetadataEdit, GroupMetadataEdit},
    nip29_pins::GroupPinList,
    nip29_roles::GroupRoles,
    nip29_room_state::RelayRoomState,
};
use serde_json::Value;

#[test]
fn captured_relay_evidence_reduces_to_the_relay_view() {
    let Ok(path) = std::env::var("OMACHAT_NIP29_CAPTURE") else {
        eprintln!("OMACHAT_NIP29_CAPTURE unset; skipping relay capture replay");
        return;
    };
    let capture: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("capture readable")).expect("json");
    let relay = capture["relay_pubkey"]
        .as_str()
        .expect("relay pubkey")
        .to_owned();
    let group = capture["group_id"].as_str().expect("group");
    let limits = EventLimits::default();
    // Capture timestamps are "now" for the probe; verify against a clock a
    // little ahead of the newest event so future-skew checks stay honest.
    let now = capture["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter_map(|event| event["created_at"].as_u64())
        .max()
        .expect("at least one event")
        + 5;

    let mut state = RelayRoomState::new(relay.clone()).expect("state");
    let mut accepted = 0_usize;
    let mut refused = Vec::new();
    for value in capture["events"].as_array().expect("events") {
        let event: SignedEvent = serde_json::from_value(value.clone()).expect("event shape");
        let kind = event.kind;
        let id = event.id.clone();
        let outcome: Result<(), String> = match kind {
            9 | 9021 | 9022 => Ok(()),
            9000 | 9001 => GroupMembershipAction::verify(event, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|action| {
                    state
                        .apply_membership(&action)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            9002 => GroupMetadataEdit::verify(event, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|edit| {
                    AcceptedMetadataEdit::from_authoritative_relay(edit, &relay)
                        .map_err(|error| error.to_string())
                })
                .and_then(|edit| {
                    state
                        .metadata_mut()
                        .apply_accepted(&edit)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            9005 => GroupDeleteRequest::verify(event, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|request| {
                    AcceptedGroupDeletion::from_authoritative_relay(request, &relay)
                        .map_err(|error| error.to_string())
                })
                .and_then(|deletion| {
                    state
                        .apply_deletion(&deletion)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            9007..=9009 => GroupLifecycleRequest::verify(event, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|request| {
                    AcceptedLifecycleAction::from_authoritative_relay(request, &relay)
                        .map_err(|error| error.to_string())
                })
                .and_then(|action| {
                    state
                        .lifecycle_mut()
                        .apply_accepted(&action)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            39000 => GroupMetadata::verify(event, &relay, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|metadata| {
                    state
                        .metadata_mut()
                        .observe_snapshot(&metadata)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            39001 | 39002 => GroupRoster::verify(event, &relay, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|roster| {
                    state
                        .observe_roster(&roster)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            39003 => GroupRoles::verify(event, &relay, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|roles| {
                    state
                        .observe_roles(&roles)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            39005 => GroupPinList::verify(event, &relay, now, &limits)
                .map_err(|error| error.to_string())
                .and_then(|pins| {
                    state
                        .observe_pins(&pins)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }),
            other => Err(format!("unmodelled kind {other}")),
        };
        match outcome {
            Ok(()) => accepted += 1,
            Err(reason) => refused.push((kind, id, reason)),
        }
    }
    eprintln!("accepted {accepted} events; refused {}", refused.len());
    for (kind, id, reason) in &refused {
        eprintln!("  refused kind {kind} {id}: {reason}");
    }
    // The only thing the relay path may legitimately have handed us that we
    // refuse is nothing: every captured event came from the relay's own
    // subscription or was accepted by it.
    assert!(
        refused.is_empty(),
        "relay-served evidence was refused: {refused:?}"
    );

    let expected = &capture["expected"];
    let metadata = state
        .metadata()
        .group(group)
        .expect("group metadata reduced");
    assert_eq!(metadata.name(), expected["name"].as_str().expect("name"));
    assert_eq!(metadata.about(), expected["about"].as_str().expect("about"));
    // OmaChat folds both the relay 39000 snapshot and the accepted 9002 edit
    // and tracks per-field provenance, so "name" is credited to whichever
    // input last set it. That is a richer model than the relay's single
    // replaceable event, so the reduced field values, not the source id, are
    // what must agree with the relay.
    assert!(
        metadata.provenance("name").is_some(),
        "reduced name must carry provenance"
    );
    assert_eq!(state.lifecycle().status(group), Some(GroupStatus::Active));

    let room = state.group(group).expect("group state");
    let admins = room
        .admins()
        .expect("admin roster")
        .principals()
        .iter()
        .map(|principal| principal.pubkey().to_owned())
        .collect::<Vec<_>>();
    let expected_admins = expected["admins"]
        .as_array()
        .expect("admins")
        .iter()
        .map(|value| value.as_str().expect("admin").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(admins, expected_admins);
    let members = room
        .members()
        .expect("member roster")
        .principals()
        .iter()
        .map(|principal| principal.pubkey().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let expected_members = expected["members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|value| value.as_str().expect("member").to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        members, expected_members,
        "final 39002 must match the relay's roster"
    );

    for deleted in capture["deleted_ids"].as_array().expect("deleted") {
        assert!(room.deletions().is_deleted(deleted.as_str().expect("id")));
    }
    for surviving in capture["surviving_ids"].as_array().expect("surviving") {
        assert!(!room.deletions().is_deleted(surviving.as_str().expect("id")));
    }
    // The relay's authoritative membership view is its 39002 roster, asserted
    // above. The parallel kind 9000/9001 reduction folds client- and
    // relay-authored moderation with NIP-01 deterministic ordering, which
    // relay29's same-second auto-generated events make ambiguous; that fold
    // has its own hermetic tests in `nip29_state`. Here we only assert that
    // every moderation event the relay served was itself accepted, which the
    // zero-refusals check above already guarantees, and that the admin's own
    // put of the member left a record.
    let member = capture["member"].as_str().expect("member");
    assert!(
        room.membership().record(member).is_some(),
        "admin put-user must be recorded"
    );
}
