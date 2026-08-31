use omachat_mesh::{
    announce::{Announcement, AuthenticatedPeerState},
    private::{
        AnnouncementTrust, PeerPins, PrivateDedup, PrivatePayload, PrivateRoute,
        choose_private_route,
    },
};

#[test]
fn authenticated_state_pins_and_public_announce_cannot_replace_it() {
    let state = AuthenticatedPeerState {
        noise_public_key: [1; 32],
        signing_public_key: [2; 32],
        capabilities: 3,
    };
    let mut pins = PeerPins::default();
    let fingerprint = pins.promote(&state).expect("first pin").fingerprint.clone();
    let matching = Announcement {
        nickname: "peer".into(),
        noise_public_key: [1; 32],
        signing_public_key: [2; 32],
        neighbors: vec![],
        capabilities: 3,
        bridge_geohash: None,
    };
    assert_eq!(
        pins.assess_announcement(&matching),
        AnnouncementTrust::MatchesAuthenticatedPin
    );
    let mut copied = matching;
    copied.signing_public_key = [9; 32];
    assert_eq!(
        pins.assess_announcement(&copied),
        AnnouncementTrust::Untrusted
    );
    assert_eq!(
        pins.get(&fingerprint).expect("pin").signing_public_key,
        [2; 32]
    );
}

#[test]
fn private_text_and_receipts_round_trip_and_deduplicate() {
    for payload in [
        PrivatePayload::Text {
            message_id: [1; 16],
            timestamp_ms: 42,
            text: "hello".into(),
        },
        PrivatePayload::Delivered {
            message_id: [1; 16],
        },
        PrivatePayload::Read {
            message_id: [1; 16],
        },
    ] {
        assert_eq!(
            PrivatePayload::decode(&payload.encode().expect("encode")).expect("decode"),
            payload
        );
    }
    let mut dedup = PrivateDedup::default();
    assert!(dedup.insert([1; 16]));
    assert!(!dedup.insert([1; 16]));
}

#[test]
fn mesh_first_fallback_requires_mutual_favorite() {
    assert_eq!(
        choose_private_route(true, false, false, true),
        PrivateRoute::Mesh
    );
    assert_eq!(
        choose_private_route(false, true, true, true),
        PrivateRoute::Nostr
    );
    assert_eq!(
        choose_private_route(false, true, false, true),
        PrivateRoute::RejectNotMutual
    );
    assert_eq!(
        choose_private_route(false, false, false, true),
        PrivateRoute::Queue
    );
}
