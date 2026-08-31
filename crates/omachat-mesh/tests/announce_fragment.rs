use omachat_mesh::{
    announce::{Announcement, AuthenticatedPeerState},
    fragment::{FragmentError, ReassemblyManager, plan},
};

#[test]
fn announcement_round_trips_empty_nickname_and_skips_unknown_tlv() {
    let announcement = Announcement {
        nickname: String::new(),
        noise_public_key: [1; 32],
        signing_public_key: [2; 32],
        neighbors: vec![[3; 8], [4; 8]],
        capabilities: 0x0102,
        bridge_geohash: Some("gcpvj".into()),
    };
    let mut bytes = announcement.encode().expect("encode");
    bytes.extend_from_slice(&[0xfe, 2, 9, 8]);
    assert_eq!(Announcement::decode(&bytes).expect("decode"), announcement);

    let state = AuthenticatedPeerState {
        noise_public_key: [1; 32],
        signing_public_key: [2; 32],
        capabilities: 0x0102,
    };
    assert_eq!(
        AuthenticatedPeerState::decode(&state.encode()).expect("state"),
        state
    );
}

#[test]
fn shuffled_duplicates_complete_but_conflicts_and_expiry_fail_safely() {
    let payload = (0_u32..2_000)
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>();
    let mut fragments = plan([7; 8], 2, &payload, 469).expect("plan");
    fragments.reverse();
    let mut manager = ReassemblyManager::default();
    assert!(
        manager
            .insert([1; 8], fragments[0].clone(), 0)
            .expect("first")
            .is_none()
    );
    assert!(
        manager
            .insert([1; 8], fragments[0].clone(), 1)
            .expect("duplicate")
            .is_none()
    );
    let mut result = None;
    for fragment in fragments.into_iter().skip(1) {
        result = manager
            .insert([1; 8], fragment, 2)
            .expect("fragment")
            .or(result);
    }
    assert_eq!(result.expect("complete").payload, payload);

    let fragments = plan([8; 8], 2, b"a sufficiently long payload", 20).expect("plan conflict");
    manager
        .insert([1; 8], fragments[0].clone(), 0)
        .expect("start");
    let mut conflict = fragments[0].clone();
    conflict.data[0] ^= 1;
    assert_eq!(
        manager.insert([1; 8], conflict, 1),
        Err(FragmentError::Conflict)
    );
    manager
        .insert([1; 8], fragments[0].clone(), 0)
        .expect("restart");
    manager.expire(30_000);
    assert!(
        manager
            .insert([1; 8], fragments[1].clone(), 30_001)
            .expect("new assembly")
            .is_none()
    );
}
