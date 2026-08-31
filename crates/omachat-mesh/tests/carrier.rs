use omachat_mesh::carrier::{BridgeLoopGuard, CarrierDirection, CarrierError, NostrCarrier};

#[test]
fn carrier_round_trip_and_loop_suppression() {
    let carrier = NostrCarrier {
        direction: CarrierDirection::MeshToNostr,
        geohash: "u10j".into(),
        event_json: br#"{"id":"abc"}"#.to_vec(),
        mesh_id: Some(*b"12345678"),
    };
    assert_eq!(
        NostrCarrier::decode(&carrier.encode().unwrap()).unwrap(),
        carrier
    );
    let mut guard = BridgeLoopGuard::new(2);
    assert!(guard.accept("abc", CarrierDirection::MeshToNostr));
    assert!(!guard.accept("abc", CarrierDirection::NostrToMesh));
    assert_eq!(guard.metrics().loop_drops, 1);
}

#[test]
fn malformed_and_oversized_are_bounded() {
    assert_eq!(NostrCarrier::decode(&[1, 0]), Err(CarrierError::Truncated));
    assert_eq!(
        NostrCarrier::decode(&vec![0; 16 * 1024 + 1]),
        Err(CarrierError::TooLarge)
    );
}
