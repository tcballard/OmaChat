use omachat_mesh::{
    packet::{MessageType, Packet},
    sync::{FILTER_P, GcsFilter, RequestSync, ResponseWindows, map_id, packet_id, select_missing},
};

fn packet(index: u8) -> Packet {
    Packet {
        version: 1,
        message_type: MessageType::Message.into(),
        ttl: 0,
        timestamp_ms: u64::from(index),
        sender: [index; 8],
        recipient: None,
        route: vec![],
        payload: vec![index; 4],
        signature: None,
        is_rsr: false,
    }
}

#[test]
fn packet_ids_filters_and_request_tlvs_round_trip() {
    let ids = (1..=20)
        .map(|index| packet_id(&packet(index)))
        .collect::<Vec<_>>();
    let filter = GcsFilter::build(&ids, FILTER_P, 20_000).expect("filter");
    for id in &ids {
        assert!(filter.contains(id).expect("membership"));
    }
    assert!(filter.bytes.len() <= 400);
    assert_ne!(map_id(&ids[0], 20_000), 0);

    let request = RequestSync {
        p: filter.p,
        modulus: filter.modulus,
        filter: filter.bytes,
        types: vec![2, 4],
        since_ms: 123,
        fragment_ids: vec![[9; 8]],
    };
    assert_eq!(
        RequestSync::decode(&request.encode().expect("encode")).expect("decode"),
        request
    );
}

#[test]
fn rsr_is_link_local_and_requires_registered_window() {
    let mut windows = ResponseWindows::default();
    windows.register([1; 8], [2; 8], 100);
    assert!(windows.accepts([1; 8], [2; 8], 0, true, 101));
    assert!(!windows.accepts([1; 8], [2; 8], 1, true, 101));
    assert!(!windows.accepts([1; 8], [2; 8], 0, false, 101));
    assert!(!windows.accepts([1; 8], [2; 8], 0, true, 30_100));
}

#[test]
fn malformed_unary_and_tlvs_remain_bounded() {
    let malformed = GcsFilter {
        p: 7,
        modulus: 10,
        bytes: vec![0xff; 400],
    };
    assert!(malformed.values().is_err());
    for length in 0..20 {
        assert!(RequestSync::decode(&vec![0xff; length]).is_err());
    }
}

#[test]
fn missing_selection_is_bounded_link_local_and_chronological() {
    let archive = (1..=100).rev().map(packet).collect::<Vec<_>>();
    let known = [packet_id(&packet(50))];
    let filter = GcsFilter::build(&known, FILTER_P, 10_000).unwrap();
    let request = RequestSync {
        p: FILTER_P,
        modulus: 10_000,
        filter: filter.bytes,
        types: vec![MessageType::Message as u8],
        since_ms: 20,
        fragment_ids: vec![],
    };
    let selected = select_missing(&request, &archive).unwrap();
    assert_eq!(selected.len(), 64);
    assert!(
        selected
            .iter()
            .all(|packet| packet.ttl == 0 && packet.is_rsr)
    );
    assert!(
        selected
            .windows(2)
            .all(|pair| pair[0].timestamp_ms <= pair[1].timestamp_ms)
    );
    assert!(!selected.iter().any(|item| item.timestamp_ms == 50));
}
