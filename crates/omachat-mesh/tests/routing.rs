use omachat_mesh::{
    packet::{MessageType, Packet},
    routing::{
        DedupCache, DedupResult, ForwardPlan, PeerPresence, PresenceDirectory, Topology,
        announce_delay_ms, forward_source_route, origin_ttl, select_fanout, should_relay,
    },
};

#[test]
fn presence_timing_and_expiry_are_deterministic() {
    assert_eq!(announce_delay_ms(0, 0), 2_000);
    assert_eq!(announce_delay_ms(0, 9), 30_000);
    assert_eq!(announce_delay_ms(1, 0), 30_000);
    let mut peers = PresenceDirectory::default();
    peers.observe(PeerPresence {
        peer_id: [1; 8],
        neighbors: vec![],
        last_seen_ms: 0,
        authenticated: false,
    });
    assert_eq!(peers.reachable(59_999).len(), 1);
    peers.expire(60_000);
    assert!(peers.reachable(60_000).is_empty());
}

#[test]
fn dedup_split_horizon_and_request_sync_rules_terminate() {
    let mut dedup = DedupCache::default();
    assert_eq!(dedup.observe([1; 16], 0), DedupResult::New);
    assert_eq!(dedup.observe([1; 16], 1), DedupResult::Duplicate);
    assert_eq!(dedup.observe([1; 16], 300_000), DedupResult::New);
    let links = [[1; 16], [2; 16], [3; 16], [4; 16], [5; 16]];
    let selected = select_fanout(&[9; 16], &links, Some([2; 16]), false);
    assert!(!selected.contains(&[2; 16]));
    assert!(selected.len() < links.len());
    assert_eq!(origin_ttl(1), 3);
    assert_eq!(origin_ttl(10), 7);

    let mut packet = Packet {
        version: 1,
        message_type: MessageType::RequestSync.into(),
        ttl: 7,
        timestamp_ms: 0,
        sender: [1; 8],
        recipient: None,
        route: vec![],
        payload: vec![],
        signature: None,
        is_rsr: false,
    };
    assert!(!should_relay(&packet));
    packet.message_type = MessageType::Message.into();
    assert!(should_relay(&packet));
    packet.ttl = 0;
    assert!(!should_relay(&packet));
}

#[test]
fn topology_requires_fresh_bidirectional_edges_and_falls_back() {
    let mut topology = Topology::default();
    topology.update([1; 8], [[2; 8]], 0);
    topology.update([2; 8], [[1; 8], [3; 8]], 0);
    topology.update([3; 8], [[2; 8]], 0);
    assert_eq!(
        topology.route([1; 8], [3; 8], 1),
        Some(vec![[2; 8], [3; 8]])
    );
    assert_eq!(topology.route([1; 8], [3; 8], 60_000), None);
    assert_eq!(
        forward_source_route([2; 8], &[[2; 8], [3; 8]]),
        ForwardPlan::SourceRoute([3; 8])
    );
    assert_eq!(
        forward_source_route([9; 8], &[[2; 8], [3; 8]]),
        ForwardPlan::Flood
    );
    assert_eq!(
        forward_source_route([2; 8], &[[2; 8], [3; 8], [2; 8]]),
        ForwardPlan::DropLoop
    );
}
