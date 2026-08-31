use omachat_nostr::{
    event::EventLimits,
    rendezvous::{create, parse},
};
use omachat_proto::geohash::Geohash;

#[test]
fn chat_and_presence_round_trip() {
    let key = [9_u8; 32];
    let aux = [4_u8; 32];
    let geohash = Geohash::parse("u10j").unwrap();
    let chat = create(
        &key,
        100,
        &geohash,
        Some("a1b2"),
        Some("hello"),
        &aux,
        &EventLimits::default(),
    )
    .unwrap();
    let parsed = parse(&chat, 100, &EventLimits::default()).unwrap();
    assert_eq!(parsed.mesh_id.as_deref(), Some("a1b2"));
    assert_eq!(parsed.content.as_deref(), Some("hello"));
    let presence = create(
        &key,
        101,
        &geohash,
        None,
        None,
        &aux,
        &EventLimits::default(),
    )
    .unwrap();
    assert!(
        parse(&presence, 101, &EventLimits::default())
            .unwrap()
            .content
            .is_none()
    );
}
