use omachat_nostr::{
    courier_drop::{DropDedup, create, parse},
    event::{EventLimits, xonly_public_key},
};

#[test]
fn throwaway_signed_drop_round_trips_and_true_identity_is_not_exposed() {
    let limits = EventLimits::default();
    let event = create(
        b"sealed courier",
        &[7; 16],
        2_000,
        1_000,
        &[3; 32],
        &[4; 32],
        &limits,
    )
    .expect("create");
    assert_ne!(
        event.pubkey,
        hex::encode(xonly_public_key(&[9; 32]).expect("identity"))
    );
    assert_eq!(
        parse(&event, &[[6; 16], [7; 16], [8; 16]], 1_001, &limits).expect("parse"),
        b"sealed courier"
    );
}

#[test]
fn stale_wrong_tag_and_duplicate_drops_fail() {
    let limits = EventLimits::default();
    let event = create(
        b"sealed", &[7; 16], 200_000, 1_000, &[3; 32], &[4; 32], &limits,
    )
    .expect("create");
    assert!(parse(&event, &[[8; 16]], 1_001, &limits).is_err());
    assert!(parse(&event, &[[7; 16]], 200_001, &limits).is_err());
    let mut dedup = DropDedup::new(100);
    assert!(dedup.accept(&event.id));
    assert!(!dedup.accept(&event.id));
}
