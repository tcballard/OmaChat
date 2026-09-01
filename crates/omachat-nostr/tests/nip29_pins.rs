use omachat_nostr::{
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    nip29_pins::{
        GROUP_PIN_LIST_KIND, GroupPinList, GroupPinUpdate, GroupPinsError, PinReference,
        UPDATE_PIN_LIST_KIND,
    },
};

const NOW: u64 = 1_800_000_000;
const RELAY_SECRET: [u8; 32] = [5; 32];
const MODERATOR_SECRET: [u8; 32] = [7; 32];
const EVENT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("valid key"))
}

fn signed(
    secret: &[u8; 32],
    kind: u32,
    tags: Vec<Vec<String>>,
) -> omachat_nostr::event::SignedEvent {
    let limits = EventLimits::default();
    UnsignedEvent::new(pubkey(secret), NOW, kind, tags, String::new(), &limits)
        .expect("pin event")
        .sign_with_aux(secret, &[3; 32], &limits)
        .expect("signed pin event")
}

#[test]
fn relay_signed_pin_snapshot_preserves_reference_order() {
    let limits = EventLimits::default();
    let relay = pubkey(&RELAY_SECRET);
    let address = format!("30023:{}:release-notes", pubkey(&MODERATOR_SECRET));
    let list = GroupPinList::verify(
        signed(
            &RELAY_SECRET,
            GROUP_PIN_LIST_KIND,
            vec![
                vec!["d".to_owned(), "omarchy".to_owned()],
                vec!["a".to_owned(), address.clone()],
                vec!["e".to_owned(), EVENT_ID.to_owned()],
            ],
        ),
        &relay,
        NOW,
        &limits,
    )
    .expect("relay-authenticated pins");

    assert_eq!(list.group_id(), "omarchy");
    assert_eq!(
        list.pins(),
        [
            PinReference::Address(address),
            PinReference::Event(EVENT_ID.to_owned()),
        ]
    );
}

#[test]
fn signed_update_request_does_not_claim_moderator_authority() {
    let limits = EventLimits::default();
    let update = GroupPinUpdate::verify(
        signed(
            &MODERATOR_SECRET,
            UPDATE_PIN_LIST_KIND,
            vec![
                vec!["h".to_owned(), "omarchy".to_owned()],
                vec!["e".to_owned(), EVENT_ID.to_owned()],
            ],
        ),
        NOW,
        &limits,
    )
    .expect("authenticated request");

    assert_eq!(update.author(), pubkey(&MODERATOR_SECRET));
    assert_eq!(update.group_id(), "omarchy");
    assert_eq!(update.pins(), [PinReference::Event(EVENT_ID.to_owned())]);
}

#[test]
fn wrong_relay_malformed_references_and_duplicates_fail_closed() {
    let limits = EventLimits::default();
    let relay = pubkey(&RELAY_SECRET);
    assert!(matches!(
        GroupPinList::verify(
            signed(
                &MODERATOR_SECRET,
                GROUP_PIN_LIST_KIND,
                vec![vec!["d".to_owned(), "room".to_owned()]],
            ),
            &relay,
            NOW,
            &limits,
        ),
        Err(GroupPinsError::RelayAuthorMismatch)
    ));

    for tag in [
        vec!["e".to_owned(), "not-an-event".to_owned()],
        vec!["a".to_owned(), "1:not:a-coordinate".to_owned()],
        vec!["e".to_owned(), EVENT_ID.to_owned(), "smuggled".to_owned()],
    ] {
        assert!(
            GroupPinUpdate::verify(
                signed(
                    &MODERATOR_SECRET,
                    UPDATE_PIN_LIST_KIND,
                    vec![vec!["h".to_owned(), "room".to_owned()], tag],
                ),
                NOW,
                &limits,
            )
            .is_err()
        );
    }

    assert!(
        GroupPinUpdate::verify(
            signed(
                &MODERATOR_SECRET,
                UPDATE_PIN_LIST_KIND,
                vec![
                    vec!["h".to_owned(), "room".to_owned()],
                    vec!["e".to_owned(), EVENT_ID.to_owned()],
                    vec!["e".to_owned(), EVENT_ID.to_owned()],
                ],
            ),
            NOW,
            &limits,
        )
        .is_err()
    );
}
