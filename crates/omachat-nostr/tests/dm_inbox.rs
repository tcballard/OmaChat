use omachat_nostr::{
    dm_inbox::{DEFAULT_DM_LOOKBACK_SECONDS, DmInbox, DmInboxConfig, DmInboxError, DmInboxReceive},
    event::{EventLimits, SignedEvent, xonly_public_key},
    gift_wrap::{ChatRecipient, GiftWrapPersistence, create_chat_rumor, create_gift_wrap},
};

const NOW: u64 = 1_800_000_000;
const SENDER_SECRET: [u8; 32] = [0x11; 32];
const RECIPIENT_SECRET: [u8; 32] = [0x22; 32];
const STRANGER_SECRET: [u8; 32] = [0x33; 32];

fn recipient_public_key() -> [u8; 32] {
    xonly_public_key(&RECIPIENT_SECRET).unwrap()
}

fn sender_public_key_hex() -> String {
    hex::encode(xonly_public_key(&SENDER_SECRET).unwrap())
}

fn wrapped_message(persistence: GiftWrapPersistence) -> SignedEvent {
    let limits = EventLimits::default();
    let rumor = create_chat_rumor(
        &SENDER_SECRET,
        NOW - 60,
        &[ChatRecipient {
            public_key: recipient_public_key(),
            relay_hint: Some("wss://relay.external.example".into()),
        }],
        "portable hello".into(),
        Some("external agent".into()),
        None,
        &limits,
    )
    .unwrap();
    create_gift_wrap(
        &rumor,
        &SENDER_SECRET,
        &recipient_public_key(),
        NOW,
        persistence,
        &limits,
    )
    .unwrap()
}

#[test]
fn opens_external_standard_message_and_deduplicates_across_relay_paths() {
    let gift_wrap = wrapped_message(GiftWrapPersistence::Persistent);
    let mut inbox = DmInbox::new(DmInboxConfig::default()).unwrap();
    let first = inbox.receive(&gift_wrap, &RECIPIENT_SECRET, NOW).unwrap();
    let DmInboxReceive::Message(message) = first else {
        panic!("valid external event must be a message")
    };
    assert_eq!(message.content, "portable hello");
    assert_eq!(message.metadata.author_pubkey, sender_public_key_hex());
    assert_eq!(message.metadata.gift_wrap_id, gift_wrap.id);
    assert_eq!(message.metadata.created_at, NOW - 60);

    assert_eq!(
        inbox
            .receive(&gift_wrap, &RECIPIENT_SECRET, NOW + 1)
            .unwrap(),
        DmInboxReceive::Duplicate {
            gift_wrap_id: gift_wrap.id,
        }
    );
}

#[test]
fn relay_tampering_never_poison_dedup_state() {
    let gift_wrap = wrapped_message(GiftWrapPersistence::Persistent);
    let mut tampered = gift_wrap.clone();
    tampered.content.push('!');
    let mut inbox = DmInbox::new(DmInboxConfig::default()).unwrap();

    assert!(inbox.receive(&tampered, &RECIPIENT_SECRET, NOW).is_err());
    assert!(matches!(
        inbox.receive(&gift_wrap, &RECIPIENT_SECRET, NOW).unwrap(),
        DmInboxReceive::Message(_)
    ));
}

#[test]
fn blocked_author_content_is_hidden_only_after_authenticated_open() {
    let gift_wrap = wrapped_message(GiftWrapPersistence::Persistent);
    let mut inbox = DmInbox::new(DmInboxConfig::default()).unwrap();
    inbox.block_author(&sender_public_key_hex()).unwrap();

    let DmInboxReceive::Blocked(metadata) =
        inbox.receive(&gift_wrap, &RECIPIENT_SECRET, NOW).unwrap()
    else {
        panic!("blocked author content must not escape")
    };
    assert_eq!(metadata.author_pubkey, sender_public_key_hex());
    assert_eq!(metadata.gift_wrap_id, gift_wrap.id);
}

#[test]
fn routing_filter_is_bounded_and_recipient_specific() {
    let inbox = DmInbox::new(DmInboxConfig::default()).unwrap();
    let recipient = hex::encode(recipient_public_key());
    let filter = inbox.subscription_filter(&recipient, NOW).unwrap();
    assert_eq!(filter["kinds"], serde_json::json!([1059]));
    assert_eq!(filter["#p"], serde_json::json!([recipient]));
    assert_eq!(filter["since"], NOW - DEFAULT_DM_LOOKBACK_SECONDS);
    assert_eq!(filter["limit"], 500);
    assert!(inbox.subscription_filter("not-a-key", NOW).is_err());
}

#[test]
fn wrong_recipient_and_ephemeral_wrappers_fail_closed() {
    let persistent = wrapped_message(GiftWrapPersistence::Persistent);
    let ephemeral = wrapped_message(GiftWrapPersistence::Ephemeral);
    let mut inbox = DmInbox::new(DmInboxConfig::default()).unwrap();

    assert!(matches!(
        inbox.receive(&persistent, &STRANGER_SECRET, NOW),
        Err(DmInboxError::WrongRecipient)
    ));
    assert!(matches!(
        inbox.receive(&ephemeral, &RECIPIENT_SECRET, NOW),
        Err(DmInboxError::UnexpectedGiftWrapKind { actual: 21_059 })
    ));
}

#[test]
fn zero_bounds_are_rejected() {
    assert!(matches!(
        DmInbox::new(DmInboxConfig {
            lookback_seconds: 0,
            ..DmInboxConfig::default()
        }),
        Err(DmInboxError::InvalidConfig)
    ));
}
