use omachat_nostr::{
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    geochat::{
        CHAT_KIND, ChatInput, GeoInbox, GeoInboxReceive, ParsedGeoEvent, create_chat,
        create_presence, mine_nonce_tag, parse_geo_event, subscription_filter,
        validated_pow_difficulty,
    },
};
use omachat_proto::geohash::Geohash;
use serde::Deserialize;
use serde_json::json;
use std::{fs, path::PathBuf, time::Duration};

#[derive(Deserialize)]
struct PowInputs {
    base_tags: Vec<Vec<String>>,
    content: String,
    created_at: u64,
    kind: u32,
    pubkey_hex: String,
}

#[derive(Deserialize)]
struct PowOutputs {
    event_id_hex: String,
}

#[derive(Deserialize)]
struct PowIntermediates {
    mined_nonce_tag: Vec<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate must be in workspace/crates")
        .to_owned()
}

fn fixture<T: for<'de> Deserialize<'de>>(file: &str) -> T {
    serde_json::from_slice(
        &fs::read(
            workspace_root()
                .join("conformance/fixtures/swift-nip13-policy-v1")
                .join(file),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn captured_nip13_nonce_and_committed_score_match_exactly() {
    let input: PowInputs = fixture("inputs.json");
    let output: PowOutputs = fixture("outputs.json");
    let intermediate: PowIntermediates = fixture("intermediates.json");
    let limits = EventLimits::default();
    let base = UnsignedEvent::new(
        input.pubkey_hex,
        input.created_at,
        input.kind,
        input.base_tags,
        input.content,
        &limits,
    )
    .unwrap();
    let nonce =
        mine_nonce_tag(&base, 8, 0, Duration::from_secs(1), Duration::from_secs(1)).unwrap();
    assert_eq!(nonce, intermediate.mined_nonce_tag);
    let mut tags = base.tags.clone();
    tags.push(nonce);
    let mined = UnsignedEvent::new(
        base.pubkey,
        base.created_at,
        base.kind,
        tags,
        base.content,
        &limits,
    )
    .unwrap();
    let event_id = hex::encode(mined.id().unwrap());
    assert_eq!(event_id, output.event_id_hex);
    assert_eq!(validated_pow_difficulty(&event_id, &mined.tags), 8);

    let mut overclaimed = mined.tags;
    overclaimed.last_mut().unwrap()[2] = "10".into();
    assert_eq!(validated_pow_difficulty(&event_id, &overclaimed), 0);
    assert_eq!(validated_pow_difficulty(&event_id, &[]), 0);
}

#[test]
fn signed_chat_presence_and_local_blocking_are_fail_closed() {
    let limits = EventLimits::default();
    let secret = [21_u8; 32];
    let geohash = Geohash::parse("gcpvj").unwrap();
    let chat = create_chat(
        &ChatInput {
            secret_key: &secret,
            created_at: 1_700_000_000,
            geohash: &geohash,
            nickname: Some(" oma "),
            teleported: true,
            content: "hello",
            signature_aux: &[22; 32],
        },
        &limits,
    )
    .unwrap();
    assert_eq!(
        parse_geo_event(&chat, chat.created_at, &limits).unwrap(),
        ParsedGeoEvent::Chat {
            event_id: chat.id.clone(),
            sender_pubkey: chat.pubkey.clone(),
            created_at: chat.created_at,
            geohash: geohash.clone(),
            nickname: Some("oma".into()),
            teleported: true,
            content: "hello".into(),
            validated_pow_bits: 0,
        }
    );

    let presence = create_presence(&secret, chat.created_at, &geohash, &[23; 32], &limits).unwrap();
    assert!(matches!(
        parse_geo_event(&presence, presence.created_at, &limits).unwrap(),
        ParsedGeoEvent::Presence { .. }
    ));

    let mut inbox = GeoInbox::new(2, 300).unwrap();
    inbox.block_sender(&chat.pubkey).unwrap();
    assert_eq!(
        inbox.receive(&chat, chat.created_at, &limits).unwrap(),
        GeoInboxReceive::Blocked {
            event_id: chat.id.clone(),
            sender_pubkey: chat.pubkey.clone(),
        }
    );
    assert_eq!(
        inbox.receive(&chat, chat.created_at + 1, &limits).unwrap(),
        GeoInboxReceive::Duplicate {
            event_id: chat.id.clone(),
        }
    );

    let mut tampered = chat;
    tampered.content.push('!');
    assert!(parse_geo_event(&tampered, tampered.created_at, &limits).is_err());
}

#[test]
fn concurrent_cells_have_distinct_filters_and_can_use_unlinked_keys() {
    let london = Geohash::parse("gcpvj").unwrap();
    let sydney = Geohash::parse("r3gx2").unwrap();
    assert_ne!(
        subscription_filter(&london, 100, 200),
        subscription_filter(&sydney, 100, 200)
    );
    assert_eq!(
        subscription_filter(&london, 100, 200)["kinds"],
        json!([20_000, 20_001])
    );

    let first = xonly_public_key(&[31_u8; 32]).unwrap();
    let second = xonly_public_key(&[32_u8; 32]).unwrap();
    assert_ne!(first, second);
}

#[test]
fn malformed_geohash_shapes_are_rejected_after_signature_verification() {
    let limits = EventLimits::default();
    let secret = [41_u8; 32];
    let unsigned = UnsignedEvent::new(
        hex::encode(xonly_public_key(&secret).unwrap()),
        1_700_000_000,
        CHAT_KIND,
        vec![vec!["n".into(), "missing-cell".into()]],
        "content".into(),
        &limits,
    )
    .unwrap();
    let signed = unsigned.sign_with_aux(&secret, &[42; 32], &limits).unwrap();
    assert!(parse_geo_event(&signed, signed.created_at, &limits).is_err());
}
