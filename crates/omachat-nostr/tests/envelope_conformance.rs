use omachat_nostr::{
    envelope::{CreateEnvelope, OpenedEnvelope, RumorShape, create, open_gift_wrap},
    event::{EventError, EventLimits, SignedEvent},
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct Inputs {
    content_utf8: String,
    gift_wrap_created_at: u64,
    gift_wrap_nonce_hex: String,
    inner_tags: Vec<Vec<String>>,
    one_time_private_key_hex: String,
    recipient_private_key_hex: String,
    recipient_xonly_public_key_hex: String,
    rumor_created_at: u64,
    seal_created_at: u64,
    seal_nonce_hex: String,
    sender_private_key_hex: String,
}

#[derive(Deserialize)]
struct Outputs {
    authenticated_open: AuthenticatedOpen,
    gift_wrap_event: SignedEvent,
}

#[derive(Deserialize)]
struct AuthenticatedOpen {
    content: String,
    sender_pubkey: String,
    true_created_at: u64,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate must be in workspace/crates")
        .to_owned()
}

fn load<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    serde_json::from_slice(&fs::read(workspace_root().join(path)).unwrap()).unwrap()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).unwrap();
    bytes
}

#[test]
fn creates_and_opens_both_pinned_mobile_shapes_exactly() {
    let limits = EventLimits::default();
    for (fixture, seal_aux, gift_aux) in [
        (
            "swift-nostr-private-envelope-tagless-v1",
            [0x55; 32],
            [0x66; 32],
        ),
        (
            "swift-nostr-private-envelope-android-shape-v1",
            [0x77; 32],
            [0x88; 32],
        ),
    ] {
        let input: Inputs = load(&format!("conformance/fixtures/{fixture}/inputs.json"));
        let output: Outputs = load(&format!("conformance/fixtures/{fixture}/outputs.json"));
        let sender_secret = hex_array(&input.sender_private_key_hex);
        let recipient_secret = hex_array(&input.recipient_private_key_hex);
        let recipient_pubkey = hex_array(&input.recipient_xonly_public_key_hex);
        let one_time_secret = hex_array(&input.one_time_private_key_hex);
        let seal_nonce = hex_array(&input.seal_nonce_hex);
        let gift_nonce = hex_array(&input.gift_wrap_nonce_hex);
        let shape = if input.inner_tags.is_empty() {
            RumorShape::SwiftTagless
        } else {
            RumorShape::SwiftRecipientTag
        };

        let created = create(
            &CreateEnvelope {
                sender_secret_key: &sender_secret,
                recipient_xonly_public_key: &recipient_pubkey,
                one_time_secret_key: &one_time_secret,
                content: &input.content_utf8,
                rumor_created_at: input.rumor_created_at,
                seal_created_at: input.seal_created_at,
                gift_wrap_created_at: input.gift_wrap_created_at,
                seal_nonce: &seal_nonce,
                gift_wrap_nonce: &gift_nonce,
                seal_signature_aux: &seal_aux,
                gift_wrap_signature_aux: &gift_aux,
                rumor_shape: shape,
            },
            &limits,
        )
        .unwrap();
        assert_eq!(created, output.gift_wrap_event, "{fixture}");

        let opened = open_gift_wrap(
            &output.gift_wrap_event,
            &recipient_secret,
            input.gift_wrap_created_at,
            &limits,
        )
        .unwrap();
        assert_eq!(
            opened,
            OpenedEnvelope {
                content: output.authenticated_open.content,
                sender_pubkey: output.authenticated_open.sender_pubkey,
                true_created_at: output.authenticated_open.true_created_at,
            },
            "{fixture}"
        );
    }
}

#[test]
fn rejects_tampered_outer_event_before_decryption() {
    let limits = EventLimits::default();
    let output: Outputs =
        load("conformance/fixtures/swift-nostr-private-envelope-tagless-v1/outputs.json");
    let input: Inputs =
        load("conformance/fixtures/swift-nostr-private-envelope-tagless-v1/inputs.json");
    let mut gift = output.gift_wrap_event;
    gift.content.push('!');
    assert!(matches!(
        open_gift_wrap(
            &gift,
            &hex_array(&input.recipient_private_key_hex),
            input.gift_wrap_created_at,
            &limits,
        ),
        Err(omachat_nostr::envelope::EnvelopeError::Event(
            EventError::IdMismatch
        ))
    ));
}
