use omachat_nostr::event::{EventError, EventLimits, SignedEvent, UnsignedEvent};
use serde::Deserialize;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct Nip13Inputs {
    pubkey_hex: String,
    created_at: u64,
    kind: u32,
    base_tags: Vec<Vec<String>>,
    content: String,
}

#[derive(Deserialize)]
struct Nip13Intermediates {
    canonical_serialization: Value,
}

#[derive(Deserialize)]
struct Nip13Outputs {
    event_id_hex: String,
}

#[derive(Deserialize)]
struct EnvelopeIntermediates {
    seal_event: SignedEvent,
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

#[test]
fn pinned_nip13_canonical_serialization_and_id_match() {
    let inputs: Nip13Inputs = load("conformance/fixtures/swift-nip13-policy-v1/inputs.json");
    let intermediate: Nip13Intermediates =
        load("conformance/fixtures/swift-nip13-policy-v1/intermediates.json");
    let output: Nip13Outputs = load("conformance/fixtures/swift-nip13-policy-v1/outputs.json");
    let tags: Vec<Vec<String>> = intermediate.canonical_serialization[4]
        .as_array()
        .unwrap()
        .iter()
        .map(|tag| {
            tag.as_array()
                .unwrap()
                .iter()
                .map(|field| field.as_str().unwrap().to_owned())
                .collect()
        })
        .collect();
    assert_eq!(&tags[..inputs.base_tags.len()], inputs.base_tags);

    let event = UnsignedEvent::new(
        inputs.pubkey_hex,
        inputs.created_at,
        inputs.kind,
        tags,
        inputs.content,
        &EventLimits::default(),
    )
    .unwrap();
    assert_eq!(
        event.canonical_json().unwrap(),
        serde_json::to_vec(&intermediate.canonical_serialization).unwrap()
    );
    assert_eq!(hex::encode(event.id().unwrap()), output.event_id_hex);
}

#[test]
fn pinned_swift_seals_authenticate() {
    let limits = EventLimits::default();
    for fixture in [
        "swift-nostr-private-envelope-tagless-v1",
        "swift-nostr-private-envelope-android-shape-v1",
    ] {
        let intermediate: EnvelopeIntermediates = load(&format!(
            "conformance/fixtures/{fixture}/intermediates.json"
        ));
        intermediate
            .seal_event
            .verify(1_700_000_600, &limits)
            .unwrap();
    }
}

#[test]
fn signing_and_tamper_detection_are_fail_closed() {
    let limits = EventLimits::default();
    let secret = [0x11; 32];
    let event = UnsignedEvent::new(
        "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa".into(),
        1_700_000_000,
        14,
        vec![],
        "synthetic".into(),
        &limits,
    )
    .unwrap()
    .sign_with_aux(&secret, &[0; 32], &limits)
    .unwrap();
    event.verify(1_700_000_000, &limits).unwrap();

    let mut tampered = event;
    tampered.content.push('!');
    assert!(matches!(
        tampered.verify(1_700_000_000, &limits),
        Err(EventError::IdMismatch)
    ));
}

#[test]
fn strict_json_rejects_unknown_duplicate_oversized_and_future_input() {
    let limits = EventLimits::default();
    let unknown = br#"{"id":"00","pubkey":"00","created_at":0,"kind":1,"tags":[],"content":"","sig":"00","extra":true}"#;
    assert!(matches!(
        SignedEvent::from_json(unknown, 0, &limits),
        Err(EventError::Json(_))
    ));
    let duplicate = br#"{"id":"00","id":"00","pubkey":"00","created_at":0,"kind":1,"tags":[],"content":"","sig":"00"}"#;
    assert!(matches!(
        SignedEvent::from_json(duplicate, 0, &limits),
        Err(EventError::Json(_))
    ));
    assert!(matches!(
        SignedEvent::from_json(&vec![b' '; limits.max_serialized_bytes + 1], 0, &limits),
        Err(EventError::SerializedTooLarge { .. })
    ));

    let event = UnsignedEvent::new(
        "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa".into(),
        limits.max_future_seconds + 1,
        1,
        vec![],
        String::new(),
        &limits,
    )
    .unwrap()
    .sign_with_aux(&[0x11; 32], &[0; 32], &limits)
    .unwrap();
    assert!(matches!(
        event.verify(0, &limits),
        Err(EventError::TooFarInFuture { .. })
    ));
}
