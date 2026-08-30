use omachat_crypto::{CryptoError, open, private_envelope_key, seal};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct KeyInputs {
    sender_private_key_hex: String,
    recipient_xonly_public_key_hex: String,
}

#[derive(Deserialize)]
struct KeyOutputs {
    private_envelope_key_hex: String,
}

#[derive(Deserialize)]
struct EnvelopeInputs {
    seal_nonce_hex: String,
}

#[derive(Deserialize)]
struct EnvelopeIntermediates {
    rumor_json_utf8_hex: String,
    seal_hkdf_key_hex: String,
    seal_event: SealEvent,
}

#[derive(Deserialize)]
struct SealEvent {
    content: String,
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
fn full_compressed_point_key_schedule_matches_pinned_swift() {
    let input: KeyInputs =
        load("conformance/fixtures/swift-nostr-private-envelope-key-schedule-v1/inputs.json");
    let output: KeyOutputs =
        load("conformance/fixtures/swift-nostr-private-envelope-key-schedule-v1/outputs.json");
    let key = private_envelope_key(
        &hex_array(&input.sender_private_key_hex),
        &hex_array(&input.recipient_xonly_public_key_hex),
    )
    .unwrap();
    assert_eq!(hex::encode(key), output.private_envelope_key_hex);
}

#[test]
fn deterministic_ciphertext_matches_pinned_swift() {
    for fixture in [
        "swift-nostr-private-envelope-tagless-v1",
        "swift-nostr-private-envelope-android-shape-v1",
    ] {
        let input: EnvelopeInputs = load(&format!("conformance/fixtures/{fixture}/inputs.json"));
        let intermediate: EnvelopeIntermediates = load(&format!(
            "conformance/fixtures/{fixture}/intermediates.json"
        ));
        let key = hex_array(&intermediate.seal_hkdf_key_hex);
        let plaintext = hex::decode(intermediate.rumor_json_utf8_hex).unwrap();
        let encoded = seal(
            &key,
            &hex_array(&input.seal_nonce_hex),
            &plaintext,
            64 * 1024,
        )
        .unwrap();
        assert_eq!(encoded, intermediate.seal_event.content);
        assert_eq!(open(&key, &encoded, 64 * 1024).unwrap(), plaintext);
    }
}

#[test]
fn tampering_and_resource_overruns_fail_closed() {
    let key = [7; 32];
    let mut encoded = seal(&key, &[8; 24], b"synthetic", 32).unwrap();
    encoded.push('A');
    assert_eq!(open(&key, &encoded, 32), Err(CryptoError::Authentication));
    assert!(matches!(
        seal(&key, &[8; 24], &[0; 33], 32),
        Err(CryptoError::PlaintextTooLarge { .. })
    ));
    assert!(matches!(
        open(&key, "v2:AA", 32),
        Err(CryptoError::TruncatedCiphertext)
    ));
    assert!(matches!(
        open(&key, &format!("v2:{}", "A".repeat(1000)), 32),
        Err(CryptoError::CiphertextTooLarge { .. })
    ));
}
