use omachat_registry::principal_proof::{
    NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalProofError,
    NostrPrincipalType,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema_version: u16,
    nostr_secret_hex: String,
    claim_hash_hex: String,
    command_id_hex: String,
    expected_registry_revision: u64,
    account_id: String,
    handle: String,
    principal_type: String,
    authorisation_hash_hex: String,
    created_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intermediates {
    schema_version: u16,
    signing_bytes_hex: String,
    proof_digest_hex: String,
    aux_rand_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outputs {
    schema_version: u16,
    proof_version: u16,
    nostr_public_key_hex: String,
    signature_hex: String,
}

fn fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/omachat-nostr-principal-proof-v1")
        .join(file_name)
}

fn read_json<T: for<'de> Deserialize<'de>>(file_name: &str) -> T {
    serde_json::from_slice(
        &fs::read(fixture_path(file_name))
            .expect("committed principal-proof artifact must be readable"),
    )
    .expect("committed principal-proof artifact must have the expected strict schema")
}

fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded)
        .expect("fixture hex must decode")
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}

fn principal_type(encoded: &str) -> NostrPrincipalType {
    match encoded {
        "device" => NostrPrincipalType::Device,
        "agent" => NostrPrincipalType::Agent,
        "account" => NostrPrincipalType::Account,
        other => panic!("unknown fixture principal type {other}"),
    }
}

fn payload(inputs: &Inputs, nostr_public_key: [u8; 32]) -> NostrPrincipalControlPayload {
    NostrPrincipalControlPayload::new(
        hex_array(&inputs.claim_hash_hex),
        hex_array(&inputs.command_id_hex),
        inputs.expected_registry_revision,
        &inputs.account_id,
        &inputs.handle,
        principal_type(&inputs.principal_type),
        nostr_public_key,
        hex_array(&inputs.authorisation_hash_hex),
        inputs.created_at,
    )
    .expect("fixture payload must be valid")
}

#[test]
fn principal_proof_matches_independent_python_transcript() {
    let inputs: Inputs = read_json("inputs.json");
    let intermediates: Intermediates = read_json("intermediates.json");
    let outputs: Outputs = read_json("outputs.json");
    assert_eq!(inputs.schema_version, 1);
    assert_eq!(intermediates.schema_version, 1);
    assert_eq!(outputs.schema_version, 1);
    assert_eq!(outputs.proof_version, 1);
    assert_eq!(intermediates.aux_rand_hex, "00".repeat(32));

    let expected_public_key = hex_array(&outputs.nostr_public_key_hex);
    let payload = payload(&inputs, expected_public_key);
    assert_eq!(
        payload.signing_bytes(),
        hex::decode(&intermediates.signing_bytes_hex).unwrap()
    );
    assert_eq!(
        payload.proof_digest(),
        hex_array(&intermediates.proof_digest_hex)
    );

    let proof =
        NostrPrincipalControlProof::sign(payload.clone(), hex_array(&inputs.nostr_secret_hex))
            .expect("fixture secret must sign");
    assert_eq!(proof.signature(), &hex_array(&outputs.signature_hex));
    proof.verify().expect("generated proof must verify");

    let decoded =
        NostrPrincipalControlProof::from_parts(payload, hex_array(&outputs.signature_hex))
            .expect("independent signature must verify");
    assert_eq!(decoded.payload().nostr_public_key(), expected_public_key);
}

#[test]
fn proof_cannot_be_transplanted_or_signed_by_another_key() {
    let inputs: Inputs = read_json("inputs.json");
    let outputs: Outputs = read_json("outputs.json");
    let expected_public_key = hex_array(&outputs.nostr_public_key_hex);
    let original = payload(&inputs, expected_public_key);
    let signature = hex_array(&outputs.signature_hex);

    let mut changed_claim_hash = hex_array(&inputs.claim_hash_hex);
    changed_claim_hash[0] ^= 1;
    let changed = NostrPrincipalControlPayload::new(
        changed_claim_hash,
        hex_array(&inputs.command_id_hex),
        inputs.expected_registry_revision,
        &inputs.account_id,
        &inputs.handle,
        principal_type(&inputs.principal_type),
        expected_public_key,
        hex_array(&inputs.authorisation_hash_hex),
        inputs.created_at,
    )
    .unwrap();
    assert_eq!(
        NostrPrincipalControlProof::from_parts(changed, signature).unwrap_err(),
        NostrPrincipalProofError::InvalidSignature
    );

    assert_eq!(
        NostrPrincipalControlProof::sign(original, [0x16; 32]).unwrap_err(),
        NostrPrincipalProofError::PublicKeyMismatch
    );
}

#[test]
fn malformed_identity_fields_fail_closed() {
    let inputs: Inputs = read_json("inputs.json");
    let outputs: Outputs = read_json("outputs.json");
    let result = NostrPrincipalControlPayload::new(
        hex_array(&inputs.claim_hash_hex),
        hex_array(&inputs.command_id_hex),
        inputs.expected_registry_revision,
        "oa1_NOT_CANONICAL",
        &inputs.handle,
        principal_type(&inputs.principal_type),
        hex_array(&outputs.nostr_public_key_hex),
        hex_array(&inputs.authorisation_hash_hex),
        inputs.created_at,
    );
    assert_eq!(
        result.unwrap_err(),
        NostrPrincipalProofError::InvalidAccountId
    );
}
