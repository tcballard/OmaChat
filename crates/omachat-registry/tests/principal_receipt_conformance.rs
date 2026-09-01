use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim, RegistryState, principal_receipt::PrincipalProofReceipt,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

const RECEIPT_HASH_DOMAIN: &[u8] = b"omachat.registry.principal-proof-receipt-hash.v1\0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema_version: u16,
    registry_signing_seed_hex: String,
    sequence: u64,
    command_id_hex: String,
    account_id: String,
    handle: String,
    account_revision: u64,
    claim_receipt_hash_hex: String,
    principal_proof_hash_hex: String,
    nostr_public_key_hex: String,
    previous_proof_receipt_hash_hex: String,
    previous_account_proof_receipt_hash_hex: String,
    accepted_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intermediates {
    schema_version: u16,
    receipt_signing_bytes_hex: String,
    receipt_hash_preimage_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outputs {
    schema_version: u16,
    receipt_version: u16,
    encoded_receipt_hex: String,
    registry_public_key_hex: String,
    signature_hex: String,
    receipt_hash_hex: String,
}

fn fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/omachat-principal-proof-receipt-v1")
        .join(file_name)
}

fn read_json<T: for<'de> Deserialize<'de>>(file_name: &str) -> T {
    serde_json::from_slice(
        &fs::read(fixture_path(file_name))
            .expect("committed principal-receipt artifact must be readable"),
    )
    .expect("committed principal-receipt artifact must have the expected strict schema")
}

fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded)
        .expect("fixture hex must decode")
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}

#[test]
fn principal_receipt_matches_independent_python_transcript() {
    let inputs: Inputs = read_json("inputs.json");
    let intermediates: Intermediates = read_json("intermediates.json");
    let outputs: Outputs = read_json("outputs.json");
    assert_eq!(inputs.schema_version, 1);
    assert_eq!(intermediates.schema_version, 1);
    assert_eq!(outputs.schema_version, 1);
    assert_eq!(outputs.receipt_version, 1);

    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(&inputs.handle).unwrap()),
        Some(DisplayName::parse("Alice Example").unwrap()),
        DevicePublicKeys {
            signing_public_key: hex_array(
                "66cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf7633",
            ),
            noise_public_key: hex_array(
                "18a6f8c1a7fddf22bd410138f79f7298cd38d1d0a542d4266d556be8609d8862",
            ),
            nostr_public_key: hex_array(
                "d793631af7aa0e709439dd47fc001acd0b0727670b6670ea528ac83cb0127f4a",
            ),
        },
        1,
        1_788_000_001,
    );
    let claim = HandleClaim::sign(
        CommandId::from_bytes(hex_array(&inputs.command_id_hex)),
        0,
        binding,
        &account,
    )
    .unwrap();
    let mut registry =
        RegistryState::from_signing_seed(hex_array(&inputs.registry_signing_seed_hex));
    let root_receipt = registry.apply(claim, inputs.accepted_at).unwrap();
    assert_eq!(root_receipt.account_id.as_str(), inputs.account_id);
    assert_eq!(root_receipt.handle.as_str(), inputs.handle);
    assert_eq!(
        root_receipt.receipt_hash(),
        hex_array(&inputs.claim_receipt_hash_hex)
    );
    assert_eq!(
        registry.verifying_key(),
        hex_array(&outputs.registry_public_key_hex)
    );

    let receipt = PrincipalProofReceipt {
        version: outputs.receipt_version,
        sequence: inputs.sequence,
        command_id: CommandId::from_bytes(hex_array(&inputs.command_id_hex)),
        account_id: root_receipt.account_id.clone(),
        handle: root_receipt.handle.clone(),
        account_revision: inputs.account_revision,
        claim_receipt_hash: hex_array(&inputs.claim_receipt_hash_hex),
        principal_proof_hash: hex_array(&inputs.principal_proof_hash_hex),
        nostr_public_key: hex_array(&inputs.nostr_public_key_hex),
        previous_proof_receipt_hash: hex_array(&inputs.previous_proof_receipt_hash_hex),
        previous_account_proof_receipt_hash: hex_array(
            &inputs.previous_account_proof_receipt_hash_hex,
        ),
        accepted_at: inputs.accepted_at,
        signature: hex_array(&outputs.signature_hex),
    };
    assert_eq!(
        receipt.signing_bytes(),
        hex::decode(&intermediates.receipt_signing_bytes_hex).unwrap()
    );
    receipt
        .verify(&hex_array(&outputs.registry_public_key_hex))
        .unwrap();
    assert_eq!(receipt.receipt_hash(), hex_array(&outputs.receipt_hash_hex));
    assert_eq!(
        receipt.to_bytes(),
        hex::decode(&outputs.encoded_receipt_hex).unwrap()
    );
    let decoded = PrincipalProofReceipt::from_bytes_for_claim_receipt(
        &receipt.to_bytes(),
        &root_receipt,
        &registry.verifying_key(),
    )
    .unwrap();
    assert_eq!(decoded, receipt);

    for length in 0..receipt.to_bytes().len() {
        assert!(
            PrincipalProofReceipt::from_bytes_for_claim_receipt(
                &receipt.to_bytes()[..length],
                &root_receipt,
                &registry.verifying_key(),
            )
            .is_err(),
            "truncation at {length} bytes must fail"
        );
    }
    let mut trailing = receipt.to_bytes();
    trailing.push(0);
    assert!(
        PrincipalProofReceipt::from_bytes_for_claim_receipt(
            &trailing,
            &root_receipt,
            &registry.verifying_key(),
        )
        .is_err()
    );

    let mut hash_preimage = RECEIPT_HASH_DOMAIN.to_vec();
    hash_preimage.extend_from_slice(&receipt.signing_bytes());
    hash_preimage.extend_from_slice(&receipt.signature);
    assert_eq!(
        hash_preimage,
        hex::decode(&intermediates.receipt_hash_preimage_hex).unwrap()
    );
}
