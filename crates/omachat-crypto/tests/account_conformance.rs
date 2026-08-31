use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema_version: u16,
    registry_signing_seed_hex: String,
    accounts: Vec<AccountInput>,
    transitions: Vec<TransitionInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountInput {
    id: String,
    account_root_seed_hex: String,
    recovery_seed_hex: String,
    device: DeviceInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceInput {
    signing_seed_hex: String,
    noise_secret_hex: String,
    nostr_secret_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionInput {
    id: String,
    account: String,
    command_id_hex: String,
    expected_registry_revision: u64,
    handle: String,
    display_name: String,
    binding_revision: u64,
    issued_at: u64,
    accepted_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intermediates {
    schema_version: u16,
    transitions: Vec<IntermediateTransition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntermediateTransition {
    id: String,
    binding_signing_bytes_hex: String,
    claim_proof_digest_hex: String,
    claim_proof_signing_bytes_hex: String,
    receipt_signing_bytes_hex: String,
    receipt_hash_preimage_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outputs {
    schema_version: u16,
    registry_public_key_hex: String,
    accounts: Vec<AccountOutput>,
    transitions: Vec<TransitionOutput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountOutput {
    id: String,
    account_id: String,
    account_root_public_key_hex: String,
    recovery_public_key_hex: String,
    device_id: String,
    device_signing_public_key_hex: String,
    noise_public_key_hex: String,
    nostr_public_key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionOutput {
    id: String,
    binding_signature_hex: String,
    claim_proof_hex: String,
    claim_hash_hex: String,
    receipt: ReceiptOutput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptOutput {
    version: u16,
    sequence: u64,
    command_id_hex: String,
    account_id: String,
    handle: String,
    account_revision: u64,
    claim_hash_hex: String,
    previous_receipt_hash_hex: String,
    previous_account_receipt_hash_hex: String,
    accepted_at: u64,
    signature_hex: String,
    receipt_hash_hex: String,
}

fn fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/fixtures/omachat-account-registry-v1")
        .join(file_name)
}

fn read_json<T: for<'de> Deserialize<'de>>(file_name: &str) -> T {
    serde_json::from_slice(
        &fs::read(fixture_path(file_name))
            .expect("committed conformance artifact must be readable"),
    )
    .expect("committed conformance artifact must have the expected strict schema")
}

fn hex_array<const N: usize>(encoded: &str) -> [u8; N] {
    hex::decode(encoded)
        .expect("fixture hex must decode")
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}

#[test]
fn account_bindings_match_independent_python_transcripts() {
    let inputs: Inputs = read_json("inputs.json");
    let intermediates: Intermediates = read_json("intermediates.json");
    let outputs: Outputs = read_json("outputs.json");

    assert_eq!(inputs.schema_version, 1);
    assert_eq!(intermediates.schema_version, 1);
    assert_eq!(outputs.schema_version, 1);
    assert_eq!(
        hex::decode(&inputs.registry_signing_seed_hex)
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        hex::decode(&outputs.registry_public_key_hex).unwrap().len(),
        32
    );
    assert_eq!(inputs.accounts.len(), 2);
    assert_eq!(inputs.transitions.len(), 3);

    for source in &inputs.accounts {
        let expected = outputs
            .accounts
            .iter()
            .find(|output| output.id == source.id)
            .expect("every fixture account must have derived outputs");
        let account = AccountSecrets::from_seeds(
            hex_array(&source.account_root_seed_hex),
            hex_array(&source.recovery_seed_hex),
        );
        let public = account.public_identity();
        assert_eq!(public.account_id.as_str(), expected.account_id);
        assert_eq!(
            public.account_root_public_key,
            hex_array(&expected.account_root_public_key_hex)
        );
        assert_eq!(
            public.recovery_public_key,
            hex_array(&expected.recovery_public_key_hex)
        );

        let device_secrets = IdentitySecrets::from_all_seeds(
            hex_array(&source.device.noise_secret_hex),
            hex_array(&source.device.signing_seed_hex),
            hex_array(&source.device.nostr_secret_hex),
            [0_u8; 32],
        );
        let device_identity = device_secrets.public_identity();
        let nostr_identity = device_secrets
            .device_nostr_identity()
            .expect("synthetic Nostr scalar is valid");
        assert_eq!(
            device_identity.signing_public_key,
            hex_array(&expected.device_signing_public_key_hex)
        );
        assert_eq!(
            device_identity.noise_public_key,
            hex_array(&expected.noise_public_key_hex)
        );
        assert_eq!(
            *nostr_identity.public_key(),
            hex_array(&expected.nostr_public_key_hex)
        );
    }

    for transition in &inputs.transitions {
        let source = inputs
            .accounts
            .iter()
            .find(|account| account.id == transition.account)
            .expect("transition account must exist");
        let expected_account = outputs
            .accounts
            .iter()
            .find(|account| account.id == transition.account)
            .expect("transition account outputs must exist");
        let intermediate = intermediates
            .transitions
            .iter()
            .find(|candidate| candidate.id == transition.id)
            .expect("transition intermediate must exist");
        let expected = outputs
            .transitions
            .iter()
            .find(|candidate| candidate.id == transition.id)
            .expect("transition output must exist");

        let device_secrets = IdentitySecrets::from_all_seeds(
            hex_array(&source.device.noise_secret_hex),
            hex_array(&source.device.signing_seed_hex),
            hex_array(&source.device.nostr_secret_hex),
            [0_u8; 32],
        );
        let device_identity = device_secrets.public_identity();
        let nostr_identity = device_secrets
            .device_nostr_identity()
            .expect("synthetic Nostr scalar is valid");
        let binding = AccountSecrets::from_seeds(
            hex_array(&source.account_root_seed_hex),
            hex_array(&source.recovery_seed_hex),
        )
        .sign_local_binding(
            Some(GlobalHandle::parse(&transition.handle).unwrap()),
            Some(DisplayName::parse(&transition.display_name).unwrap()),
            DevicePublicKeys {
                signing_public_key: device_identity.signing_public_key,
                noise_public_key: device_identity.noise_public_key,
                nostr_public_key: *nostr_identity.public_key(),
            },
            transition.binding_revision,
            transition.issued_at,
        );

        binding.verify().expect("fixture binding must verify");
        assert_eq!(binding.account_id.as_str(), expected_account.account_id);
        assert_eq!(binding.device_id.as_str(), expected_account.device_id);
        assert_eq!(
            binding.signing_bytes(),
            hex::decode(&intermediate.binding_signing_bytes_hex).unwrap()
        );
        assert_eq!(
            binding.signature,
            hex_array(&expected.binding_signature_hex)
        );

        // These fields are consumed by the registry conformance test. Reading
        // them here keeps the fixture schemas jointly strict across crates.
        assert_eq!(hex::decode(&transition.command_id_hex).unwrap().len(), 32);
        assert_eq!(
            transition.expected_registry_revision + 1,
            expected.receipt.account_revision
        );
        assert_eq!(transition.accepted_at, expected.receipt.accepted_at);
        assert_eq!(expected.id, transition.id);
        assert_eq!(hex::decode(&expected.claim_proof_hex).unwrap().len(), 64);
        assert_eq!(hex::decode(&expected.claim_hash_hex).unwrap().len(), 32);
        assert_eq!(
            hex::decode(&intermediate.claim_proof_digest_hex)
                .unwrap()
                .len(),
            32
        );
        assert!(!intermediate.claim_proof_signing_bytes_hex.is_empty());
        assert!(!intermediate.receipt_signing_bytes_hex.is_empty());
        assert!(!intermediate.receipt_hash_preimage_hex.is_empty());
        assert_eq!(expected.receipt.version, 1);
        assert!(expected.receipt.sequence > 0);
        assert_eq!(expected.receipt.command_id_hex, transition.command_id_hex);
        assert_eq!(expected.receipt.account_id, expected_account.account_id);
        assert_eq!(expected.receipt.handle, transition.handle);
        assert_eq!(expected.receipt.claim_hash_hex, expected.claim_hash_hex);
        assert_eq!(
            hex::decode(&expected.receipt.previous_receipt_hash_hex)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            hex::decode(&expected.receipt.previous_account_receipt_hash_hex)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            hex::decode(&expected.receipt.signature_hex).unwrap().len(),
            64
        );
        assert_eq!(
            hex::decode(&expected.receipt.receipt_hash_hex)
                .unwrap()
                .len(),
            32
        );
    }
}
