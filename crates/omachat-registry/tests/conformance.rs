use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, SignedLocalAccountBinding,
};
use omachat_registry::{CommandId, HandleClaim, RegistryReceipt, RegistryState};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::PathBuf};

const CLAIM_PROOF_DOMAIN: &[u8] = b"omachat.registry-handle-claim-proof.v1\0";

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

fn fixture_binding(
    transition: &TransitionInput,
    source: &AccountInput,
    expected_account: &AccountOutput,
) -> SignedLocalAccountBinding {
    AccountSecrets::from_seeds(
        hex_array(&source.account_root_seed_hex),
        hex_array(&source.recovery_seed_hex),
    )
    .sign_local_binding(
        Some(GlobalHandle::parse(&transition.handle).unwrap()),
        Some(DisplayName::parse(&transition.display_name).unwrap()),
        DevicePublicKeys {
            signing_public_key: hex_array(&expected_account.device_signing_public_key_hex),
            noise_public_key: hex_array(&expected_account.noise_public_key_hex),
            nostr_public_key: hex_array(&expected_account.nostr_public_key_hex),
        },
        transition.binding_revision,
        transition.issued_at,
    )
}

#[test]
fn registry_receipts_match_independent_python_transcripts() {
    let inputs: Inputs = read_json("inputs.json");
    let intermediates: Intermediates = read_json("intermediates.json");
    let outputs: Outputs = read_json("outputs.json");
    assert_eq!(inputs.schema_version, 1);
    assert_eq!(intermediates.schema_version, 1);
    assert_eq!(outputs.schema_version, 1);
    assert_eq!(inputs.transitions.len(), 3);

    let mut registry =
        RegistryState::from_signing_seed(hex_array(&inputs.registry_signing_seed_hex));
    let pinned_registry_key = registry.verifying_key();
    assert_eq!(
        pinned_registry_key,
        hex_array(&outputs.registry_public_key_hex)
    );

    let mut global_receipts: Vec<RegistryReceipt> = Vec::new();
    let mut account_receipts: BTreeMap<String, RegistryReceipt> = BTreeMap::new();
    for transition in &inputs.transitions {
        let source = inputs
            .accounts
            .iter()
            .find(|account| account.id == transition.account)
            .expect("transition account input must exist");
        let expected_account = outputs
            .accounts
            .iter()
            .find(|account| account.id == transition.account)
            .expect("transition account output must exist");
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

        let binding = fixture_binding(transition, source, expected_account);
        assert_eq!(binding.account_id.as_str(), expected_account.account_id);
        assert_eq!(binding.device_id.as_str(), expected_account.device_id);
        assert_eq!(
            binding.account_root_public_key,
            hex_array(&expected_account.account_root_public_key_hex)
        );
        assert_eq!(
            binding.recovery_public_key,
            hex_array(&expected_account.recovery_public_key_hex)
        );
        assert_eq!(
            binding.signing_bytes(),
            hex::decode(&intermediate.binding_signing_bytes_hex).unwrap()
        );
        assert_eq!(
            binding.signature,
            hex_array(&expected.binding_signature_hex)
        );

        let command_id = CommandId::from_bytes(hex_array(&transition.command_id_hex));
        let account = AccountSecrets::from_seeds(
            hex_array(&source.account_root_seed_hex),
            hex_array(&source.recovery_seed_hex),
        );
        let claim = HandleClaim::sign(
            command_id,
            transition.expected_registry_revision,
            binding,
            &account,
        )
        .expect("fixture claim must verify");
        let proof_digest = claim.proof_digest();
        assert_eq!(
            proof_digest,
            hex_array(&intermediate.claim_proof_digest_hex)
        );
        assert_eq!(
            [CLAIM_PROOF_DOMAIN, proof_digest.as_slice()].concat(),
            hex::decode(&intermediate.claim_proof_signing_bytes_hex).unwrap()
        );
        assert_eq!(*claim.proof(), hex_array(&expected.claim_proof_hex));
        assert_eq!(claim.claim_hash(), hex_array(&expected.claim_hash_hex));

        let receipt = registry
            .apply(claim.clone(), transition.accepted_at)
            .expect("fixture transition must be accepted");
        let expected_receipt = &expected.receipt;
        assert_eq!(expected.id, transition.id);
        assert_eq!(receipt.version, expected_receipt.version);
        assert_eq!(receipt.sequence, expected_receipt.sequence);
        assert_eq!(
            receipt.command_id,
            CommandId::from_bytes(hex_array(&expected_receipt.command_id_hex))
        );
        assert_eq!(receipt.account_id.as_str(), expected_receipt.account_id);
        assert_eq!(receipt.handle.as_str(), expected_receipt.handle);
        assert_eq!(receipt.account_revision, expected_receipt.account_revision);
        assert_eq!(
            receipt.claim_hash,
            hex_array(&expected_receipt.claim_hash_hex)
        );
        assert_eq!(
            receipt.previous_receipt_hash,
            hex_array(&expected_receipt.previous_receipt_hash_hex)
        );
        assert_eq!(
            receipt.previous_account_receipt_hash,
            hex_array(&expected_receipt.previous_account_receipt_hash_hex)
        );
        assert_eq!(receipt.accepted_at, expected_receipt.accepted_at);
        assert_eq!(
            receipt.signature,
            hex_array(&expected_receipt.signature_hex)
        );
        assert_eq!(
            receipt.signing_bytes(),
            hex::decode(&intermediate.receipt_signing_bytes_hex).unwrap()
        );
        let receipt_hash_preimage = [
            u64::try_from(receipt.signing_bytes().len())
                .unwrap()
                .to_be_bytes()
                .as_slice(),
            receipt.signing_bytes().as_slice(),
            receipt.signature.as_slice(),
        ]
        .concat();
        assert_eq!(
            receipt_hash_preimage,
            hex::decode(&intermediate.receipt_hash_preimage_hex).unwrap()
        );
        assert_eq!(
            receipt.receipt_hash(),
            hex_array(&expected_receipt.receipt_hash_hex)
        );
        receipt
            .verify_for_claim(&pinned_registry_key, &claim)
            .expect("receipt must be bound to this exact claim");
        receipt
            .verify_after(&pinned_registry_key, global_receipts.last())
            .expect("receipt must extend the global chain");
        receipt
            .verify_account_after(
                &pinned_registry_key,
                account_receipts.get(receipt.account_id.as_str()),
            )
            .expect("receipt must extend its account chain");

        account_receipts.insert(receipt.account_id.to_string(), receipt.clone());
        global_receipts.push(receipt);
    }

    assert_eq!(global_receipts.len(), 3);
    assert_eq!(
        global_receipts[2].previous_receipt_hash,
        global_receipts[1].receipt_hash()
    );
    assert_eq!(
        global_receipts[2].previous_account_receipt_hash,
        global_receipts[0].receipt_hash()
    );
    assert_ne!(
        global_receipts[2].previous_receipt_hash,
        global_receipts[2].previous_account_receipt_hash
    );

    // The input device scalars are intentionally committed test-only private
    // material; the account kernel test independently checks their derivation.
    for account in inputs.accounts {
        assert_eq!(
            hex::decode(account.device.signing_seed_hex).unwrap().len(),
            32
        );
        assert_eq!(
            hex::decode(account.device.noise_secret_hex).unwrap().len(),
            32
        );
        assert_eq!(
            hex::decode(account.device.nostr_secret_hex).unwrap().len(),
            32
        );
    }
}
