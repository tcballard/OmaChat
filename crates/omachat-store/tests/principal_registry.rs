use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    principal_registry::{PrincipalRegistryRestoreError, PrincipalRegistrySnapshot},
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_store::{
    PrincipalRegistryVault, PrincipalRegistryVaultError, RequestedProvider, SealedStore,
};
use tempfile::tempdir;

const STATE_RECORD: &str = "principal-registry-state-v1";

#[allow(clippy::too_many_arguments)]
fn validated_claim(
    account: &AccountSecrets,
    seed: u8,
    command_id: [u8; 32],
    handle: &str,
    expected_revision: u64,
    binding_revision: u64,
    proof_created_at: u64,
) -> ProofBearingDeviceHandleClaim {
    let identity = IdentitySecrets::from_all_seeds(
        [seed; 32],
        [seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
        [seed.wrapping_add(3); 32],
    );
    let nostr_identity = identity.device_nostr_identity().unwrap();
    let device_signer =
        AccountSecrets::from_seeds([seed.wrapping_add(4); 32], [seed.wrapping_add(5); 32]);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Principal Vault Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: device_signer.public_identity().account_root_public_key,
            noise_public_key: [seed.wrapping_add(6); 32],
            nostr_public_key: *nostr_identity.public_key(),
        },
        binding_revision,
        1_000 + binding_revision,
    );
    let claim = HandleClaim::sign(
        CommandId::from_bytes(command_id),
        expected_revision,
        binding,
        account,
    )
    .unwrap();
    let payload = NostrPrincipalControlPayload::new(
        claim.claim_hash(),
        command_id,
        expected_revision,
        claim.binding().account_id.as_str(),
        claim.binding().handle.as_ref().unwrap().as_str(),
        NostrPrincipalType::Device,
        claim.binding().device_keys.nostr_public_key,
        device_authorisation_hash(claim.binding()),
        proof_created_at,
    )
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, *nostr_identity.private_key()).unwrap();
    ProofBearingDeviceHandleClaim::new(claim, proof).unwrap()
}

#[tokio::test]
async fn sealed_principal_state_survives_restart_and_exact_replay() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let signing_seed = [0x71; 32];
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let account_id = account.public_identity().account_id;
    let claim = validated_claim(&account, 0x20, [0x41; 32], "alice", 0, 1, 1_002);
    let replay = claim.clone();
    let public_key = claim.principal_proof().payload().nostr_public_key();

    let mut initial = PrincipalRegistryVault::load_or_create(&store, signing_seed, None).unwrap();
    let expected = initial.apply_device(claim, 2_000).unwrap();
    let head = PrincipalRegistryVault::persist(&store, &initial).unwrap();

    let mut restored =
        PrincipalRegistryVault::load_or_create(&store, signing_seed, Some(&head)).unwrap();
    assert_eq!(
        restored.account_record(account_id.as_str()),
        Some(&expected)
    );
    assert_eq!(restored.public_key_record(&public_key), Some(&expected));
    assert_eq!(restored.apply_device(replay, 9_999).unwrap(), expected);
    assert_eq!(restored.head().unwrap().sequence, 1);
}

#[tokio::test]
async fn older_valid_sealed_state_is_rejected_against_newer_head_anchor() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let signing_seed = [0x71; 32];
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let first = validated_claim(&account, 0x20, [0x41; 32], "alice", 0, 1, 1_002);
    let second = validated_claim(&account, 0x21, [0x42; 32], "alice", 1, 2, 1_003);
    let mut state = PrincipalRegistryVault::load_or_create(&store, signing_seed, None).unwrap();
    state.apply_device(first, 2_000).unwrap();
    PrincipalRegistryVault::persist(&store, &state).unwrap();
    let older_plaintext = store.read(STATE_RECORD).unwrap();
    state.apply_device(second, 2_001).unwrap();
    let current_head = PrincipalRegistryVault::persist(&store, &state).unwrap();

    store.write(STATE_RECORD, &older_plaintext).unwrap();
    let replayed_record = store.read(STATE_RECORD).unwrap();
    assert!(matches!(
        PrincipalRegistryVault::load_or_create(&store, signing_seed, Some(&current_head)),
        Err(PrincipalRegistryVaultError::Restore(
            PrincipalRegistryRestoreError::RollbackDetected
        ))
    ));
    assert_eq!(store.read(STATE_RECORD).unwrap(), replayed_record);
}

#[tokio::test]
async fn malformed_wrong_key_unsupported_and_missing_anchored_state_fail_closed() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let signing_seed = [0x71; 32];

    store.write(STATE_RECORD, b"not-json").unwrap();
    assert!(matches!(
        PrincipalRegistryVault::load_or_create(&store, signing_seed, None),
        Err(PrincipalRegistryVaultError::Encoding)
    ));

    store.delete(STATE_RECORD).unwrap();
    let state = PrincipalRegistryVault::load_or_create(&store, signing_seed, None).unwrap();
    let mut unsupported = state.snapshot();
    unsupported.version = 2;
    store
        .write(STATE_RECORD, &serde_json::to_vec(&unsupported).unwrap())
        .unwrap();
    assert!(matches!(
        PrincipalRegistryVault::load_or_create(&store, signing_seed, None),
        Err(PrincipalRegistryVaultError::UnsupportedVersion(2))
    ));

    let valid_snapshot: PrincipalRegistrySnapshot = state.snapshot();
    store
        .write(STATE_RECORD, &serde_json::to_vec(&valid_snapshot).unwrap())
        .unwrap();
    assert!(matches!(
        PrincipalRegistryVault::load_or_create(&store, [0x72; 32], None),
        Err(PrincipalRegistryVaultError::Restore(
            PrincipalRegistryRestoreError::InvalidSignature
        ))
    ));

    let anchored_head = valid_snapshot.head;
    store.delete(STATE_RECORD).unwrap();
    assert!(matches!(
        PrincipalRegistryVault::load_or_create(&store, signing_seed, Some(&anchored_head)),
        Err(PrincipalRegistryVaultError::MissingAnchoredState)
    ));
}
