use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    principal_registry::{
        PrincipalRegistryError, PrincipalRegistryRestoreError, PrincipalRegistrySnapshot,
        PrincipalRegistryState,
    },
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

#[allow(clippy::too_many_arguments)]
fn validated_claim(
    account: &AccountSecrets,
    account_seed: u8,
    nostr_secret_key: [u8; 32],
    command_id: [u8; 32],
    handle: &str,
    expected_revision: u64,
    binding_revision: u64,
    proof_created_at: u64,
) -> ProofBearingDeviceHandleClaim {
    let device_signer = AccountSecrets::from_seeds(
        [account_seed.wrapping_add(1); 32],
        [account_seed.wrapping_add(2); 32],
    );
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Principal Registry Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: device_signer.public_identity().account_root_public_key,
            noise_public_key: [account_seed.wrapping_add(3); 32],
            nostr_public_key: nostr_public_key(&nostr_secret_key),
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
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret_key).unwrap();
    ProofBearingDeviceHandleClaim::new(claim, proof).unwrap()
}

#[test]
fn exact_replay_is_idempotent_and_conflicting_proof_is_rejected() {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let claim = validated_claim(&account, 0x20, [0x31; 32], [0x41; 32], "alice", 0, 1, 1_002);
    let different_proof =
        validated_claim(&account, 0x20, [0x31; 32], [0x41; 32], "alice", 0, 1, 1_003);
    let mut registry = PrincipalRegistryState::from_signing_seed([0x71; 32]);

    let first = registry.apply_device(claim.clone(), 2_000).unwrap();
    let replay = registry.apply_device(claim, 9_999).unwrap();
    assert_eq!(first, replay);
    assert_eq!(registry.head().unwrap().sequence, 1);
    assert_eq!(
        registry.apply_device(different_proof, 2_001),
        Err(PrincipalRegistryError::CommandIdConflict)
    );
    assert_eq!(registry.head().unwrap().sequence, 1);
}

#[test]
fn duplicate_public_key_is_rejected_before_root_state_mutates() {
    let alice = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let bob = AccountSecrets::from_seeds([0x51; 32], [0x52; 32]);
    let shared_nostr_secret = [0x31; 32];
    let alice_claim = validated_claim(
        &alice,
        0x20,
        shared_nostr_secret,
        [0x41; 32],
        "alice",
        0,
        1,
        1_002,
    );
    let bob_claim = validated_claim(
        &bob,
        0x60,
        shared_nostr_secret,
        [0x61; 32],
        "bob",
        0,
        1,
        1_002,
    );
    let bob_id = bob.public_identity().account_id;
    let mut registry = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let first = registry.apply_device(alice_claim, 2_000).unwrap();

    assert!(matches!(
        registry.apply_device(bob_claim, 2_001),
        Err(PrincipalRegistryError::PublicKeyAlreadyBound { .. })
    ));
    assert_eq!(registry.head(), Some(first.claim_receipt()));
    assert!(registry.account_record(bob_id.as_str()).is_none());
}

#[test]
fn same_account_can_rotate_its_device_nostr_key_atomically() {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let account_id = account.public_identity().account_id;
    let old_secret = [0x31; 32];
    let new_secret = [0x32; 32];
    let first = validated_claim(&account, 0x20, old_secret, [0x41; 32], "alice", 0, 1, 1_002);
    let second = validated_claim(&account, 0x20, new_secret, [0x42; 32], "alice", 1, 2, 1_003);
    let old_public_key = nostr_public_key(&old_secret);
    let new_public_key = nostr_public_key(&new_secret);
    let mut registry = PrincipalRegistryState::from_signing_seed([0x71; 32]);

    registry.apply_device(first, 2_000).unwrap();
    let current = registry.apply_device(second, 2_001).unwrap();

    assert!(registry.public_key_record(&old_public_key).is_none());
    assert_eq!(registry.public_key_record(&new_public_key), Some(&current));
    assert_eq!(registry.account_record(account_id.as_str()), Some(&current));
    assert_eq!(registry.head().unwrap().sequence, 2);
    current
        .claim_receipt()
        .verify_for_claim(&registry.verifying_key(), current.claim())
        .unwrap();
    let validated = ProofBearingDeviceHandleClaim::new(
        current.claim().clone(),
        current.principal_proof().clone(),
    )
    .unwrap();
    current
        .principal_receipt()
        .verify_for(
            &registry.verifying_key(),
            &validated,
            current.claim_receipt(),
        )
        .unwrap();
}

#[test]
fn proof_receipts_bind_evidence_and_preserve_both_chains() {
    let alice = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let bob = AccountSecrets::from_seeds([0x51; 32], [0x52; 32]);
    let alice_first = validated_claim(&alice, 0x20, [0x31; 32], [0x41; 32], "alice", 0, 1, 1_002);
    let bob_first = validated_claim(&bob, 0x60, [0x71; 32], [0x61; 32], "bob", 0, 1, 1_002);
    let alice_second = validated_claim(&alice, 0x20, [0x32; 32], [0x42; 32], "alice", 1, 2, 1_003);
    let mut registry = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let pinned_key = registry.verifying_key();

    let first = registry.apply_device(alice_first, 2_000).unwrap();
    let second = registry.apply_device(bob_first, 2_001).unwrap();
    let third = registry.apply_device(alice_second, 2_002).unwrap();

    first
        .principal_receipt()
        .verify_after(&pinned_key, None)
        .unwrap();
    second
        .principal_receipt()
        .verify_after(&pinned_key, Some(first.principal_receipt()))
        .unwrap();
    third
        .principal_receipt()
        .verify_after(&pinned_key, Some(second.principal_receipt()))
        .unwrap();

    first
        .principal_receipt()
        .verify_account_after(&pinned_key, None)
        .unwrap();
    second
        .principal_receipt()
        .verify_account_after(&pinned_key, None)
        .unwrap();
    third
        .principal_receipt()
        .verify_account_after(&pinned_key, Some(first.principal_receipt()))
        .unwrap();

    let mut tampered = third.principal_receipt().clone();
    tampered.accepted_at += 1;
    assert!(tampered.verify(&pinned_key).is_err());
}

#[test]
fn signed_snapshot_replays_exact_state_and_indexes_after_restart() {
    let signing_seed = [0x71; 32];
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let account_id = account.public_identity().account_id;
    let first = validated_claim(&account, 0x20, [0x31; 32], [0x41; 32], "alice", 0, 1, 1_002);
    let second = validated_claim(&account, 0x20, [0x32; 32], [0x42; 32], "alice", 1, 2, 1_003);
    let replay = second.clone();
    let current_public_key = second.principal_proof().payload().nostr_public_key();
    let mut registry = PrincipalRegistryState::from_signing_seed(signing_seed);
    registry.apply_device(first, 2_000).unwrap();
    let expected = registry.apply_device(second, 2_001).unwrap();
    let snapshot = registry.snapshot();
    let expected_head = snapshot.head.clone();
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded: PrincipalRegistrySnapshot = serde_json::from_slice(&encoded).unwrap();

    let mut restored =
        PrincipalRegistryState::restore(signing_seed, decoded, Some(&expected_head)).unwrap();
    assert_eq!(
        restored.account_record(account_id.as_str()),
        Some(&expected)
    );
    assert_eq!(
        restored.public_key_record(&current_public_key),
        Some(&expected)
    );
    assert_eq!(restored.apply_device(replay, 9_999).unwrap(), expected);
    assert_eq!(restored.head().unwrap().sequence, 2);
}

#[test]
fn snapshot_corruption_truncation_wrong_key_and_rollback_fail_closed() {
    let signing_seed = [0x71; 32];
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let first = validated_claim(&account, 0x20, [0x31; 32], [0x41; 32], "alice", 0, 1, 1_002);
    let second = validated_claim(&account, 0x20, [0x32; 32], [0x42; 32], "alice", 1, 2, 1_003);
    let mut registry = PrincipalRegistryState::from_signing_seed(signing_seed);
    registry.apply_device(first, 2_000).unwrap();
    let old_snapshot = registry.snapshot();
    registry.apply_device(second, 2_001).unwrap();
    let current_snapshot = registry.snapshot();
    let current_head = current_snapshot.head.clone();

    let mut corrupt = current_snapshot.clone();
    corrupt.entries[0].principal_proof[0] ^= 1;
    assert_eq!(
        PrincipalRegistryState::restore(signing_seed, corrupt, None)
            .err()
            .unwrap(),
        PrincipalRegistryRestoreError::InvalidSignature
    );

    let mut truncated = current_snapshot.clone();
    truncated.entries.pop();
    truncated.head.entry_count -= 1;
    assert_eq!(
        PrincipalRegistryState::restore(signing_seed, truncated, None)
            .err()
            .unwrap(),
        PrincipalRegistryRestoreError::InvalidSignature
    );

    assert_eq!(
        PrincipalRegistryState::restore([0x72; 32], current_snapshot, None)
            .err()
            .unwrap(),
        PrincipalRegistryRestoreError::InvalidSignature
    );
    assert_eq!(
        PrincipalRegistryState::restore(signing_seed, old_snapshot, Some(&current_head))
            .err()
            .unwrap(),
        PrincipalRegistryRestoreError::RollbackDetected
    );
}
