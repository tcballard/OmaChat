use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
};
use omachat_registry::{CommandId, HandleClaim, RegistryError, RegistryState};

fn account(seed: u8) -> AccountSecrets {
    AccountSecrets::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
}

fn device_keys(seed: u8) -> DevicePublicKeys {
    let signing = account(seed.wrapping_add(10)).public_identity();
    let nostr = IdentitySecrets::from_seeds(
        [seed.wrapping_add(20); 32],
        [seed.wrapping_add(21); 32],
        [seed.wrapping_add(22); 32],
    )
    .device_nostr_identity()
    .unwrap();
    DevicePublicKeys {
        signing_public_key: signing.account_root_public_key,
        noise_public_key: [seed.wrapping_add(30); 32],
        nostr_public_key: *nostr.public_key(),
    }
}

fn binding(
    account: &AccountSecrets,
    handle: &str,
    revision: u64,
) -> omachat_crypto::SignedLocalAccountBinding {
    account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Registry Test").unwrap()),
        device_keys(revision as u8),
        revision,
        1_788_000_000 + revision,
    )
}

fn claim(
    account: &AccountSecrets,
    command: u8,
    handle: &str,
    expected_revision: u64,
) -> HandleClaim {
    claim_with_binding_revision(
        account,
        command,
        handle,
        expected_revision,
        expected_revision + 1,
    )
}

fn claim_with_binding_revision(
    account: &AccountSecrets,
    command: u8,
    handle: &str,
    expected_registry_revision: u64,
    binding_revision: u64,
) -> HandleClaim {
    HandleClaim::sign(
        CommandId::from_bytes([command; 32]),
        expected_registry_revision,
        binding(account, handle, binding_revision),
        account,
    )
    .unwrap()
}

#[test]
fn initial_claim_accepts_a_later_local_binding_revision() {
    let alice = account(1);
    let mut registry = RegistryState::from_signing_seed([90; 32]);

    // A daemon first persists an unconfigured rev-1 binding, then configuring
    // the first handle creates rev 2 before the registry has any account state.
    let first = registry
        .apply(claim_with_binding_revision(&alice, 1, "alice", 0, 2), 100)
        .unwrap();

    assert_eq!(first.account_revision, 1);
    assert_eq!(registry.account_revision(&first.account_id), Some(1));
    assert_eq!(
        registry
            .account_binding(&first.account_id)
            .unwrap()
            .revision,
        2
    );

    let non_advancing = claim_with_binding_revision(&alice, 2, "alice", 1, 2);
    assert_eq!(
        registry.apply(non_advancing, 101),
        Err(RegistryError::StaleBindingRevision {
            proposed: 2,
            current: 2,
        })
    );
    assert_eq!(registry.head(), Some(&first));

    let advancing = claim_with_binding_revision(&alice, 3, "alice", 1, 4);
    let second = registry.apply(advancing, 102).unwrap();
    assert_eq!(second.account_revision, 2);
    assert_eq!(registry.account_revision(&second.account_id), Some(2));
    assert_eq!(
        registry
            .account_binding(&second.account_id)
            .unwrap()
            .revision,
        4
    );
}

#[test]
fn duplicate_handle_conflict_is_atomic() {
    let alice = account(1);
    let bob = account(3);
    let mut registry = RegistryState::from_signing_seed([90; 32]);

    let alice_receipt = registry.apply(claim(&alice, 1, "alice", 0), 100).unwrap();
    let error = registry.apply(claim(&bob, 2, "alice", 0), 101).unwrap_err();

    assert_eq!(
        error,
        RegistryError::HandleTaken(GlobalHandle::parse("alice").unwrap())
    );
    assert_eq!(
        registry.handle_owner(&GlobalHandle::parse("alice").unwrap()),
        Some(&alice.public_identity().account_id)
    );
    assert!(
        registry
            .account_binding(&bob.public_identity().account_id)
            .is_none()
    );
    assert_eq!(registry.head(), Some(&alice_receipt));
}

#[test]
fn exact_replay_is_idempotent_but_command_reuse_is_rejected() {
    let alice = account(1);
    let mut registry = RegistryState::from_signing_seed([90; 32]);
    let first_claim = claim(&alice, 1, "alice", 0);

    let first = registry.apply(first_claim.clone(), 100).unwrap();
    let replay = registry.apply(first_claim, 999).unwrap();
    assert_eq!(replay, first);
    assert_eq!(registry.head().unwrap().sequence, 1);

    let reused_id = HandleClaim::sign(
        CommandId::from_bytes([1; 32]),
        1,
        binding(&alice, "alice2", 2),
        &alice,
    )
    .unwrap();
    assert_eq!(
        registry.apply(reused_id, 101),
        Err(RegistryError::CommandIdConflict)
    );
    assert_eq!(registry.head(), Some(&first));
}

#[test]
fn stale_revision_does_not_mutate_current_state() {
    let alice = account(1);
    let mut registry = RegistryState::from_signing_seed([90; 32]);
    let first = registry.apply(claim(&alice, 1, "alice", 0), 100).unwrap();

    let stale = claim(&alice, 2, "alice2", 0);
    assert_eq!(
        registry.apply(stale, 101),
        Err(RegistryError::StaleRevision {
            expected: 0,
            current: 1,
        })
    );
    assert_eq!(registry.head(), Some(&first));
    assert_eq!(
        registry.handle_owner(&GlobalHandle::parse("alice").unwrap()),
        Some(&alice.public_identity().account_id)
    );
    assert!(
        registry
            .handle_owner(&GlobalHandle::parse("alice2").unwrap())
            .is_none()
    );
}

#[test]
fn claim_and_receipt_tampering_are_detected() {
    let alice = account(1);
    let original = claim(&alice, 1, "alice", 0);

    let mut bad_proof = *original.proof();
    bad_proof[0] ^= 1;
    assert_eq!(
        HandleClaim::from_signed_parts(
            original.command_id(),
            original.expected_revision(),
            original.binding().clone(),
            bad_proof,
        ),
        Err(RegistryError::InvalidClaimProof)
    );

    let mut changed_binding = original.binding().clone();
    changed_binding.handle = Some(GlobalHandle::parse("alice2").unwrap());
    assert!(matches!(
        HandleClaim::from_signed_parts(
            original.command_id(),
            original.expected_revision(),
            changed_binding,
            *original.proof(),
        ),
        Err(RegistryError::InvalidBinding(_))
    ));

    let mut registry = RegistryState::from_signing_seed([90; 32]);
    let pinned_key = registry.verifying_key();
    let receipt_claim = original.clone();
    let receipt = registry.apply(original, 100).unwrap();
    receipt.verify_after(&pinned_key, None).unwrap();
    receipt
        .verify_for_claim(&pinned_key, &receipt_claim)
        .unwrap();

    let mut changed_receipt = receipt.clone();
    changed_receipt.accepted_at += 1;
    assert_eq!(
        changed_receipt.verify(&pinned_key),
        Err(RegistryError::InvalidReceiptSignature)
    );

    let wrong_key = RegistryState::from_signing_seed([91; 32]).verifying_key();
    assert_eq!(
        receipt.verify(&wrong_key),
        Err(RegistryError::InvalidReceiptSignature)
    );
}

#[test]
fn receipt_verification_is_bound_to_the_exact_claim() {
    let alice = account(1);
    let bob = account(3);
    let accepted_claim = claim(&alice, 1, "alice", 0);
    let mut registry = RegistryState::from_signing_seed([90; 32]);
    let pinned_key = registry.verifying_key();
    let receipt = registry.apply(accepted_claim.clone(), 100).unwrap();

    receipt
        .verify_for_claim(&pinned_key, &accepted_claim)
        .unwrap();

    let wrong_command = claim(&alice, 2, "alice", 0);
    let wrong_account = claim(&bob, 1, "bob", 0);
    let wrong_handle = claim(&alice, 1, "alice_alt", 0);
    let wrong_claim_hash = claim_with_binding_revision(&alice, 1, "alice", 0, 2);
    for hostile_claim in [wrong_command, wrong_account, wrong_handle, wrong_claim_hash] {
        assert_eq!(
            receipt.verify_for_claim(&pinned_key, &hostile_claim),
            Err(RegistryError::ReceiptClaimMismatch)
        );
    }
}

#[test]
fn interleaved_receipts_preserve_global_and_per_account_chains() {
    let alice = account(1);
    let bob = account(3);
    let mut registry = RegistryState::from_signing_seed([90; 32]);
    let pinned_key = registry.verifying_key();

    let alice_first = registry.apply(claim(&alice, 1, "alice", 0), 100).unwrap();
    let bob_first = registry.apply(claim(&bob, 2, "bob", 0), 101).unwrap();
    let alice_second = registry.apply(claim(&alice, 3, "alice", 1), 102).unwrap();

    alice_first.verify_after(&pinned_key, None).unwrap();
    bob_first
        .verify_after(&pinned_key, Some(&alice_first))
        .unwrap();
    alice_second
        .verify_after(&pinned_key, Some(&bob_first))
        .unwrap();

    alice_first.verify_account_after(&pinned_key, None).unwrap();
    bob_first.verify_account_after(&pinned_key, None).unwrap();
    alice_second
        .verify_account_after(&pinned_key, Some(&alice_first))
        .unwrap();
    assert_eq!(alice_second.sequence, 3);
    assert_eq!(alice_second.account_revision, 2);
    assert_eq!(alice_second.previous_receipt_hash, bob_first.receipt_hash());
    assert_eq!(
        alice_second.previous_account_receipt_hash,
        alice_first.receipt_hash()
    );
    assert_eq!(
        alice_second.verify_account_after(&pinned_key, Some(&bob_first)),
        Err(RegistryError::InvalidAccountReceiptChain)
    );
    assert_eq!(
        alice_second.verify_after(&pinned_key, Some(&alice_first)),
        Err(RegistryError::InvalidReceiptChain)
    );
}

#[test]
fn handle_rename_is_deferred_without_a_reuse_policy() {
    let alice = account(1);
    let bob = account(3);
    let mut registry = RegistryState::from_signing_seed([90; 32]);
    let first = registry.apply(claim(&alice, 1, "alice", 0), 100).unwrap();

    assert_eq!(
        registry.apply(claim(&alice, 2, "alice_new", 1), 101),
        Err(RegistryError::HandleRenameDeferred)
    );
    assert_eq!(
        registry.apply(claim(&bob, 3, "alice", 0), 102),
        Err(RegistryError::HandleTaken(
            GlobalHandle::parse("alice").unwrap()
        ))
    );
    assert_eq!(registry.head(), Some(&first));
    assert_eq!(
        registry.handle_owner(&GlobalHandle::parse("alice").unwrap()),
        Some(&alice.public_identity().account_id)
    );
    assert!(
        registry
            .handle_owner(&GlobalHandle::parse("alice_new").unwrap())
            .is_none()
    );
}

#[test]
fn claim_signer_must_match_bound_account() {
    let alice = account(1);
    let bob = account(3);
    assert_eq!(
        HandleClaim::sign(
            CommandId::from_bytes([1; 32]),
            0,
            binding(&alice, "alice", 1),
            &bob,
        ),
        Err(RegistryError::ClaimAccountMismatch)
    );
}
