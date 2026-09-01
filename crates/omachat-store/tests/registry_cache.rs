use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
    SignedLocalAccountBinding,
};
use omachat_registry::{
    AcceptedRegistryRecord, CommandId, HandleClaim, RegistryError, RegistryState,
};
use omachat_store::{
    RegistryCacheError, RegistryCacheLookup, RequestedProvider, SealedStore, VerifiedRegistryCache,
};
use tempfile::tempdir;

fn account(seed: u8) -> AccountSecrets {
    AccountSecrets::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
}

fn identity(seed: u8) -> IdentitySecrets {
    IdentitySecrets::from_all_seeds(
        [seed; 32],
        [seed.wrapping_add(1); 32],
        [seed.wrapping_add(2); 32],
        [seed.wrapping_add(3); 32],
    )
}

fn device_keys(seed: u8) -> DevicePublicKeys {
    let signing = account(seed).public_identity();
    let nostr = identity(seed).device_nostr_identity().unwrap();
    DevicePublicKeys {
        signing_public_key: signing.account_root_public_key,
        noise_public_key: [seed.wrapping_add(30); 32],
        nostr_public_key: *nostr.public_key(),
    }
}

fn binding(account: &AccountSecrets, handle: &str, revision: u64) -> SignedLocalAccountBinding {
    account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Registry Cache Test").unwrap()),
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
    HandleClaim::sign(
        CommandId::from_bytes([command; 32]),
        expected_revision,
        binding(account, handle, expected_revision + 1),
        account,
    )
    .unwrap()
}

fn apply(
    state: &mut RegistryState,
    account: &AccountSecrets,
    command: u8,
    handle: &str,
    expected_revision: u64,
    accepted_at: u64,
) -> AcceptedRegistryRecord {
    state
        .apply(
            claim(account, command, handle, expected_revision),
            accepted_at,
        )
        .unwrap();
    state
        .account_record(&account.public_identity().account_id)
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn verified_evidence_survives_restart_with_explicit_freshness() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut registry = RegistryState::from_signing_seed([44; 32]);
    let registry_key = registry.verifying_key();
    let alice = account(1);
    let record = apply(&mut registry, &alice, 1, "alice", 0, 100);
    let account_id = alice.public_identity().account_id;
    let handle = GlobalHandle::parse("alice").unwrap();
    let nostr_public_key = record.claim.binding().device_keys.nostr_public_key;

    let mut cache = VerifiedRegistryCache::load_or_create(&store, registry_key).unwrap();
    assert!(cache.is_empty());
    cache.observe(&store, record.clone(), 1_000).unwrap();
    assert_eq!(cache.len(), 1);

    assert!(matches!(
        cache.lookup_account(&account_id, 1_100, 100),
        RegistryCacheLookup::Fresh(ref cached) if cached.record == record
    ));
    assert!(matches!(
        cache.lookup_handle(&handle, 1_101, 100),
        RegistryCacheLookup::OfflineStale(ref cached) if cached.record == record
    ));
    assert!(matches!(
        cache.lookup_nostr_public_key(&nostr_public_key, 999, 100),
        RegistryCacheLookup::UnusableClockRollback(ref cached) if cached.record == record
    ));

    let reloaded = VerifiedRegistryCache::load_or_create(&store, registry_key).unwrap();
    assert_eq!(reloaded.len(), 1);
    assert!(matches!(
        reloaded.lookup_account(&account_id, 1_001, 100),
        RegistryCacheLookup::Fresh(ref cached) if cached.verified_at == 1_000
    ));
    let other_account = account(9).public_identity().account_id;
    assert_eq!(
        reloaded.lookup_account(&other_account, 1_001, 100),
        RegistryCacheLookup::Missing
    );

    let other_key = RegistryState::from_signing_seed([45; 32]).verifying_key();
    assert!(matches!(
        VerifiedRegistryCache::load_or_create(&store, other_key),
        Err(RegistryCacheError::PinnedRegistryKeyMismatch)
    ));
}

#[tokio::test]
async fn account_rollback_and_missing_chain_links_fail_closed() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut registry = RegistryState::from_signing_seed([55; 32]);
    let registry_key = registry.verifying_key();
    let alice = account(2);
    let first = apply(&mut registry, &alice, 1, "alice", 0, 100);
    let second = apply(&mut registry, &alice, 2, "alice", 1, 101);
    apply(&mut registry, &alice, 3, "alice", 2, 102);
    let fourth = apply(&mut registry, &alice, 4, "alice", 3, 103);

    let mut cache = VerifiedRegistryCache::load_or_create(&store, registry_key).unwrap();
    cache.observe(&store, first.clone(), 1_000).unwrap();
    cache.observe(&store, second, 1_001).unwrap();
    assert!(matches!(
        cache.observe(&store, first, 1_002),
        Err(RegistryCacheError::AccountRollback {
            cached: 2,
            proposed: 1
        })
    ));
    assert!(matches!(
        cache.observe(&store, fourth, 1_003),
        Err(RegistryCacheError::AccountChainGap {
            cached: 2,
            proposed: 4
        })
    ));
    assert_eq!(cache.len(), 2);
}

#[tokio::test]
async fn conflicting_signed_forks_and_forged_receipts_are_rejected() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let registry_seed = [66; 32];
    let mut registry = RegistryState::from_signing_seed(registry_seed);
    let registry_key = registry.verifying_key();
    let alice = account(3);
    let first = apply(&mut registry, &alice, 1, "alice", 0, 100);
    let fork_point = registry.snapshot();
    let mut left = RegistryState::restore(registry_seed, fork_point.clone()).unwrap();
    let mut right = RegistryState::restore(registry_seed, fork_point).unwrap();
    let left_record = apply(&mut left, &alice, 2, "alice", 1, 101);
    let right_record = apply(&mut right, &alice, 3, "alice", 1, 102);

    let mut cache = VerifiedRegistryCache::load_or_create(&store, registry_key).unwrap();
    cache.observe(&store, first, 1_000).unwrap();
    cache.observe(&store, left_record, 1_001).unwrap();
    assert!(matches!(
        cache.observe(&store, right_record, 1_002),
        Err(RegistryCacheError::AccountEquivocation)
    ));

    let mut forged = apply(
        &mut RegistryState::from_signing_seed(registry_seed),
        &account(8),
        9,
        "mallory",
        0,
        200,
    );
    forged.receipt.signature[0] ^= 0xFF;
    assert!(matches!(
        cache.observe(&store, forged, 1_003),
        Err(RegistryCacheError::Registry(
            RegistryError::InvalidReceiptSignature
        ))
    ));
    assert_eq!(cache.len(), 2);
}

#[tokio::test]
async fn one_handle_or_nostr_key_cannot_bind_two_cached_accounts() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let registry_seed = [77; 32];
    let registry_key = RegistryState::from_signing_seed(registry_seed).verifying_key();
    let alice = account(4);
    let bob = account(6);

    let alice_record = apply(
        &mut RegistryState::from_signing_seed(registry_seed),
        &alice,
        1,
        "shared",
        0,
        100,
    );
    let bob_record = apply(
        &mut RegistryState::from_signing_seed(registry_seed),
        &bob,
        2,
        "shared",
        0,
        101,
    );

    let mut cache = VerifiedRegistryCache::load_or_create(&store, registry_key).unwrap();
    cache.observe(&store, alice_record, 1_000).unwrap();
    assert!(matches!(
        cache.observe(&store, bob_record, 1_001),
        Err(RegistryCacheError::HandleEquivocation)
    ));
    assert_eq!(cache.len(), 1);
}
