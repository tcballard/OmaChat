use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    principal_registry::PrincipalRegistryState,
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_store::{
    PrincipalRegistryCacheError, PrincipalRegistryCacheLookup, PrincipalRegistryEvidence,
    RequestedProvider, SealedStore, VerifiedPrincipalRegistryCache,
};
use tempfile::tempdir;

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
    device_seed: u8,
    nostr_secret: [u8; 32],
    command: u8,
    handle: &str,
    expected_revision: u64,
    binding_revision: u64,
) -> ProofBearingDeviceHandleClaim {
    let public_key = nostr_public_key(&nostr_secret);
    let device_signer =
        AccountSecrets::from_seeds([device_seed; 32], [device_seed.wrapping_add(1); 32]);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Principal Cache Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: device_signer.public_identity().account_root_public_key,
            noise_public_key: [device_seed.wrapping_add(2); 32],
            nostr_public_key: public_key,
        },
        binding_revision,
        1_788_000_000 + binding_revision,
    );
    let command_id = [command; 32];
    let root_claim = HandleClaim::sign(
        CommandId::from_bytes(command_id),
        expected_revision,
        binding,
        account,
    )
    .unwrap();
    let payload = NostrPrincipalControlPayload::new(
        root_claim.claim_hash(),
        command_id,
        expected_revision,
        root_claim.binding().account_id.as_str(),
        handle,
        NostrPrincipalType::Device,
        public_key,
        device_authorisation_hash(root_claim.binding()),
        1_788_000_100 + binding_revision,
    )
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).unwrap();
    ProofBearingDeviceHandleClaim::new(root_claim, proof).unwrap()
}

fn apply(
    state: &mut PrincipalRegistryState,
    claim: ProofBearingDeviceHandleClaim,
    accepted_at: u64,
) -> PrincipalRegistryEvidence {
    PrincipalRegistryEvidence::from_record(&state.apply_device(claim, accepted_at).unwrap())
}

#[tokio::test]
async fn verified_principal_evidence_survives_restart_with_explicit_freshness() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut registry = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let registry_key = registry.verifying_key();
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let evidence = apply(
        &mut registry,
        validated_claim(&account, 0x21, [0x31; 32], 0x41, "alice", 0, 1),
        1_788_000_200,
    );
    let account_id = account.public_identity().account_id;
    let handle = GlobalHandle::parse("alice").unwrap();
    let public_key = evidence
        .claim
        .principal_proof()
        .payload()
        .nostr_public_key();

    let mut cache = VerifiedPrincipalRegistryCache::load_or_create(&store, registry_key).unwrap();
    cache.observe(&store, evidence.clone(), 1_000).unwrap();
    assert!(matches!(
        cache.lookup_account(&account_id, 1_100, 100),
        PrincipalRegistryCacheLookup::Fresh(ref cached) if cached.evidence == evidence
    ));
    assert!(matches!(
        cache.lookup_handle(&handle, 1_101, 100),
        PrincipalRegistryCacheLookup::OfflineStale(ref cached) if cached.evidence == evidence
    ));
    assert!(matches!(
        cache.lookup_public_key(&public_key, 999, 100),
        PrincipalRegistryCacheLookup::UnusableClockRollback(ref cached)
            if cached.evidence == evidence
    ));

    let reloaded = VerifiedPrincipalRegistryCache::load_or_create(&store, registry_key).unwrap();
    assert_eq!(reloaded.len(), 1);
    assert!(matches!(
        reloaded.lookup_public_key(&public_key, 1_001, 100),
        PrincipalRegistryCacheLookup::Fresh(ref cached) if cached.verified_at == 1_000
    ));
    let other_key = PrincipalRegistryState::from_signing_seed([0x72; 32]).verifying_key();
    assert!(matches!(
        VerifiedPrincipalRegistryCache::load_or_create(&store, other_key),
        Err(PrincipalRegistryCacheError::PinnedRegistryKeyMismatch)
    ));
}

#[tokio::test]
async fn account_rotation_advances_both_chains_without_tombstoning_the_old_key() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut registry = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let registry_key = registry.verifying_key();
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let first = apply(
        &mut registry,
        validated_claim(&account, 0x21, [0x31; 32], 0x41, "alice", 0, 1),
        1_788_000_200,
    );
    let second = apply(
        &mut registry,
        validated_claim(&account, 0x22, [0x32; 32], 0x42, "alice", 1, 2),
        1_788_000_201,
    );
    let old_key = first.claim.principal_proof().payload().nostr_public_key();
    let new_key = second.claim.principal_proof().payload().nostr_public_key();
    let mut cache = VerifiedPrincipalRegistryCache::load_or_create(&store, registry_key).unwrap();
    cache.observe(&store, first.clone(), 1_000).unwrap();
    cache.observe(&store, second.clone(), 1_001).unwrap();
    assert_eq!(
        cache.lookup_public_key(&old_key, 1_001, 100),
        PrincipalRegistryCacheLookup::Missing
    );
    assert!(matches!(
        cache.lookup_public_key(&new_key, 1_001, 100),
        PrincipalRegistryCacheLookup::Fresh(ref cached) if cached.evidence == second
    ));
    assert!(matches!(
        cache.observe(&store, first, 1_002),
        Err(PrincipalRegistryCacheError::AccountRollback {
            cached: 2,
            proposed: 1
        })
    ));
}

#[tokio::test]
async fn signed_forks_and_forged_principal_receipts_fail_closed() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let seed = [0x71; 32];
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let first_claim = validated_claim(&account, 0x21, [0x31; 32], 0x41, "alice", 0, 1);
    let mut left = PrincipalRegistryState::from_signing_seed(seed);
    let mut right = PrincipalRegistryState::from_signing_seed(seed);
    let first = apply(&mut left, first_claim.clone(), 1_788_000_200);
    apply(&mut right, first_claim, 1_788_000_200);
    let left_second = apply(
        &mut left,
        validated_claim(&account, 0x22, [0x32; 32], 0x42, "alice", 1, 2),
        1_788_000_201,
    );
    let right_second = apply(
        &mut right,
        validated_claim(&account, 0x23, [0x33; 32], 0x43, "alice", 1, 2),
        1_788_000_202,
    );
    let mut cache =
        VerifiedPrincipalRegistryCache::load_or_create(&store, left.verifying_key()).unwrap();
    cache.observe(&store, first, 1_000).unwrap();
    cache.observe(&store, left_second, 1_001).unwrap();
    assert!(matches!(
        cache.observe(&store, right_second, 1_002),
        Err(PrincipalRegistryCacheError::AccountEquivocation)
    ));

    let mut forged = PrincipalRegistryEvidence::from_record(
        &right
            .public_key_record(&nostr_public_key(&[0x33; 32]))
            .unwrap()
            .clone(),
    );
    forged.principal_receipt.signature[0] ^= 0xFF;
    assert!(matches!(
        cache.observe(&store, forged, 1_003),
        Err(PrincipalRegistryCacheError::InvalidPrincipalReceipt)
    ));
}

#[tokio::test]
async fn one_live_nostr_key_cannot_bind_two_cached_accounts() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let seed = [0x71; 32];
    let alice = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let mallory = AccountSecrets::from_seeds([0x13; 32], [0x14; 32]);
    let shared_secret = [0x31; 32];
    let alice_evidence = apply(
        &mut PrincipalRegistryState::from_signing_seed(seed),
        validated_claim(&alice, 0x21, shared_secret, 0x41, "alice", 0, 1),
        1_788_000_200,
    );
    let mallory_evidence = apply(
        &mut PrincipalRegistryState::from_signing_seed(seed),
        validated_claim(&mallory, 0x22, shared_secret, 0x42, "mallory", 0, 1),
        1_788_000_201,
    );
    let mut cache = VerifiedPrincipalRegistryCache::load_or_create(
        &store,
        PrincipalRegistryState::from_signing_seed(seed).verifying_key(),
    )
    .unwrap();
    cache.observe(&store, alice_evidence, 1_000).unwrap();
    assert!(matches!(
        cache.observe(&store, mallory_evidence, 1_001),
        Err(PrincipalRegistryCacheError::PrincipalEquivocation)
    ));
    assert_eq!(cache.len(), 1);
}
