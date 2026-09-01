use std::fs;

use omachat_crypto::{DisplayName, GlobalHandle, IdentitySecrets};
use omachat_registry::{
    CommandId, HandleClaimSnapshot,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_store::{
    AccountVault, PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME, PrincipalRegistryClaimIntentError,
    PrincipalRegistryClaimIntentStore, RequestedProvider, SealedStore, StoreError,
};
use tempfile::tempdir;

async fn local_claim(
    directory: &std::path::Path,
    command_id: [u8; 32],
) -> (SealedStore, ProofBearingDeviceHandleClaim) {
    let store = SealedStore::open(directory, RequestedProvider::File)
        .await
        .expect("sealed store");
    let identity = IdentitySecrets::from_all_seeds([31; 32], [32; 32], [33; 32], [34; 32]);
    let account = AccountVault::load_or_create(
        &store,
        &identity,
        Some(GlobalHandle::parse("alice").expect("handle")),
        Some(DisplayName::parse("Alice").expect("display name")),
        1_788_000_000,
    )
    .expect("local account");
    let root_claim = account
        .sign_registry_handle_claim(CommandId::from_bytes(command_id), 0)
        .expect("root claim");
    let nostr = identity
        .device_nostr_identity()
        .expect("device Nostr identity");
    let payload = NostrPrincipalControlPayload::new(
        root_claim.claim_hash(),
        command_id,
        0,
        root_claim.binding().account_id.as_str(),
        root_claim
            .binding()
            .handle
            .as_ref()
            .expect("bound handle")
            .as_str(),
        NostrPrincipalType::Device,
        root_claim.binding().device_keys.nostr_public_key,
        device_authorisation_hash(root_claim.binding()),
        1_788_000_001,
    )
    .expect("principal payload");
    let proof =
        NostrPrincipalControlProof::sign(payload, *nostr.private_key()).expect("principal proof");
    let claim = ProofBearingDeviceHandleClaim::new(root_claim, proof).expect("proof-bearing claim");
    (store, claim)
}

#[tokio::test]
async fn exact_dual_signed_claim_survives_restart_and_replays_idempotently() {
    let directory = tempdir().expect("state directory");
    let (store, claim) = local_claim(directory.path(), [41; 32]).await;
    let intents = PrincipalRegistryClaimIntentStore::new(&store);
    assert_eq!(intents.prepare(&claim).expect("prepare"), claim);
    assert_eq!(intents.prepare(&claim).expect("idempotent prepare"), claim);
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    assert_eq!(
        PrincipalRegistryClaimIntentStore::new(&reopened)
            .load()
            .expect("load intent"),
        Some(claim)
    );
}

#[tokio::test]
async fn conflicting_proof_cannot_replace_or_clear_pending_intent() {
    let directory = tempdir().expect("state directory");
    let (store, first) = local_claim(directory.path(), [42; 32]).await;
    let (_, conflicting) = local_claim(directory.path(), [43; 32]).await;
    let intents = PrincipalRegistryClaimIntentStore::new(&store);
    intents.prepare(&first).expect("prepare first");
    assert!(matches!(
        intents.prepare(&conflicting),
        Err(PrincipalRegistryClaimIntentError::PendingConflict)
    ));
    assert!(matches!(
        intents.clear(&conflicting),
        Err(PrincipalRegistryClaimIntentError::PendingConflict)
    ));
    assert_eq!(intents.load().expect("load first"), Some(first));
}

#[tokio::test]
async fn exact_completion_clears_only_the_matching_intent() {
    let directory = tempdir().expect("state directory");
    let (store, claim) = local_claim(directory.path(), [44; 32]).await;
    let intents = PrincipalRegistryClaimIntentStore::new(&store);
    intents.prepare(&claim).expect("prepare");
    intents.clear(&claim).expect("clear exact claim");
    assert_eq!(intents.load().expect("load cleared intent"), None);
    assert!(matches!(
        intents.clear(&claim),
        Err(PrincipalRegistryClaimIntentError::PendingMissing)
    ));
}

#[tokio::test]
async fn ciphertext_plaintext_and_proof_corruption_fail_closed() {
    let directory = tempdir().expect("state directory");
    let (store, claim) = local_claim(directory.path(), [45; 32]).await;
    let intents = PrincipalRegistryClaimIntentStore::new(&store);
    intents.prepare(&claim).expect("prepare");

    let record_path = directory
        .path()
        .join("records")
        .join(PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME);
    let mut ciphertext = fs::read(&record_path).expect("read ciphertext");
    *ciphertext.last_mut().expect("ciphertext byte") ^= 1;
    fs::write(&record_path, ciphertext).expect("tamper ciphertext");
    assert!(matches!(
        intents.load(),
        Err(PrincipalRegistryClaimIntentError::Store(
            StoreError::Authentication
        ))
    ));

    store
        .write(PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME, b"not-json")
        .expect("seal malformed plaintext");
    assert!(matches!(
        intents.load(),
        Err(PrincipalRegistryClaimIntentError::Encoding)
    ));

    let mut damaged_proof = claim.principal_proof().to_bytes();
    *damaged_proof.last_mut().expect("proof byte") ^= 1;
    let damaged = serde_json::json!({
        "version": 1,
        "root_claim": HandleClaimSnapshot::from_claim(claim.claim()),
        "principal_proof_hex": hex::encode(damaged_proof),
    });
    store
        .write(
            PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME,
            &serde_json::to_vec(&damaged).expect("encode damaged record"),
        )
        .expect("seal damaged proof");
    assert!(matches!(
        intents.load(),
        Err(PrincipalRegistryClaimIntentError::InvalidPrincipalClaim)
    ));
}
