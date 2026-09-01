use std::fs;

use omachat_crypto::{DisplayName, GlobalHandle, IdentitySecrets};
use omachat_registry::CommandId;
use omachat_store::{
    AccountVault, REGISTRY_CLAIM_INTENT_RECORD_NAME, RegistryClaimIntentError,
    RegistryClaimIntentStore, RequestedProvider, SealedStore, StoreError,
};
use tempfile::tempdir;

async fn local_account(directory: &std::path::Path) -> (SealedStore, omachat_store::LocalAccount) {
    let store = SealedStore::open(directory, RequestedProvider::File)
        .await
        .expect("sealed store");
    let identity = IdentitySecrets::from_seeds([31; 32], [32; 32], [33; 32]);
    let account = AccountVault::load_or_create(
        &store,
        &identity,
        Some(GlobalHandle::parse("alice").expect("handle")),
        Some(DisplayName::parse("Alice").expect("display name")),
        1_788_000_000,
    )
    .expect("local account");
    (store, account)
}

#[tokio::test]
async fn exact_signed_claim_survives_restart_and_replays_idempotently() {
    let directory = tempdir().expect("state directory");
    let (store, account) = local_account(directory.path()).await;
    let claim = account
        .sign_registry_handle_claim(CommandId::from_bytes([41; 32]), 0)
        .expect("signed claim");
    let intents = RegistryClaimIntentStore::new(&store);
    assert_eq!(intents.prepare(&claim).expect("prepare"), claim);
    assert_eq!(intents.prepare(&claim).expect("idempotent prepare"), claim);
    drop(account);
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    assert_eq!(
        RegistryClaimIntentStore::new(&reopened)
            .load()
            .expect("load intent"),
        Some(claim)
    );
}

#[tokio::test]
async fn conflicting_command_cannot_replace_or_clear_pending_intent() {
    let directory = tempdir().expect("state directory");
    let (store, account) = local_account(directory.path()).await;
    let first = account
        .sign_registry_handle_claim(CommandId::from_bytes([42; 32]), 0)
        .expect("first claim");
    let conflicting = account
        .sign_registry_handle_claim(CommandId::from_bytes([43; 32]), 0)
        .expect("conflicting claim");
    let intents = RegistryClaimIntentStore::new(&store);
    intents.prepare(&first).expect("prepare first");
    assert!(matches!(
        intents.prepare(&conflicting),
        Err(RegistryClaimIntentError::PendingConflict)
    ));
    assert!(matches!(
        intents.clear(&conflicting),
        Err(RegistryClaimIntentError::PendingConflict)
    ));
    assert_eq!(intents.load().expect("load first"), Some(first));
}

#[tokio::test]
async fn exact_completion_clears_the_intent_only_after_success() {
    let directory = tempdir().expect("state directory");
    let (store, account) = local_account(directory.path()).await;
    let claim = account
        .sign_registry_handle_claim(CommandId::from_bytes([44; 32]), 0)
        .expect("claim");
    let intents = RegistryClaimIntentStore::new(&store);
    intents.prepare(&claim).expect("prepare");
    intents.clear(&claim).expect("clear exact claim");
    assert_eq!(intents.load().expect("load cleared intent"), None);
    assert!(matches!(
        intents.clear(&claim),
        Err(RegistryClaimIntentError::PendingMissing)
    ));
}

#[tokio::test]
async fn ciphertext_and_sealed_plaintext_corruption_fail_closed() {
    let directory = tempdir().expect("state directory");
    let (store, account) = local_account(directory.path()).await;
    let claim = account
        .sign_registry_handle_claim(CommandId::from_bytes([45; 32]), 0)
        .expect("claim");
    let intents = RegistryClaimIntentStore::new(&store);
    intents.prepare(&claim).expect("prepare");

    let record_path = directory
        .path()
        .join("records")
        .join(REGISTRY_CLAIM_INTENT_RECORD_NAME);
    let mut ciphertext = fs::read(&record_path).expect("read ciphertext");
    *ciphertext.last_mut().expect("ciphertext byte") ^= 1;
    fs::write(&record_path, ciphertext).expect("tamper ciphertext");
    assert!(matches!(
        intents.load(),
        Err(RegistryClaimIntentError::Store(StoreError::Authentication))
    ));

    store
        .write(REGISTRY_CLAIM_INTENT_RECORD_NAME, b"not-json")
        .expect("seal malformed plaintext");
    assert!(matches!(
        intents.load(),
        Err(RegistryClaimIntentError::Encoding)
    ));
}
