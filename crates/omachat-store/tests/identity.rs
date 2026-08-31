use omachat_store::{
    IdentityStoreError, IdentityVault, RequestedProvider, SealedStore, StoreError,
};
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn identity_is_created_only_when_explicitly_absent() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .expect("create store");
    let first = IdentityVault::load_or_create(&store)
        .expect("create identity")
        .public_identity();
    drop(store);

    let reopened = SealedStore::open(&state, RequestedProvider::Auto)
        .await
        .expect("reopen store");
    let second = IdentityVault::load_or_create(&reopened)
        .expect("load identity")
        .public_identity();
    assert_eq!(first, second);

    let record = state.join("records/identity-v1");
    let mut ciphertext = fs::read(&record).expect("identity ciphertext");
    *ciphertext.last_mut().expect("authentication tag") ^= 1;
    fs::write(record, ciphertext).expect("tamper identity");
    assert!(matches!(
        IdentityVault::load_or_create(&reopened),
        Err(IdentityStoreError::Store(StoreError::Authentication))
    ));
}
