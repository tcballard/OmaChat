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

#[tokio::test]
async fn pre_retirement_identity_keeps_the_hosted_signing_key() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let seed = [23u8; 32];
    let old = serde_json::json!({"signing_seed":seed,"noise_static_secret":vec![0;32],"nostr_identity_secret":vec![1;32],"nostr_device_seed":vec![2;32]});
    store
        .write("identity-v1", &serde_json::to_vec(&old).unwrap())
        .unwrap();
    let loaded = IdentityVault::load_or_create(&store).unwrap();
    let expected = omachat_crypto::IdentitySecrets::from_signing_seed(seed);
    assert_eq!(loaded.public_identity(), expected.public_identity());
    assert_eq!(
        loaded.sign(b"hosted challenge"),
        expected.sign(b"hosted challenge")
    );
    assert_eq!(
        serde_json::to_value(&loaded)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        1
    );
}
