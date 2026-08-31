use omachat_store::{RequestedProvider, SealedStore, StoreError};

#[tokio::test]
async fn panic_removes_key_before_ciphertext_and_old_capture_cannot_open() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("state");
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .unwrap();
    store.write("secret", b"sensitive").unwrap();
    let captured = std::fs::read(state.join("records/secret")).unwrap();
    store.panic_erase().await.unwrap();
    assert!(!state.exists());
    let replacement = SealedStore::open(&state, RequestedProvider::File)
        .await
        .unwrap();
    std::fs::write(state.join("records/secret"), captured).unwrap();
    assert!(matches!(
        replacement.read("secret"),
        Err(StoreError::Authentication)
    ));
}
