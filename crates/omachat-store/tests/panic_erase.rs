use omachat_store::{RequestedProvider, SealedStore, StoreError};
use std::sync::{Arc, mpsc};

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

#[tokio::test]
async fn cleanup_failure_leaves_the_store_terminally_erased() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("state");
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .unwrap();
    store.write("secret", b"sensitive").unwrap();
    std::fs::remove_file(state.join("master.key")).unwrap();

    assert!(matches!(
        store.panic_erase().await,
        Err(StoreError::MissingMasterKey)
    ));
    assert!(matches!(store.read("secret"), Err(StoreError::Erased)));
    assert!(matches!(
        store.write("new-secret", b"must not be written"),
        Err(StoreError::Erased)
    ));
    assert!(matches!(store.delete("secret"), Err(StoreError::Erased)));
    assert!(!state.exists());
    assert!(!state.join("records/new-secret").exists());
    assert!(matches!(store.panic_erase().await, Err(StoreError::Erased)));
}

#[tokio::test]
async fn operations_racing_erase_stop_at_the_terminal_key_state() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("state");
    let store = Arc::new(
        SealedStore::open(&state, RequestedProvider::File)
            .await
            .unwrap(),
    );
    store.write("racing", b"before erase").unwrap();

    let worker_store = Arc::clone(&store);
    let (ready_tx, ready_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        // Prove the worker is live before the erase races its next lock.
        worker_store.write("racing", b"worker active").unwrap();
        ready_tx.send(()).unwrap();

        loop {
            match worker_store.read("racing") {
                Ok(_) | Err(StoreError::RecordNotFound) => {}
                Err(StoreError::Erased) => break,
                Err(error) => panic!("read failed before terminal erase: {error}"),
            }
            match worker_store.write("racing", b"concurrent write") {
                Ok(()) => {}
                Err(StoreError::Erased) => break,
                Err(error) => panic!("write failed before terminal erase: {error}"),
            }
            match worker_store.delete("racing") {
                Ok(()) => {}
                Err(StoreError::Erased) => break,
                Err(error) => panic!("delete failed before terminal erase: {error}"),
            }
            std::thread::yield_now();
        }

        assert!(matches!(
            worker_store.write("after", b"must not persist"),
            Err(StoreError::Erased)
        ));
        assert!(matches!(
            worker_store.read("racing"),
            Err(StoreError::Erased)
        ));
        assert!(matches!(
            worker_store.delete("racing"),
            Err(StoreError::Erased)
        ));
    });

    ready_rx.recv().unwrap();
    store.panic_erase().await.unwrap();
    worker.join().unwrap();
    assert!(!state.exists());
}
