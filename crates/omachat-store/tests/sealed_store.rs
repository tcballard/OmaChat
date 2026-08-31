use omachat_store::{ProviderKind, RequestedProvider, SealedStore, StoreError};
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::tempdir;

#[tokio::test]
async fn file_provider_is_sticky_private_and_never_regenerates_silently() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");

    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .expect("create file-backed store");
    assert_eq!(store.status().provider, ProviderKind::File);
    let key = state.join("master.key");
    assert_eq!(
        fs::metadata(&key)
            .expect("master-key metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(store);

    assert!(matches!(
        SealedStore::open(&state, RequestedProvider::SecretService).await,
        Err(StoreError::ProviderConflict)
    ));

    fs::remove_file(&key).expect("simulate lost selected key");
    assert!(matches!(
        SealedStore::open(&state, RequestedProvider::Auto).await,
        Err(StoreError::MissingMasterKey)
    ));
    assert!(
        !key.exists(),
        "a selected missing key must not be regenerated"
    );
}

#[tokio::test]
async fn records_authenticate_version_name_and_ciphertext() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .expect("create store");
    let plaintext = b"private identity material";

    store.write("identity", plaintext).expect("seal identity");
    assert_eq!(store.read("identity").expect("open identity"), plaintext);

    let identity_path = state.join("records/identity");
    let raw = fs::read(&identity_path).expect("read envelope");
    assert!(
        !raw.windows(plaintext.len())
            .any(|window| window == plaintext),
        "plaintext must not appear in the sealed envelope"
    );

    fs::copy(&identity_path, state.join("records/outbox")).expect("swap ciphertext");
    assert!(matches!(
        store.read("outbox"),
        Err(StoreError::Authentication)
    ));

    let mut tampered = raw;
    *tampered.last_mut().expect("authentication tag") ^= 0x80;
    fs::write(&identity_path, tampered).expect("tamper with envelope");
    assert!(matches!(
        store.read("identity"),
        Err(StoreError::Authentication)
    ));
}

#[tokio::test]
async fn interrupted_temporary_files_never_replace_a_committed_record() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .expect("create store");
    store
        .write("outbox", b"committed queue")
        .expect("commit queue");
    drop(store);

    let orphan = state.join("records/.outbox.tmp-999-1");
    fs::write(&orphan, b"partial replacement").expect("simulate interrupted write");

    let reopened = SealedStore::open(&state, RequestedProvider::Auto)
        .await
        .expect("recover store");
    assert_eq!(
        reopened.read("outbox").expect("read committed queue"),
        b"committed queue"
    );
    assert!(!orphan.exists(), "orphan temporary file must be removed");
}

#[tokio::test]
async fn insecure_key_permissions_fail_closed() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    drop(
        SealedStore::open(&state, RequestedProvider::File)
            .await
            .expect("create store"),
    );
    let key = state.join("master.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).expect("weaken permissions");

    assert!(matches!(
        SealedStore::open(&state, RequestedProvider::Auto).await,
        Err(StoreError::InsecurePermissions)
    ));
}
