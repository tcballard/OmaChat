use omachat_nostr::{event::EventLimits, nip29_room_state::RelayRoomState};
use omachat_store::{
    FileGenerationAnchor, RequestedProvider, RoomStateGenerationAnchor, RoomStateLoad,
    RoomStateVault, RoomStateVaultError, SealedStore,
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
use tempfile::TempDir;

const RELAY: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const OTHER_RELAY: &str = "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b";
const CONTEXT: &str = "device:0123456789abcdef/omachat";
const NOW: u64 = 1_800_000_000;

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("mkdir");
    for entry in fs::read_dir(source).expect("read dir") {
        let entry = entry.expect("entry");
        let destination = target.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy");
        }
    }
}

#[tokio::test]
async fn generations_are_monotonic_and_isolated_per_relay_and_context() {
    let root = TempDir::new().expect("tempdir");
    let state = root.path().join("state");
    fs::create_dir_all(&state).expect("state");
    let anchor = FileGenerationAnchor::open(root.path().join("anchors"), &state).expect("anchor");

    assert_eq!(
        anchor.load_generation(CONTEXT, RELAY).await.expect("load"),
        None
    );
    anchor
        .store_generation(CONTEXT, RELAY, 0)
        .await
        .expect("zero");
    anchor
        .store_generation(CONTEXT, RELAY, 3)
        .await
        .expect("three");
    anchor
        .store_generation(CONTEXT, RELAY, 3)
        .await
        .expect("idempotent");
    assert!(anchor.store_generation(CONTEXT, RELAY, 2).await.is_err());
    assert_eq!(
        anchor.load_generation(CONTEXT, RELAY).await.expect("load"),
        Some(3)
    );

    assert_eq!(
        anchor
            .load_generation(CONTEXT, OTHER_RELAY)
            .await
            .expect("load"),
        None
    );
    assert_eq!(
        anchor
            .load_generation("other-context", RELAY)
            .await
            .expect("load"),
        None
    );
    anchor
        .store_generation("other-context", RELAY, 1)
        .await
        .expect("other");
    assert_eq!(
        anchor.load_generation(CONTEXT, RELAY).await.expect("load"),
        Some(3)
    );

    // Files are private and interrupted temporaries never count.
    let mode = fs::metadata(anchor.directory())
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
    let relay_dir = anchor.directory().join(RELAY);
    for entry in fs::read_dir(&relay_dir).expect("dir") {
        let entry = entry.expect("entry");
        let mode = entry.metadata().expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{:?}", entry.path());
    }
    assert!(anchor.store_generation(CONTEXT, "relay", 1).await.is_err());
    assert!(anchor.store_generation("", RELAY, 1).await.is_err());
    assert!(
        anchor
            .store_generation(&"x".repeat(129), RELAY, 1)
            .await
            .is_err()
    );

    // A file rebound to another relay or context is refused, not trusted.
    let path = fs::read_dir(&relay_dir)
        .expect("dir")
        .map(|entry| entry.expect("entry").path())
        .find(|path| path.to_string_lossy().contains("device"))
        .expect("anchor file");
    let swapped = fs::read_to_string(&path)
        .expect("read")
        .replace(RELAY, OTHER_RELAY);
    fs::write(&path, swapped).expect("write");
    assert!(anchor.load_generation(CONTEXT, RELAY).await.is_err());
}

#[tokio::test]
async fn anchor_refuses_to_share_the_sealed_rollback_domain() {
    let root = TempDir::new().expect("tempdir");
    let state = root.path().join("state");
    fs::create_dir_all(&state).expect("state");
    assert!(FileGenerationAnchor::open(&state, &state).is_err());
    assert!(FileGenerationAnchor::open(state.join("anchors"), &state).is_err());
    assert!(FileGenerationAnchor::open(root.path(), &state).is_err());
    assert!(FileGenerationAnchor::open(root.path().join("anchors"), &state).is_ok());
}

#[tokio::test]
async fn restoring_the_sealed_store_from_backup_is_detected() {
    let root = TempDir::new().expect("tempdir");
    let state = root.path().join("state");
    let backup = root.path().join("backup");
    let limits = EventLimits::default();
    let anchor_directory = root.path().join("anchors");

    {
        let store = SealedStore::open(&state, RequestedProvider::File)
            .await
            .expect("store");
        let anchor = FileGenerationAnchor::open(&anchor_directory, &state).expect("anchor");
        let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, RELAY).expect("vault");
        let (room_state, load) = vault.load_or_create(NOW, &limits).await.expect("fresh");
        assert_eq!(load, RoomStateLoad::Fresh);
        assert_eq!(vault.persist(&room_state).await.expect("persist"), 1);
        copy_tree(&state, &backup);
        assert_eq!(vault.persist(&room_state).await.expect("persist"), 2);
    }

    // Same anchor, current state: loads at generation 2.
    {
        let store = SealedStore::open(&state, RequestedProvider::File)
            .await
            .expect("store");
        let anchor = FileGenerationAnchor::open(&anchor_directory, &state).expect("anchor");
        let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, RELAY).expect("vault");
        let (_, load) = vault.load_or_create(NOW, &limits).await.expect("load");
        assert_eq!(load, RoomStateLoad::Restored { generation: 2 });
    }

    // Operator restores the state directory from the older backup.
    fs::remove_dir_all(&state).expect("remove");
    copy_tree(&backup, &state);
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .expect("store");
    let anchor = FileGenerationAnchor::open(&anchor_directory, &state).expect("anchor");
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, RELAY).expect("vault");
    assert!(matches!(
        vault.load_or_create(NOW, &limits).await,
        Err(RoomStateVaultError::Rollback {
            record_generation: 1,
            anchor_generation: 2
        })
    ));

    // A wiped state directory with a surviving anchor is not "fresh" either.
    fs::remove_dir_all(&state).expect("remove");
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .expect("store");
    let anchor = FileGenerationAnchor::open(&anchor_directory, &state).expect("anchor");
    let mut vault = RoomStateVault::open(&store, &anchor, CONTEXT, RELAY).expect("vault");
    assert!(matches!(
        vault.load_or_create(NOW, &limits).await,
        Err(RoomStateVaultError::Rollback {
            record_generation: 0,
            anchor_generation: 2
        })
    ));

    // A different relay in the same anchor directory is unaffected.
    let mut other = RoomStateVault::open(&store, &anchor, CONTEXT, OTHER_RELAY).expect("vault");
    let (fresh, load) = other.load_or_create(NOW, &limits).await.expect("fresh");
    assert_eq!(load, RoomStateLoad::Fresh);
    assert_eq!(
        fresh,
        RelayRoomState::new(OTHER_RELAY.to_owned()).expect("empty")
    );
}
