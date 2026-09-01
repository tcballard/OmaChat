use omachat_store::{
    NostrDeliveryProfile, NostrOutbox, OutboxError, OutboxState, RequestedProvider, SealedStore,
};
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn restart_preserves_order_attempts_and_sealed_plaintext() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let store = SealedStore::open(&state, RequestedProvider::File)
        .await
        .expect("store");
    let mut outbox = NostrOutbox::load(&store, 100).expect("outbox");
    outbox
        .enqueue("one", "peer-a", "first private plaintext", 100)
        .expect("first");
    outbox
        .enqueue("two", "peer-a", "second private plaintext", 101)
        .expect("second");
    assert_eq!(
        outbox.record_attempt("one", false, 102).expect("attempt"),
        OutboxState::Pending
    );
    drop(outbox);
    drop(store);

    let backing = fs::read(state.join("records/nostr-outbox-v1")).expect("sealed outbox");
    assert!(
        !backing
            .windows(17)
            .any(|bytes| bytes == b"private plaintext")
    );

    let reopened_store = SealedStore::open(&state, RequestedProvider::Auto)
        .await
        .expect("reopen store");
    let mut reopened = NostrOutbox::load(&reopened_store, 103).expect("reopen outbox");
    assert_eq!(reopened.messages()[0].id, "one");
    assert_eq!(
        reopened.messages()[0].nostr_profile,
        NostrDeliveryProfile::Compatibility
    );
    assert_eq!(reopened.messages()[0].attempts, 1);
    assert_eq!(reopened.messages()[1].id, "two");

    reopened
        .record_attempt("one", true, 104)
        .expect("acknowledge");
    assert_eq!(reopened.next_pending().expect("second pending").id, "two");
}

#[tokio::test]
async fn restart_preserves_nip17_profile_and_old_records_default_to_compatibility() {
    let temporary = tempdir().expect("temporary directory");
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .expect("store");
    let mut outbox = NostrOutbox::load(&store, 100).expect("outbox");
    outbox
        .enqueue_with_profile(
            "nip17",
            "peer",
            "signed gift wrap",
            NostrDeliveryProfile::Nip17,
            100,
        )
        .expect("NIP-17 enqueue");
    drop(outbox);
    let reopened = NostrOutbox::load(&store, 101).expect("reopen NIP-17 outbox");
    assert_eq!(
        reopened.messages()[0].nostr_profile,
        NostrDeliveryProfile::Nip17
    );
    drop(reopened);

    store
        .write(
            "nostr-outbox-v1",
            br#"{"messages":[{"id":"old","peer":"peer","gift_wrap":"legacy","created_at":102,"attempts":0,"last_attempt_at":null,"state":"pending"}]}"#,
        )
        .expect("write pre-profile record");
    let migrated = NostrOutbox::load(&store, 103).expect("load pre-profile record");
    assert_eq!(
        migrated.messages()[0].nostr_profile,
        NostrDeliveryProfile::Compatibility
    );
}

#[tokio::test]
async fn bounds_expiry_and_terminal_failure_are_visible() {
    let temporary = tempdir().expect("temporary directory");
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .expect("store");
    let mut outbox = NostrOutbox::load(&store, 0).expect("outbox");
    for index in 0..100 {
        outbox
            .enqueue(format!("id-{index}"), "peer", "ciphertext", index)
            .expect("bounded enqueue");
    }
    assert!(matches!(
        outbox.enqueue("overflow", "peer", "ciphertext", 100),
        Err(OutboxError::QueueFull)
    ));

    for attempt in 1..=8 {
        let state = outbox
            .record_attempt("id-0", false, 100 + attempt)
            .expect("record failure");
        assert_eq!(
            state,
            if attempt == 8 {
                OutboxState::Failed
            } else {
                OutboxState::Pending
            }
        );
    }
    assert_eq!(outbox.messages()[0].attempts, 8);

    drop(outbox);
    let expired = NostrOutbox::load(&store, 24 * 60 * 60 + 100).expect("expire old queue");
    assert!(expired.messages().is_empty());
}
