use std::{collections::BTreeSet, fs};

use omachat_nostr::{
    event::{EventLimits, xonly_public_key},
    profile_metadata::{NostrProfileDraft, create_profile_metadata_with_aux},
};
use omachat_store::{RequestedProvider, SealedStore, StoreError};
use omachatd::{
    PROFILE_PUBLICATION_INTENT_RECORD_NAME, ProfilePublicationIntentError,
    ProfilePublicationIntentStore, ProfilePublicationProgress,
};
use tempfile::tempdir;

const NOW: u64 = 1_800_000_000;

fn profile(secret: &[u8; 32], created_at: u64, name: &str) -> omachat_nostr::event::SignedEvent {
    create_profile_metadata_with_aux(
        secret,
        created_at,
        &NostrProfileDraft {
            nostr_name: Some(name.into()),
            display_name: Some("Tom Ballard".into()),
            about: Some("Building OmaChat".into()),
            picture: None,
        },
        &[17; 32],
        &EventLimits::default(),
    )
    .expect("profile event")
}

fn relays() -> Vec<String> {
    vec![
        "wss://relay-b.example".into(),
        "wss://relay-a.example/".into(),
    ]
}

#[tokio::test]
async fn exact_profile_and_partial_acknowledgements_survive_restart() {
    let directory = tempdir().expect("state directory");
    let secret = [61; 32];
    let public_key = xonly_public_key(&secret).expect("public key");
    let event = profile(&secret, NOW, "tom.local");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
    let intents = ProfilePublicationIntentStore::new(&store);
    let pending = intents
        .prepare(
            &event,
            &relays(),
            2,
            &public_key,
            NOW,
            &EventLimits::default(),
        )
        .expect("prepare");
    assert_eq!(
        pending.relay_urls(),
        ["wss://relay-a.example/", "wss://relay-b.example/"]
    );
    assert_eq!(
        intents
            .prepare(
                &event,
                &relays(),
                2,
                &public_key,
                NOW,
                &EventLimits::default(),
            )
            .expect("idempotent prepare"),
        pending
    );
    let ProfilePublicationProgress::Pending(partial) = intents
        .acknowledge(&event.id, &[1], &public_key, NOW, &EventLimits::default())
        .expect("partial acknowledgement")
    else {
        panic!("publication completed too early");
    };
    assert_eq!(partial.acknowledged_relay_indices(), &BTreeSet::from([1]));
    drop(store);

    let reopened = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("reopen store");
    let intents = ProfilePublicationIntentStore::new(&reopened);
    let loaded = intents
        .load(&public_key, NOW, &EventLimits::default())
        .expect("load intent")
        .expect("pending intent");
    assert_eq!(loaded, partial);
    assert_eq!(loaded.remaining_relay_indices(), BTreeSet::from([0]));
    assert_eq!(
        intents
            .acknowledge(&event.id, &[0], &public_key, NOW, &EventLimits::default(),)
            .expect("final acknowledgement"),
        ProfilePublicationProgress::Complete
    );
    assert!(
        intents
            .load(&public_key, NOW, &EventLimits::default())
            .expect("load completed")
            .is_none()
    );
}

#[tokio::test]
async fn conflicting_event_policy_or_author_cannot_replace_pending_state() {
    let directory = tempdir().expect("state directory");
    let secret = [62; 32];
    let public_key = xonly_public_key(&secret).expect("public key");
    let event = profile(&secret, NOW, "tom.local");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
    let intents = ProfilePublicationIntentStore::new(&store);
    intents
        .prepare(
            &event,
            &relays(),
            1,
            &public_key,
            NOW,
            &EventLimits::default(),
        )
        .expect("prepare");

    let replacement = profile(&secret, NOW + 1, "tom.next");
    assert!(matches!(
        intents.prepare(
            &replacement,
            &relays(),
            1,
            &public_key,
            NOW + 1,
            &EventLimits::default(),
        ),
        Err(ProfilePublicationIntentError::PendingConflict)
    ));
    assert!(matches!(
        intents.prepare(
            &event,
            &relays(),
            2,
            &public_key,
            NOW,
            &EventLimits::default(),
        ),
        Err(ProfilePublicationIntentError::PendingConflict)
    ));
    assert!(matches!(
        intents.load(
            &xonly_public_key(&[63; 32]).expect("other public key"),
            NOW,
            &EventLimits::default(),
        ),
        Err(ProfilePublicationIntentError::Verification(_))
    ));
}

#[tokio::test]
async fn unsafe_relays_thresholds_and_progress_fail_closed() {
    let directory = tempdir().expect("state directory");
    let secret = [64; 32];
    let public_key = xonly_public_key(&secret).expect("public key");
    let event = profile(&secret, NOW, "tom.local");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
    let intents = ProfilePublicationIntentStore::new(&store);
    for relay_set in [
        Vec::new(),
        vec!["https://relay.example".into()],
        vec!["wss://user@relay.example".into()],
        vec!["wss://relay.example?token=secret".into()],
        vec!["wss://relay.example".into(), "wss://relay.example/".into()],
    ] {
        assert!(matches!(
            intents.prepare(
                &event,
                &relay_set,
                1,
                &public_key,
                NOW,
                &EventLimits::default(),
            ),
            Err(ProfilePublicationIntentError::InvalidRelays)
        ));
    }
    assert!(matches!(
        intents.prepare(
            &event,
            &relays(),
            0,
            &public_key,
            NOW,
            &EventLimits::default(),
        ),
        Err(ProfilePublicationIntentError::InvalidThreshold)
    ));
    intents
        .prepare(
            &event,
            &relays(),
            2,
            &public_key,
            NOW,
            &EventLimits::default(),
        )
        .expect("valid intent");
    assert!(matches!(
        intents.acknowledge(&event.id, &[2], &public_key, NOW, &EventLimits::default(),),
        Err(ProfilePublicationIntentError::InvalidProgress)
    ));
    assert!(matches!(
        intents.acknowledge("00", &[0], &public_key, NOW, &EventLimits::default(),),
        Err(ProfilePublicationIntentError::PendingConflict)
    ));
}

#[tokio::test]
async fn ciphertext_plaintext_and_snapshot_progress_corruption_fail_closed() {
    let directory = tempdir().expect("state directory");
    let secret = [65; 32];
    let public_key = xonly_public_key(&secret).expect("public key");
    let event = profile(&secret, NOW, "tom.local");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
    let intents = ProfilePublicationIntentStore::new(&store);
    intents
        .prepare(
            &event,
            &relays(),
            2,
            &public_key,
            NOW,
            &EventLimits::default(),
        )
        .expect("prepare");
    let record_path = directory
        .path()
        .join("records")
        .join(PROFILE_PUBLICATION_INTENT_RECORD_NAME);
    let mut ciphertext = fs::read(&record_path).expect("read ciphertext");
    *ciphertext.last_mut().expect("ciphertext byte") ^= 1;
    fs::write(&record_path, ciphertext).expect("tamper ciphertext");
    assert!(matches!(
        intents.load(&public_key, NOW, &EventLimits::default()),
        Err(ProfilePublicationIntentError::Store(
            StoreError::Authentication
        ))
    ));

    store
        .write(PROFILE_PUBLICATION_INTENT_RECORD_NAME, b"not-json")
        .expect("seal malformed plaintext");
    assert!(matches!(
        intents.load(&public_key, NOW, &EventLimits::default()),
        Err(ProfilePublicationIntentError::Encoding)
    ));

    let invalid_progress = serde_json::json!({
        "version": 1,
        "event": event,
        "relay_urls": ["wss://relay-a.example/", "wss://relay-b.example/"],
        "required_acknowledgements": 2,
        "acknowledged_relay_indices": [0, 2]
    });
    store
        .write(
            PROFILE_PUBLICATION_INTENT_RECORD_NAME,
            &serde_json::to_vec(&invalid_progress).expect("encode invalid progress"),
        )
        .expect("seal invalid progress");
    assert!(matches!(
        intents.load(&public_key, NOW, &EventLimits::default()),
        Err(ProfilePublicationIntentError::InvalidProgress)
    ));
}
