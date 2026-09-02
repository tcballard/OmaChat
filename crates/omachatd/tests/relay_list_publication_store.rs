use omachat_nostr::{
    discovery::{NIP65_RELAY_LIST_KIND, RelayDiscoveryLimits},
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME, RelayListPublicationIntentError,
    RelayListPublicationIntentState, RelayListPublicationIntentStore, RelayListPublicationMutation,
};
use tempfile::tempdir;

#[tokio::test]
async fn exact_event_and_partial_acknowledgements_survive_restart() {
    let state = tempdir().unwrap();
    let secret = [141; 32];
    let public_key = xonly_public_key(&secret).unwrap();
    let event = relay_list_event(&secret, 1_000, "wss://one.example", "wss://two.example");
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    let intents = RelayListPublicationIntentStore::new(&store);
    assert_eq!(
        intents
            .prepare(
                &event,
                &public_key,
                2,
                1_000,
                &EventLimits::default(),
                &RelayDiscoveryLimits::default(),
            )
            .unwrap(),
        RelayListPublicationMutation::Stored
    );
    assert_eq!(
        intents
            .prepare(
                &event,
                &public_key,
                2,
                1_000,
                &EventLimits::default(),
                &RelayDiscoveryLimits::default(),
            )
            .unwrap(),
        RelayListPublicationMutation::Unchanged
    );
    let progress = intents
        .acknowledge(
            &event.id,
            "wss://one.example/",
            1_000,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .unwrap();
    assert!(!progress.complete);
    assert_eq!(progress.acknowledged_relays, ["wss://one.example/"]);
    drop(store);

    let reopened = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    let intents = RelayListPublicationIntentStore::new(&reopened);
    let RelayListPublicationIntentState::Pending(pending) = intents
        .load(
            1_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .unwrap()
    else {
        panic!("publication intent was not restored");
    };
    assert_eq!(pending.event(), &event);
    assert_eq!(pending.expected_public_key(), &public_key);
    assert_eq!(pending.required_acknowledgements(), 2);
    assert_eq!(
        pending.publication_relays(),
        ["wss://one.example/", "wss://two.example/"]
    );
    assert!(pending.acknowledged_relays().contains("wss://one.example/"));

    let progress = intents
        .acknowledge(
            &event.id,
            "wss://two.example/",
            1_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .unwrap();
    assert!(progress.complete);
    assert_eq!(progress.acknowledged_relays.len(), 2);
    assert!(matches!(
        intents
            .load(
                1_001,
                &EventLimits::default(),
                &RelayDiscoveryLimits::default(),
            )
            .unwrap(),
        RelayListPublicationIntentState::Missing
    ));
}

#[tokio::test]
async fn conflicting_event_policy_author_and_acknowledgements_fail_closed() {
    let state = tempdir().unwrap();
    let secret = [142; 32];
    let public_key = xonly_public_key(&secret).unwrap();
    let event = relay_list_event(&secret, 2_000, "wss://one.example", "wss://two.example");
    let replacement = relay_list_event(&secret, 2_001, "wss://three.example", "wss://four.example");
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    let intents = RelayListPublicationIntentStore::new(&store);
    intents
        .prepare(
            &event,
            &public_key,
            1,
            2_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        )
        .unwrap();
    assert!(matches!(
        intents.prepare(
            &replacement,
            &public_key,
            1,
            2_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListPublicationIntentError::PendingConflict)
    ));
    assert!(matches!(
        intents.prepare(
            &event,
            &public_key,
            2,
            2_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListPublicationIntentError::PendingConflict)
    ));
    assert!(matches!(
        intents.acknowledge(
            &replacement.id,
            "wss://one.example/",
            2_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListPublicationIntentError::EventMismatch)
    ));
    assert!(matches!(
        intents.acknowledge(
            &event.id,
            "wss://unknown.example/",
            2_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListPublicationIntentError::UnknownRelay)
    ));

    let attacker = [143; 32];
    let forged = relay_list_event(&attacker, 2_001, "wss://one.example", "wss://two.example");
    let other_state = tempdir().unwrap();
    let other_store = SealedStore::open(other_state.path(), RequestedProvider::File)
        .await
        .unwrap();
    assert!(matches!(
        RelayListPublicationIntentStore::new(&other_store).prepare(
            &forged,
            &public_key,
            1,
            2_001,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListPublicationIntentError::UnexpectedAuthor)
    ));
}

#[tokio::test]
async fn malformed_or_completed_persisted_state_is_rejected() {
    let state = tempdir().unwrap();
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    store
        .write(RELAY_LIST_PUBLICATION_INTENT_RECORD_NAME, b"{}")
        .unwrap();
    assert!(matches!(
        RelayListPublicationIntentStore::new(&store).load(
            3_000,
            &EventLimits::default(),
            &RelayDiscoveryLimits::default(),
        ),
        Err(RelayListPublicationIntentError::InvalidEncoding)
    ));
}

fn relay_list_event(secret: &[u8; 32], created_at: u64, first: &str, second: &str) -> SignedEvent {
    let public_key = xonly_public_key(secret).unwrap();
    UnsignedEvent::new(
        hex::encode(public_key),
        created_at,
        NIP65_RELAY_LIST_KIND,
        vec![
            vec!["r".into(), first.into(), "write".into()],
            vec!["r".into(), second.into()],
        ],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(secret, &[144; 32], &EventLimits::default())
    .unwrap()
}
