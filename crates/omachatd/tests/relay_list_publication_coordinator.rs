use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use omachat_nostr::{
    discovery::{NIP65_RELAY_LIST_KIND, RelayDiscoveryLimits},
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    RelayListPublicationCoordinator, RelayListPublicationCoordinatorError,
    RelayListPublicationIntentState, RelayListPublicationIntentStore,
    RelayListPublicationOutcomeStatus, RelayListPublicationSource, RelayListPublishFuture,
    RelayListPublisher, RelayListRelayResult, RelayListRelayStatus,
};
use tempfile::tempdir;

#[tokio::test]
async fn partial_publication_resumes_the_exact_event_only_on_unacknowledged_relays() {
    let state = tempdir().unwrap();
    let secret = [151; 32];
    let public_key = xonly_public_key(&secret).unwrap();
    let event = relay_list_event(&secret, 4_000);

    let first_publisher = Arc::new(RecordingPublisher::new(vec![vec![
        relay_result("wss://one.example/", RelayListRelayStatus::Acknowledged),
        relay_result("wss://two.example/", RelayListRelayStatus::Failed),
        relay_result("wss://three.example/", RelayListRelayStatus::Rejected),
    ]]));
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    let coordinator = new_coordinator(first_publisher.clone());
    let first = coordinator
        .publish(&store, &event, &public_key, 2, 4_000)
        .await
        .unwrap();
    assert_eq!(first.status, RelayListPublicationOutcomeStatus::Pending);
    assert_eq!(first.source, RelayListPublicationSource::New);
    assert_eq!(first.acknowledged_relays, ["wss://one.example/"]);
    assert_eq!(first.failed_relays, ["wss://two.example/"]);
    assert_eq!(first.rejected_relays, ["wss://three.example/"]);
    assert_eq!(
        first_publisher.calls(),
        vec![(
            event.id.clone(),
            vec![
                "wss://one.example/".into(),
                "wss://two.example/".into(),
                "wss://three.example/".into(),
            ],
        )]
    );
    drop(coordinator);
    drop(store);

    let second_publisher = Arc::new(RecordingPublisher::new(vec![vec![
        relay_result("wss://two.example/", RelayListRelayStatus::Acknowledged),
        relay_result("wss://three.example/", RelayListRelayStatus::Failed),
    ]]));
    let reopened = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    let resumed = new_coordinator(second_publisher.clone())
        .resume(&reopened, 4_001)
        .await
        .unwrap()
        .expect("sealed publication should resume");
    assert_eq!(resumed.status, RelayListPublicationOutcomeStatus::Complete);
    assert_eq!(resumed.source, RelayListPublicationSource::SealedReplay);
    assert_eq!(
        resumed.acknowledged_relays,
        ["wss://one.example/", "wss://two.example/"]
    );
    assert_eq!(
        second_publisher.calls(),
        vec![(
            event.id,
            vec!["wss://two.example/".into(), "wss://three.example/".into(),],
        )]
    );
    assert!(matches!(
        RelayListPublicationIntentStore::new(&reopened)
            .load(
                4_001,
                &EventLimits::default(),
                &RelayDiscoveryLimits::default(),
            )
            .unwrap(),
        RelayListPublicationIntentState::Missing
    ));
}

#[tokio::test]
async fn malformed_transport_results_cannot_mutate_sealed_progress() {
    let state = tempdir().unwrap();
    let secret = [152; 32];
    let public_key = xonly_public_key(&secret).unwrap();
    let event = relay_list_event(&secret, 5_000);
    let publisher = Arc::new(RecordingPublisher::new(vec![vec![
        relay_result("wss://one.example/", RelayListRelayStatus::Acknowledged),
        relay_result("wss://one.example/", RelayListRelayStatus::Acknowledged),
        relay_result("wss://three.example/", RelayListRelayStatus::Acknowledged),
    ]]));
    let store = SealedStore::open(state.path(), RequestedProvider::File)
        .await
        .unwrap();
    assert!(matches!(
        new_coordinator(publisher)
            .publish(&store, &event, &public_key, 2, 5_000)
            .await,
        Err(RelayListPublicationCoordinatorError::InvalidTransportResult)
    ));
    let RelayListPublicationIntentState::Pending(pending) =
        RelayListPublicationIntentStore::new(&store)
            .load(
                5_000,
                &EventLimits::default(),
                &RelayDiscoveryLimits::default(),
            )
            .unwrap()
    else {
        panic!("exact intent should remain pending");
    };
    assert_eq!(pending.event(), &event);
    assert!(pending.acknowledged_relays().is_empty());
}

fn new_coordinator(publisher: Arc<RecordingPublisher>) -> RelayListPublicationCoordinator {
    RelayListPublicationCoordinator::new(
        publisher,
        EventLimits::default(),
        RelayDiscoveryLimits::default(),
    )
}

struct RecordingPublisher {
    responses: Mutex<VecDeque<Vec<RelayListRelayResult>>>,
    calls: Mutex<Vec<(String, Vec<String>)>>,
}

impl RecordingPublisher {
    fn new(responses: Vec<Vec<RelayListRelayResult>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }
}

impl RelayListPublisher for RecordingPublisher {
    fn publish<'a>(
        &'a self,
        event: SignedEvent,
        relay_urls: Vec<String>,
    ) -> RelayListPublishFuture<'a> {
        self.calls.lock().unwrap().push((event.id, relay_urls));
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("test publisher has a response");
        Box::pin(async move { response })
    }
}

fn relay_result(relay_url: &str, status: RelayListRelayStatus) -> RelayListRelayResult {
    RelayListRelayResult {
        relay_url: relay_url.into(),
        status,
    }
}

fn relay_list_event(secret: &[u8; 32], created_at: u64) -> SignedEvent {
    let public_key = xonly_public_key(secret).unwrap();
    UnsignedEvent::new(
        hex::encode(public_key),
        created_at,
        NIP65_RELAY_LIST_KIND,
        vec![
            vec!["r".into(), "wss://one.example".into(), "write".into()],
            vec!["r".into(), "wss://two.example".into(), "write".into()],
            vec!["r".into(), "wss://three.example".into()],
        ],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(secret, &[153; 32], &EventLimits::default())
    .unwrap()
}
