use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    event::EventLimits,
    profile_metadata::{NostrProfileDraft, create_profile_metadata_with_aux},
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    ProfilePublicationConfig, ProfilePublicationCoordinator, ProfilePublicationCoordinatorError,
    ProfilePublicationOutcomeStatus, ProfilePublicationServiceConfig,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::{accept_async, tungstenite::Message};

const NOW: u64 = 1_800_000_000;

async fn relay(listener: TcpListener, first_accept: bool) -> Vec<String> {
    let mut profile_event_ids = Vec::new();
    for connection_index in 0..2 {
        let (stream, _) = listener.accept().await.expect("relay connection");
        let mut socket = accept_async(stream).await.expect("WebSocket");
        socket
            .send(Message::Text(
                json!(["AUTH", format!("coordinator-{connection_index}")])
                    .to_string()
                    .into(),
            ))
            .await
            .expect("authentication challenge");
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) => {
                    let value: serde_json::Value =
                        serde_json::from_str(&text).expect("relay frame");
                    if value[0] == "AUTH" {
                        let event_id = value[1]["id"].as_str().expect("auth ID");
                        socket
                            .send(Message::Text(
                                json!(["OK", event_id, true, "authenticated"])
                                    .to_string()
                                    .into(),
                            ))
                            .await
                            .expect("authentication acknowledgement");
                    } else if value[0] == "EVENT" {
                        let event_id = value[1]["id"].as_str().expect("event ID").to_owned();
                        profile_event_ids.push(event_id.clone());
                        let accepted = connection_index > 0 || first_accept;
                        socket
                            .send(Message::Text(
                                json!(["OK", event_id, accepted, "profile policy"])
                                    .to_string()
                                    .into(),
                            ))
                            .await
                            .expect("profile acknowledgement");
                    }
                }
                Message::Ping(payload) => socket
                    .send(Message::Pong(payload))
                    .await
                    .expect("relay pong"),
                Message::Close(_) => break,
                _ => {}
            }
        }
    }
    profile_event_ids
}

#[tokio::test]
async fn sealed_partial_publication_resumes_exactly_after_restart() {
    let accepting_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("accepting listener");
    let retrying_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("retrying listener");
    let accepting_url = format!(
        "ws://{}/",
        accepting_listener.local_addr().expect("accepting address")
    );
    let retrying_url = format!(
        "ws://{}/",
        retrying_listener.local_addr().expect("retrying address")
    );
    let accepting_server = tokio::spawn(relay(accepting_listener, true));
    let retrying_server = tokio::spawn(relay(retrying_listener, false));

    let directory = tempdir().expect("state directory");
    let store = Arc::new(
        SealedStore::open(directory.path(), RequestedProvider::File)
            .await
            .expect("sealed store"),
    );
    let secret = [91; 32];
    let event = create_profile_metadata_with_aux(
        &secret,
        NOW,
        &NostrProfileDraft {
            nostr_name: Some("tom.local".into()),
            display_name: Some("Tom Ballard".into()),
            about: Some("Building OmaChat".into()),
            picture: None,
        },
        &[92; 32],
        &EventLimits::default(),
    )
    .expect("profile event");
    let config = ProfilePublicationConfig {
        relays: vec![accepting_url, retrying_url],
        required_acknowledgements: 2,
    };
    let signer = RelayAuthSigner::from_secret_key(secret).expect("auth signer");
    let first = ProfilePublicationCoordinator::spawn(
        Arc::clone(&store),
        &config,
        signer.clone(),
        ProfilePublicationServiceConfig::default(),
    )
    .expect("first coordinator");
    let partial = first
        .handle()
        .publish(&event, NOW)
        .await
        .expect("first publication");
    assert_eq!(partial.status, ProfilePublicationOutcomeStatus::Pending);
    assert_eq!(partial.acknowledged_relays, 1);
    assert_eq!(partial.required_acknowledgements, 2);
    first.shutdown().await.expect("first shutdown");

    let resumed = ProfilePublicationCoordinator::spawn(
        Arc::clone(&store),
        &config,
        signer,
        ProfilePublicationServiceConfig::default(),
    )
    .expect("resumed coordinator");
    let complete = resumed
        .handle()
        .resume(NOW)
        .await
        .expect("resume publication")
        .expect("sealed publication");
    assert_eq!(complete.event_id, event.id);
    assert_eq!(complete.status, ProfilePublicationOutcomeStatus::Complete);
    assert_eq!(complete.acknowledged_relays, 2);
    assert_eq!(complete.required_acknowledgements, 2);
    resumed.shutdown().await.expect("resumed shutdown");

    let accepting_ids = accepting_server.await.expect("accepting relay");
    let retrying_ids = retrying_server.await.expect("retrying relay");
    assert_eq!(accepting_ids.as_slice(), std::slice::from_ref(&event.id));
    assert_eq!(retrying_ids, [event.id.clone(), event.id]);
}

#[tokio::test]
async fn quiesce_cancels_an_unacknowledged_publish_and_joins_the_relay() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("relay listener");
    let relay_url = format!("ws://{}/", listener.local_addr().expect("relay address"));
    let (published, publication_started) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("relay connection");
        let mut socket = accept_async(stream).await.expect("WebSocket");
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) => {
                    let value: serde_json::Value =
                        serde_json::from_str(&text).expect("relay frame");
                    if value[0] == "EVENT" {
                        let _ = published.send(());
                        while let Some(Ok(message)) = socket.next().await {
                            if matches!(message, Message::Close(_)) {
                                return;
                            }
                        }
                        return;
                    }
                }
                Message::Ping(payload) => socket
                    .send(Message::Pong(payload))
                    .await
                    .expect("relay pong"),
                Message::Close(_) => return,
                _ => {}
            }
        }
    });

    let directory = tempdir().expect("state directory");
    let store = Arc::new(
        SealedStore::open(directory.path(), RequestedProvider::File)
            .await
            .expect("sealed store"),
    );
    let secret = [93; 32];
    let event = create_profile_metadata_with_aux(
        &secret,
        NOW,
        &NostrProfileDraft {
            nostr_name: Some("cancel.local".into()),
            display_name: None,
            about: None,
            picture: None,
        },
        &[94; 32],
        &EventLimits::default(),
    )
    .expect("profile event");
    let coordinator = ProfilePublicationCoordinator::spawn(
        store,
        &ProfilePublicationConfig {
            relays: vec![relay_url],
            required_acknowledgements: 1,
        },
        RelayAuthSigner::from_secret_key(secret).expect("auth signer"),
        ProfilePublicationServiceConfig::default(),
    )
    .expect("coordinator");
    let handle = coordinator.handle();
    let publisher = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.publish(&event, NOW).await })
    };
    publication_started.await.expect("publication started");
    tokio::time::timeout(Duration::from_secs(1), handle.quiesce())
        .await
        .expect("bounded quiesce");
    assert!(matches!(
        publisher.await.expect("publisher task"),
        Err(ProfilePublicationCoordinatorError::Stopped)
    ));
    coordinator.shutdown().await.expect("coordinator shutdown");
    server.await.expect("relay shutdown");
}
