use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    event::EventLimits,
    profile_metadata::{NostrProfileDraft, create_profile_metadata_with_aux},
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    ProfilePublicationConfig, ProfilePublicationCoordinator, ProfilePublicationProgress,
    ProfilePublicationServiceConfig,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::net::TcpListener;
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
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
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
    let mut first = ProfilePublicationCoordinator::new(
        &store,
        &config,
        signer.clone(),
        ProfilePublicationServiceConfig::default(),
    )
    .expect("first coordinator");
    let ProfilePublicationProgress::Pending(partial) = first
        .publish(&event, NOW, &EventLimits::default())
        .await
        .expect("first publication")
    else {
        panic!("profile completed before its quorum");
    };
    assert_eq!(partial.acknowledged_relay_indices().len(), 1);
    first.shutdown().await.expect("first shutdown");

    let mut resumed = ProfilePublicationCoordinator::new(
        &store,
        &config,
        signer,
        ProfilePublicationServiceConfig::default(),
    )
    .expect("resumed coordinator");
    assert_eq!(
        resumed
            .resume(NOW, &EventLimits::default())
            .await
            .expect("resume publication"),
        Some(ProfilePublicationProgress::Complete)
    );
    resumed.shutdown().await.expect("resumed shutdown");

    let accepting_ids = accepting_server.await.expect("accepting relay");
    let retrying_ids = retrying_server.await.expect("retrying relay");
    assert_eq!(accepting_ids.as_slice(), std::slice::from_ref(&event.id));
    assert_eq!(retrying_ids, [event.id.clone(), event.id]);
}
