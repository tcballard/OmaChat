use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::{NIP42_AUTH_KIND, RelayAuthSigner},
    event::{EventLimits, SignedEvent, xonly_public_key},
    profile_metadata::{NostrProfileDraft, create_profile_metadata_with_aux},
};
use omachat_store::{RequestedProvider, SealedStore};
use omachatd::{
    ProfilePublicationIntentStore, ProfilePublicationProgress, ProfilePublicationService,
    ProfilePublicationServiceConfig,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

async fn relay(
    listener: TcpListener,
    first_accept: bool,
    expected_public_key: String,
) -> Vec<String> {
    let mut event_ids = Vec::new();
    for connection_index in 0..2 {
        let (stream, _) = listener.accept().await.expect("relay connection");
        let mut socket = accept_async(stream).await.expect("WebSocket");
        let challenge = format!("profile-publication-{connection_index}");
        socket
            .send(Message::Text(json!(["AUTH", challenge]).to_string().into()))
            .await
            .expect("authentication challenge");
        let authentication = loop {
            match socket.next().await.expect("authentication frame") {
                Ok(Message::Text(text)) => {
                    break serde_json::from_str::<serde_json::Value>(&text)
                        .expect("authentication JSON");
                }
                Ok(Message::Ping(payload)) => socket
                    .send(Message::Pong(payload))
                    .await
                    .expect("authentication pong"),
                Ok(message) => panic!("unexpected authentication frame: {message:?}"),
                Err(error) => panic!("authentication socket failed: {error}"),
            }
        };
        assert_eq!(authentication[0], "AUTH");
        let authentication_event: SignedEvent =
            serde_json::from_value(authentication[1].clone()).expect("authentication event");
        assert_eq!(authentication_event.kind, NIP42_AUTH_KIND);
        assert_eq!(authentication_event.pubkey, expected_public_key);
        socket
            .send(Message::Text(
                json!(["OK", authentication_event.id, true, "authenticated"])
                    .to_string()
                    .into(),
            ))
            .await
            .expect("authentication acknowledgement");
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) => {
                    let value: serde_json::Value =
                        serde_json::from_str(&text).expect("relay frame");
                    if value[0] == "EVENT" {
                        let event_id = value[1]["id"].as_str().expect("event ID").to_owned();
                        event_ids.push(event_id.clone());
                        let accepted = connection_index > 0 || first_accept;
                        socket
                            .send(Message::Text(
                                json!([
                                    "OK",
                                    event_id,
                                    accepted,
                                    if accepted { "stored" } else { "retry" }
                                ])
                                .to_string()
                                .into(),
                            ))
                            .await
                            .expect("relay acknowledgement");
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
    event_ids
}

#[tokio::test]
async fn restart_retries_exact_event_only_on_unacknowledged_relay() {
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
    let directory = tempdir().expect("state directory");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
    let secret = [81; 32];
    let public_key = xonly_public_key(&secret).expect("public key");
    let event = create_profile_metadata_with_aux(
        &secret,
        1_800_000_000,
        &NostrProfileDraft {
            nostr_name: Some("tom.local".into()),
            display_name: Some("Tom Ballard".into()),
            about: None,
            picture: None,
        },
        &[82; 32],
        &EventLimits::default(),
    )
    .expect("profile event");
    let accepting_server = tokio::spawn(relay(accepting_listener, true, event.pubkey.clone()));
    let retrying_server = tokio::spawn(relay(retrying_listener, false, event.pubkey.clone()));
    let pending = ProfilePublicationIntentStore::new(&store)
        .prepare(
            &event,
            &[accepting_url.clone(), retrying_url.clone()],
            2,
            &public_key,
            1_800_000_000,
            &EventLimits::default(),
        )
        .expect("pending profile");
    let auth = RelayAuthSigner::from_secret_key(secret).expect("auth signer");
    let service = ProfilePublicationService::spawn(
        pending.relay_urls(),
        auth.clone(),
        ProfilePublicationServiceConfig::default(),
    )
    .expect("publisher");
    let first = service
        .handle()
        .publish(&pending)
        .await
        .expect("first publish");
    assert_eq!(first.accepted, 1);
    assert_eq!(first.attempted, 2);
    let accepted = first
        .outcomes
        .iter()
        .filter(|outcome| outcome.result.is_ok())
        .map(|outcome| outcome.relay_index)
        .collect::<Vec<_>>();
    let ProfilePublicationProgress::Pending(partial) = ProfilePublicationIntentStore::new(&store)
        .acknowledge(
            &event.id,
            &accepted,
            &public_key,
            1_800_000_000,
            &EventLimits::default(),
        )
        .expect("partial progress")
    else {
        panic!("profile completed after one acknowledgement");
    };
    service.shutdown().await.expect("first shutdown");

    let resumed = ProfilePublicationService::spawn(
        partial.relay_urls(),
        auth,
        ProfilePublicationServiceConfig::default(),
    )
    .expect("resumed publisher");
    let second = resumed
        .handle()
        .publish(&partial)
        .await
        .expect("retry publish");
    assert_eq!(second.accepted, 1);
    assert_eq!(second.attempted, 1);
    let accepted = second
        .outcomes
        .iter()
        .filter(|outcome| outcome.result.is_ok())
        .map(|outcome| outcome.relay_index)
        .collect::<Vec<_>>();
    assert_eq!(
        ProfilePublicationIntentStore::new(&store)
            .acknowledge(
                &event.id,
                &accepted,
                &public_key,
                1_800_000_000,
                &EventLimits::default(),
            )
            .expect("complete progress"),
        ProfilePublicationProgress::Complete
    );
    resumed.shutdown().await.expect("resumed shutdown");

    let accepting_ids = accepting_server.await.expect("accepting relay");
    let retrying_ids = retrying_server.await.expect("retrying relay");
    assert_eq!(accepting_ids.as_slice(), std::slice::from_ref(&event.id));
    assert_eq!(retrying_ids, [event.id.clone(), event.id]);
}
