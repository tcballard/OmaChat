use std::{sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::RelayAuthSigner,
    discovery::NIP65_RELAY_LIST_KIND,
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
};
use omachatd::{
    NostrRelayListPublisherConfig, NostrRelayListPublisherService, RelayListPublisher,
    RelayListRelayStatus,
};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publisher_authenticates_reports_each_relay_and_joins_connections() {
    let accepted_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rejected_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let accepted_url = format!("ws://{}", accepted_listener.local_addr().unwrap());
    let rejected_url = format!("ws://{}", rejected_listener.local_addr().unwrap());
    let secret = [161; 32];
    let event = relay_list_event(&secret);
    let expected_event = event.clone();
    let accepted = tokio::spawn(serve_relay(
        accepted_listener,
        expected_event.clone(),
        true,
        true,
    ));
    let rejected = tokio::spawn(serve_relay(rejected_listener, expected_event, false, false));
    let service = NostrRelayListPublisherService::spawn(
        RelayAuthSigner::from_secret_key(secret).unwrap(),
        test_config(),
    )
    .unwrap();
    let publisher: Arc<dyn RelayListPublisher> = Arc::new(service.handle());
    let results = publisher
        .publish(event, vec![accepted_url.clone(), rejected_url.clone()])
        .await;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].relay_url, accepted_url);
    assert_eq!(results[0].status, RelayListRelayStatus::Acknowledged);
    assert_eq!(results[1].relay_url, rejected_url);
    assert_eq!(results[1].status, RelayListRelayStatus::Rejected);
    service.shutdown().await.unwrap();
    accepted.await.unwrap();
    rejected.await.unwrap();
}

#[tokio::test]
async fn signer_author_mismatch_fails_without_networking() {
    let signer_secret = [162; 32];
    let author_secret = [163; 32];
    let service = NostrRelayListPublisherService::spawn(
        RelayAuthSigner::from_secret_key(signer_secret).unwrap(),
        test_config(),
    )
    .unwrap();
    let results = service
        .handle()
        .publish(
            relay_list_event(&author_secret),
            vec!["wss://must-not-connect.invalid".into()],
        )
        .await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].status, RelayListRelayStatus::Failed);
    service.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_caller_cannot_detach_an_inflight_relay_actor() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let secret = [165; 32];
    let event = relay_list_event(&secret);
    let (observed, observed_event) = tokio::sync::oneshot::channel();
    let relay = tokio::spawn(serve_delayed_relay(listener, event.clone(), observed));
    let service = NostrRelayListPublisherService::spawn(
        RelayAuthSigner::from_secret_key(secret).unwrap(),
        test_config(),
    )
    .unwrap();
    let handle = service.handle();
    let publish = tokio::spawn(async move { handle.publish(event, vec![relay_url]).await });
    observed_event.await.unwrap();
    publish.abort();
    assert!(publish.await.unwrap_err().is_cancelled());
    service.shutdown().await.unwrap();
    relay.await.unwrap();
}

async fn serve_relay(
    listener: TcpListener,
    expected_event: SignedEvent,
    challenge: bool,
    accept: bool,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    if challenge {
        socket
            .send(Message::Text(
                json!(["AUTH", "relay-list-publication"]).to_string().into(),
            ))
            .await
            .unwrap();
        let authentication = next_json(&mut socket).await;
        assert_eq!(authentication[0], "AUTH");
        let auth_event: SignedEvent = serde_json::from_value(authentication[1].clone()).unwrap();
        auth_event
            .verify(unix_now() + 1, &EventLimits::default())
            .unwrap();
        assert_eq!(auth_event.pubkey, expected_event.pubkey);
        socket
            .send(Message::Text(
                json!(["OK", auth_event.id, true, "authenticated"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
    }
    let publication = next_json(&mut socket).await;
    assert_eq!(publication[0], "EVENT");
    assert_eq!(
        publication[1],
        serde_json::to_value(&expected_event).unwrap()
    );
    socket
        .send(Message::Text(
            json!([
                "OK",
                expected_event.id,
                accept,
                if accept { "stored" } else { "blocked" }
            ])
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Ping(payload)) => socket.send(Message::Pong(payload)).await.unwrap(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

async fn serve_delayed_relay(
    listener: TcpListener,
    expected_event: SignedEvent,
    observed: tokio::sync::oneshot::Sender<()>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    let publication = next_json(&mut socket).await;
    assert_eq!(publication[0], "EVENT");
    assert_eq!(
        publication[1],
        serde_json::to_value(&expected_event).unwrap()
    );
    let _ = observed.send(());
    tokio::time::sleep(Duration::from_millis(100)).await;
    socket
        .send(Message::Text(
            json!(["OK", expected_event.id, true, "stored"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Ping(payload)) => socket.send(Message::Pong(payload)).await.unwrap(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => return serde_json::from_str(&text).unwrap(),
            Some(Ok(Message::Ping(payload))) => socket.send(Message::Pong(payload)).await.unwrap(),
            Some(Ok(Message::Close(frame))) => panic!("relay closed early: {frame:?}"),
            Some(Ok(_)) => {}
            Some(Err(error)) => panic!("relay failed: {error}"),
            None => panic!("relay ended early"),
        }
    }
}

fn relay_list_event(secret: &[u8; 32]) -> SignedEvent {
    let public_key = xonly_public_key(secret).unwrap();
    UnsignedEvent::new(
        hex::encode(public_key),
        unix_now(),
        NIP65_RELAY_LIST_KIND,
        vec![vec!["r".into(), "wss://participant.example".into()]],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(secret, &[164; 32], &EventLimits::default())
    .unwrap()
}

fn test_config() -> NostrRelayListPublisherConfig {
    NostrRelayListPublisherConfig {
        relay_ready_timeout: Duration::from_secs(1),
        relay_settle_timeout: Duration::from_millis(50),
        service_shutdown_timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(1),
        response_timeout: Duration::from_secs(1),
        relay_shutdown_timeout: Duration::from_secs(1),
        ..NostrRelayListPublisherConfig::default()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
