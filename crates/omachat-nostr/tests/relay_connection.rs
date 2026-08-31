use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    auth::{NIP42_AUTH_KIND, RelayAuthSigner},
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    relay::{RelayConfig, RelayConnection, RelayError, RelayNotification, RelayRoute},
};
use serde_json::{Value, json};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn config(address: std::net::SocketAddr) -> RelayConfig {
    let mut config = RelayConfig::new(format!("ws://{address}/"), RelayRoute::Direct);
    config.ping_interval = Duration::from_secs(5);
    config.idle_timeout = Duration::from_secs(15);
    config.response_timeout = Duration::from_secs(2);
    config.reconnect_initial_delay = Duration::from_millis(10);
    config.reconnect_max_delay = Duration::from_millis(20);
    config
}

fn event() -> omachat_nostr::event::SignedEvent {
    let secret = [7_u8; 32];
    UnsignedEvent::new(
        hex::encode(xonly_public_key(&secret).unwrap()),
        now(),
        1,
        vec![],
        "hello".into(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&secret, &[9; 32], &EventLimits::default())
    .unwrap()
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            other => panic!("unexpected client message: {other:?}"),
        }
    }
}

async fn wait_for<F>(connection: &mut RelayConnection, predicate: F) -> RelayNotification
where
    F: Fn(&RelayNotification) -> bool,
{
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notification = connection.next_notification().await.unwrap();
            if predicate(&notification) {
                return notification;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn publishes_subscribes_closes_and_shuts_down_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        assert_eq!(
            next_json(&mut socket).await,
            json!(["REQ", "cell", {"kinds":[1]}])
        );
        socket
            .send(Message::Text(json!(["EOSE", "cell"]).to_string().into()))
            .await
            .unwrap();
        let publish = next_json(&mut socket).await;
        assert_eq!(publish[0], "EVENT");
        let id = publish[1]["id"].as_str().unwrap();
        socket
            .send(Message::Text(
                json!(["OK", id, true, "stored"]).to_string().into(),
            ))
            .await
            .unwrap();
        assert_eq!(next_json(&mut socket).await, json!(["CLOSE", "cell"]));
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
    });

    let mut connection = RelayConnection::spawn(config(address)).unwrap();
    connection
        .subscribe("cell".into(), vec![json!({"kinds":[1]})])
        .await
        .unwrap();
    assert!(matches!(
        wait_for(&mut connection, |item| matches!(
            item,
            RelayNotification::EndOfStoredEvents { .. }
        ))
        .await,
        RelayNotification::EndOfStoredEvents { subscription_id } if subscription_id == "cell"
    ));
    let acknowledgement = connection.publish(event()).await.unwrap();
    assert_eq!(acknowledgement.message, "stored");
    connection.close_subscription("cell".into()).await.unwrap();
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn replays_subscriptions_after_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (first, _) = listener.accept().await.unwrap();
        let mut first = accept_async(first).await.unwrap();
        assert_eq!(next_json(&mut first).await[0], "REQ");
        first.close(None).await.unwrap();

        let (second, _) = listener.accept().await.unwrap();
        let mut second = accept_async(second).await.unwrap();
        assert_eq!(
            next_json(&mut second).await,
            json!(["REQ", "replay", {"limit":1}])
        );
        second
            .send(Message::Text(json!(["EOSE", "replay"]).to_string().into()))
            .await
            .unwrap();
        while let Some(Ok(message)) = second.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    });

    let mut connection = RelayConnection::spawn(config(address)).unwrap();
    connection
        .subscribe("replay".into(), vec![json!({"limit":1})])
        .await
        .unwrap();
    wait_for(&mut connection, |item| {
        matches!(item, RelayNotification::Disconnected)
    })
    .await;
    wait_for(&mut connection, |item| {
        matches!(item, RelayNotification::Connected)
    })
    .await;
    wait_for(&mut connection, |item| {
        matches!(item, RelayNotification::EndOfStoredEvents { .. })
    })
    .await;
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn surfaces_auth_required_publish_rejection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let publish = next_json(&mut socket).await;
        let id = publish[1]["id"].as_str().unwrap();
        socket
            .send(Message::Text(
                json!(["OK", id, false, "auth-required: sign in"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
    });

    let connection = RelayConnection::spawn(config(address)).unwrap();
    assert_eq!(
        connection.publish(event()).await.unwrap_err(),
        RelayError::PublishRejected("auth-required: sign in".into())
    );
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn answers_nip42_challenge_with_the_configured_principal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay_url = format!("ws://{address}/");
    let agent_secret = [0x31; 32];
    let expected_public_key = hex::encode(xonly_public_key(&agent_secret).unwrap());
    let server_relay_url = relay_url.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(
                json!(["AUTH", "hermetic-challenge"]).to_string().into(),
            ))
            .await
            .unwrap();
        let auth = next_json(&mut socket).await;
        assert_eq!(auth[0], "AUTH");
        let event: omachat_nostr::event::SignedEvent =
            serde_json::from_value(auth[1].clone()).unwrap();
        event.verify(now(), &EventLimits::default()).unwrap();
        assert_eq!(event.kind, NIP42_AUTH_KIND);
        assert_eq!(event.pubkey, expected_public_key);
        assert_eq!(event.content, "");
        assert_eq!(
            event.tags,
            vec![
                vec!["relay".to_owned(), server_relay_url],
                vec!["challenge".to_owned(), "hermetic-challenge".to_owned()],
            ]
        );
        socket
            .send(Message::Text(
                json!(["OK", event.id, true, "authenticated"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        while let Some(Ok(message)) = socket.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    });

    let mut relay_config = config(address);
    relay_config.auth = Some(RelayAuthSigner::from_secret_key(agent_secret).unwrap());
    let mut connection = RelayConnection::spawn(relay_config).unwrap();
    assert!(matches!(
        wait_for(&mut connection, |item| matches!(
            item,
            RelayNotification::AuthChallenge(_)
        ))
        .await,
        RelayNotification::AuthChallenge(challenge) if challenge == "hermetic-challenge"
    ));
    assert!(matches!(
        wait_for(&mut connection, |item| matches!(
            item,
            RelayNotification::Authenticated { .. }
        ))
        .await,
        RelayNotification::Authenticated { public_key }
            if public_key == hex::encode(xonly_public_key(&agent_secret).unwrap())
    ));
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn reports_nip42_rejection_without_claiming_authentication() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(json!(["AUTH", "denied"]).to_string().into()))
            .await
            .unwrap();
        let auth = next_json(&mut socket).await;
        socket
            .send(Message::Text(
                json!(["OK", auth[1]["id"], false, "restricted: not a member"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
    });

    let mut relay_config = config(address);
    relay_config.auth = Some(RelayAuthSigner::from_secret_key([0x32; 32]).unwrap());
    let mut connection = RelayConnection::spawn(relay_config).unwrap();
    assert!(matches!(
        wait_for(&mut connection, |item| matches!(
            item,
            RelayNotification::AuthenticationRejected { .. }
        ))
        .await,
        RelayNotification::AuthenticationRejected { message, .. }
            if message == "restricted: not a member"
    ));
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn oversized_or_malformed_input_disconnects_fail_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        socket
            .send(Message::Text("x".repeat(1024).into()))
            .await
            .unwrap();
    });

    let mut relay_config = config(address);
    relay_config.frame_limits.max_frame_bytes = 128;
    let mut connection = RelayConnection::spawn(relay_config).unwrap();
    wait_for(&mut connection, |item| {
        matches!(item, RelayNotification::Disconnected)
    })
    .await;
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn timed_out_publish_can_be_retried_without_leaking_pending_state() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let first = next_json(&mut socket).await;
        let second = next_json(&mut socket).await;
        assert_eq!(first[1]["id"], second[1]["id"]);
        socket
            .send(Message::Text(
                json!(["OK", second[1]["id"], true, "retried"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
    });

    let mut relay_config = config(address);
    relay_config.response_timeout = Duration::from_millis(30);
    let connection = RelayConnection::spawn(relay_config).unwrap();
    let signed = event();
    assert_eq!(
        connection.publish(signed.clone()).await.unwrap_err(),
        RelayError::ResponseTimeout
    );
    assert_eq!(connection.publish(signed).await.unwrap().message, "retried");
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn missing_pong_triggers_idle_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _socket = accept_async(stream).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let mut relay_config = config(address);
    relay_config.ping_interval = Duration::from_millis(20);
    relay_config.idle_timeout = Duration::from_millis(60);
    let mut connection = RelayConnection::spawn(relay_config).unwrap();
    wait_for(&mut connection, |item| {
        matches!(item, RelayNotification::Disconnected)
    })
    .await;
    connection.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn slow_notification_consumer_is_bounded_and_disconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        socket
            .send(Message::Text(
                json!(["NOTICE", "queue pressure"]).to_string().into(),
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let mut relay_config = config(address);
    relay_config.notification_capacity = 1;
    let connection = RelayConnection::spawn(relay_config).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        connection.shutdown().await.unwrap_err(),
        RelayError::Backpressure
    );
    server.await.unwrap();
}

#[tokio::test]
async fn shutdown_aborts_and_awaits_an_actor_wedged_in_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (handshake_sender, handshake_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 256];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "client closed before sending its handshake");
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        handshake_sender.send(()).unwrap();

        // Never answer the WebSocket handshake. The client socket reaching
        // EOF proves shutdown did not merely detach its blocked actor.
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });

    let mut relay_config = config(address);
    relay_config.connect_timeout = Duration::from_secs(30);
    relay_config.shutdown_timeout = Duration::from_millis(25);
    let connection = RelayConnection::spawn(relay_config).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handshake_receiver)
        .await
        .expect("client starts WebSocket handshake")
        .expect("handshake signal");

    let started = Instant::now();
    assert_eq!(
        connection.shutdown().await.unwrap_err(),
        RelayError::ShutdownTimeout
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "shutdown exceeded its actor-owned deadline"
    );
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("aborted actor drops its socket before shutdown returns")
        .expect("handshake server task");
}
