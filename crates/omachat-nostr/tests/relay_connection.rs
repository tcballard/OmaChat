use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    relay::{RelayConfig, RelayConnection, RelayError, RelayNotification, RelayRoute},
};
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
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
