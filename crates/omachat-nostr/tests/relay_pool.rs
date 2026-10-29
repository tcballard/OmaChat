use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    pool::{RelayPool, RelayPoolConfig, RelayPoolError},
    relay::{RelayConfig, RelayNotification, RelayRoute},
};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn event() -> SignedEvent {
    let secret = [11_u8; 32];
    UnsignedEvent::new(
        hex::encode(xonly_public_key(&secret).unwrap()),
        now(),
        1,
        vec![],
        "pooled".into(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&secret, &[12; 32], &EventLimits::default())
    .unwrap()
}

fn relay_config(address: std::net::SocketAddr) -> RelayConfig {
    let mut config = RelayConfig::new(format!("ws://{address}/"), RelayRoute::Direct);
    config.ping_interval = Duration::from_secs(5);
    config.idle_timeout = Duration::from_secs(15);
    config.response_timeout = Duration::from_millis(500);
    config.reconnect_initial_delay = Duration::from_millis(10);
    config.reconnect_max_delay = Duration::from_millis(20);
    config
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            other => panic!("unexpected pool client message: {other:?}"),
        }
    }
}

async fn wait_connected(pool: &mut RelayPool, count: usize) {
    let mut connected = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        while connected < count {
            if matches!(
                pool.next_notification().await.unwrap().notification,
                RelayNotification::Connected
            ) {
                connected += 1;
            }
        }
    })
    .await
    .unwrap();
}

async fn finish_on_close(mut socket: WebSocketStream<TcpStream>) {
    while let Some(Ok(message)) = socket.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
}

#[tokio::test]
async fn healthy_acknowledgement_succeeds_while_one_relay_flaps() {
    let healthy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let flapping = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let configs = vec![
        relay_config(healthy.local_addr().unwrap()),
        relay_config(flapping.local_addr().unwrap()),
    ];
    let healthy_server = tokio::spawn(async move {
        let (stream, _) = healthy.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let publish = next_json(&mut socket).await;
        socket
            .send(Message::Text(
                json!(["OK", publish[1]["id"], true, "healthy"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        finish_on_close(socket).await;
    });
    let flapping_server = tokio::spawn(async move {
        let (stream, _) = flapping.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        assert_eq!(next_json(&mut socket).await[0], "EVENT");
        socket.close(None).await.unwrap();
    });

    let mut pool = RelayPool::spawn(configs, RelayPoolConfig::default()).unwrap();
    wait_connected(&mut pool, 2).await;
    let result = pool.publish(event()).await.unwrap();
    assert_eq!(result.accepted, 1);
    assert_eq!(result.attempted, 2);
    assert_eq!(result.outcomes.len(), 2);
    for outcome in pool.shutdown().await {
        outcome.unwrap();
    }
    healthy_server.await.unwrap();
    flapping_server.await.unwrap();
}

#[tokio::test]
async fn acknowledgement_threshold_fails_closed() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let configs = vec![
        relay_config(first.local_addr().unwrap()),
        relay_config(second.local_addr().unwrap()),
    ];
    let first_server = tokio::spawn(ack_server(first, true));
    let second_server = tokio::spawn(ack_server(second, false));
    let mut pool = RelayPool::spawn(
        configs,
        RelayPoolConfig {
            acknowledgement_threshold: 2,
            ..RelayPoolConfig::default()
        },
    )
    .unwrap();
    wait_connected(&mut pool, 2).await;
    assert_eq!(
        pool.publish(event()).await.unwrap_err(),
        RelayPoolError::AcknowledgementThreshold {
            accepted: 1,
            required: 2,
            attempted: 2,
        }
    );
    for outcome in pool.shutdown().await {
        outcome.unwrap();
    }
    first_server.await.unwrap();
    second_server.await.unwrap();
}

#[tokio::test]
async fn selected_publish_never_sends_to_an_ineligible_healthy_relay() {
    let ineligible = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authenticated = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let configs = vec![
        relay_config(ineligible.local_addr().unwrap()),
        relay_config(authenticated.local_addr().unwrap()),
    ];
    let ineligible_server = tokio::spawn(async move {
        let (stream, _) = ineligible.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, socket.next()).await {
                Err(_) => break,
                Ok(Some(Ok(Message::Ping(payload)))) => {
                    socket.send(Message::Pong(payload)).await.unwrap();
                }
                Ok(Some(Ok(Message::Text(text)))) => {
                    panic!("ineligible relay received client text frame: {text}");
                }
                Ok(Some(Ok(Message::Close(_))) | None) => break,
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(error))) => panic!("ineligible relay socket failed: {error}"),
            }
        }
        finish_on_close(socket).await;
    });
    let authenticated_server = tokio::spawn(ack_server(authenticated, true));

    let mut pool = RelayPool::spawn(configs, RelayPoolConfig::default()).unwrap();
    wait_connected(&mut pool, 2).await;
    let result = pool
        .publish_to_indices(event(), &HashSet::from([1]), 1)
        .await
        .unwrap();
    assert_eq!(result.accepted, 1);
    assert_eq!(result.attempted, 1);
    assert_eq!(result.outcomes[0].relay_index, 1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    for outcome in pool.shutdown().await {
        outcome.unwrap();
    }
    ineligible_server.await.unwrap();
    authenticated_server.await.unwrap();
}

async fn ack_server(listener: TcpListener, accepted: bool) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    let publish = next_json(&mut socket).await;
    socket
        .send(Message::Text(
            json!(["OK", publish[1]["id"], accepted, "policy"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    finish_on_close(socket).await;
}

#[tokio::test]
async fn deduplicates_events_and_identical_subscriptions() {
    let signed = event();
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let configs = vec![
        relay_config(first.local_addr().unwrap()),
        relay_config(second.local_addr().unwrap()),
    ];
    let first_server = tokio::spawn(subscription_server(first, signed.clone()));
    let second_server = tokio::spawn(subscription_server(second, signed));
    let mut pool = RelayPool::spawn(
        configs,
        RelayPoolConfig {
            dedup_capacity: 1,
            ..RelayPoolConfig::default()
        },
    )
    .unwrap();
    wait_connected(&mut pool, 2).await;
    let filters = vec![json!({"kinds":[1]})];
    assert!(
        pool.subscribe("shared".into(), filters.clone())
            .await
            .iter()
            .all(Result::is_ok)
    );
    assert!(pool.subscribe("shared".into(), filters).await.is_empty());

    let mut events = 0;
    let mut eose = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        while events + eose < 3 {
            match pool.next_notification().await.unwrap().notification {
                RelayNotification::Event { .. } => events += 1,
                RelayNotification::EndOfStoredEvents { .. } => eose += 1,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(events, 1);
    assert_eq!(eose, 2);
    for outcome in pool.shutdown().await {
        outcome.unwrap();
    }
    first_server.await.unwrap();
    second_server.await.unwrap();
}

async fn subscription_server(listener: TcpListener, event: SignedEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    assert_eq!(next_json(&mut socket).await[0], "REQ");
    socket
        .send(Message::Text(
            json!(["EVENT", "shared", event]).to_string().into(),
        ))
        .await
        .unwrap();
    socket
        .send(Message::Text(json!(["EOSE", "shared"]).to_string().into()))
        .await
        .unwrap();
    finish_on_close(socket).await;
}
