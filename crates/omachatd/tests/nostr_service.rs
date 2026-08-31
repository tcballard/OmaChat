use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    relay::RelayNotification,
};
use omachatd::NostrService;
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt, net::TcpListener};
use tokio_tungstenite::{accept_async, tungstenite::Message};

fn signed_event(secret: [u8; 32], auxiliary: [u8; 32], content: &str) -> SignedEvent {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    UnsignedEvent::new(
        hex::encode(xonly_public_key(&secret).unwrap()),
        now,
        1,
        vec![],
        content.into(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&secret, &auxiliary, &EventLimits::default())
    .unwrap()
}

#[tokio::test]
async fn daemon_service_publishes_to_and_shuts_down_hermetic_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) => {
                    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if value[0] == "EVENT" {
                        socket
                            .send(Message::Text(
                                json!(["OK", value[1]["id"], true, "stored"])
                                    .to_string()
                                    .into(),
                            ))
                            .await
                            .unwrap();
                    }
                }
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
                Message::Close(_) => break,
                _ => {}
            }
        }
    });
    let (inbound, mut notifications) = tokio::sync::mpsc::channel(8);
    let service = NostrService::spawn(&[url], inbound).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !matches!(
            notifications.recv().await.unwrap().notification,
            RelayNotification::Connected
        ) {}
    })
    .await
    .unwrap();
    let event = signed_event([3; 32], [4; 32], "hello");
    assert_eq!(service.handle().publish(event).await.unwrap().accepted, 1);
    service.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn quiesce_cancels_active_publish_and_discards_queued_publish() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let (first_seen_sender, first_seen_receiver) = tokio::sync::oneshot::channel();
    let quiesced = Arc::new(AtomicBool::new(false));
    let server_quiesced = Arc::clone(&quiesced);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let mut event_ids = Vec::new();
        let mut post_quiesce_events = 0;
        let mut first_seen_sender = Some(first_seen_sender);
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) => {
                    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if value[0] == "EVENT" {
                        if server_quiesced.load(Ordering::Acquire) {
                            post_quiesce_events += 1;
                        }
                        event_ids.push(value[1]["id"].as_str().unwrap().to_owned());
                        if let Some(sender) = first_seen_sender.take() {
                            sender.send(()).unwrap();
                        }
                        // Deliberately withhold the acknowledgement so the
                        // first publish remains active while another queues.
                    }
                }
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
                Message::Close(_) => break,
                _ => {}
            }
        }
        (event_ids, post_quiesce_events)
    });
    let (inbound, mut notifications) = tokio::sync::mpsc::channel(8);
    let service = NostrService::spawn(&[url], inbound).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !matches!(
            notifications.recv().await.unwrap().notification,
            RelayNotification::Connected
        ) {}
    })
    .await
    .unwrap();

    let handle = service.handle();
    let active_handle = handle.clone();
    let active = tokio::spawn(async move {
        active_handle
            .publish(signed_event([3; 32], [4; 32], "active"))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), first_seen_receiver)
        .await
        .expect("relay receives active publish")
        .expect("relay signal");

    let mut queued = Box::pin(handle.publish(signed_event([5; 32], [6; 32], "queued")));
    assert!(
        futures_util::poll!(&mut queued).is_pending(),
        "second publish is queued behind the unacknowledged first publish"
    );

    tokio::time::timeout(std::time::Duration::from_secs(2), handle.quiesce())
        .await
        .expect("quiesce cancels relay work without waiting for publish timeout");
    quiesced.store(true, Ordering::Release);
    assert!(active.await.expect("active publish task").is_err());
    assert!(queued.await.is_err());
    assert!(
        handle
            .publish(signed_event([7; 32], [8; 32], "after stop"))
            .await
            .is_err(),
        "new work is rejected immediately after quiesce begins"
    );
    tokio::time::sleep(Duration::from_millis(25)).await;

    service.shutdown().await.unwrap();
    let (event_ids, post_quiesce_events) = server.await.unwrap();
    assert_eq!(event_ids.len(), 1, "queued publish reached the relay");
    assert_eq!(
        post_quiesce_events, 0,
        "a relay actor published after quiesce returned"
    );
}

#[tokio::test]
async fn quiesce_aborts_and_awaits_a_relay_actor_wedged_in_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
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

        // Keep the handshake permanently in flight. EOF is only observable
        // once the relay task has been aborted and its socket has been dropped.
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    });
    let (inbound, _notifications) = tokio::sync::mpsc::channel(8);
    let service = NostrService::spawn(&[url], inbound).unwrap();
    tokio::time::timeout(Duration::from_secs(1), handshake_receiver)
        .await
        .expect("relay actor starts WebSocket handshake")
        .expect("handshake signal");

    tokio::time::timeout(Duration::from_secs(5), service.handle().quiesce())
        .await
        .expect("quiesce owns the relay shutdown deadline");
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("quiesce waits until the relay actor drops its socket")
        .expect("handshake server task");
    assert!(
        service.shutdown().await.is_err(),
        "forced relay cancellation remains observable to the owner"
    );
}
