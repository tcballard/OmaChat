use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    event::{EventLimits, UnsignedEvent, xonly_public_key},
    relay::RelayNotification,
};
use omachatd::NostrService;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

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
    let secret = [3; 32];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = UnsignedEvent::new(
        hex::encode(xonly_public_key(&secret).unwrap()),
        now,
        1,
        vec![],
        "hello".into(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&secret, &[4; 32], &EventLimits::default())
    .unwrap();
    assert_eq!(service.handle().publish(event).await.unwrap().accepted, 1);
    service.shutdown().await.unwrap();
    server.await.unwrap();
}
