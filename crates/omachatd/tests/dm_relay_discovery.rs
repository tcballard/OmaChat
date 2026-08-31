use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    discovery::NIP17_DM_RELAY_LIST_KIND,
    dm_relay_cache::CacheMutation,
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_discovers_and_seals_recipient_metadata_across_restart() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let recipient_secret = [81; 32];
    let recipient = xonly_public_key(&recipient_secret).unwrap();
    let now = unix_now();
    let metadata = UnsignedEvent::new(
        hex::encode(recipient),
        now,
        NIP17_DM_RELAY_LIST_KIND,
        vec![vec!["relay".into(), "wss://recipient.example".into()]],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&recipient_secret, &[82; 32], &EventLimits::default())
    .unwrap();
    let relay = tokio::spawn(serve_discovery(listener, metadata.clone()));
    let state = tempdir().unwrap();
    let config = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        dm_relays: vec![relay_url],
        ..DaemonConfig::default()
    };
    let core = DaemonCore::open(state.path(), config.clone(), EventHub::default())
        .await
        .unwrap();
    let response = core
        .handle(Request {
            version: VERSION,
            id: "discover-dm-relays".into(),
            command: Command::DiscoverDmRelays {
                public_key: hex::encode(recipient),
            },
        })
        .await;
    let ResponseOutcome::Ok { result } = response else {
        panic!("discovery IPC failed");
    };
    assert_eq!(result["status"], "stored");
    relay.await.unwrap();
    drop(core);

    let reopened = DaemonCore::open(state.path(), config, EventHub::default())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .remember_dm_relay_list(&metadata, &recipient, now)
            .unwrap(),
        CacheMutation::Unchanged
    );
}

async fn serve_discovery(listener: TcpListener, metadata: SignedEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(
            json!(["AUTH", "daemon-discovery"]).to_string().into(),
        ))
        .await
        .unwrap();
    let authentication = next_json(&mut socket).await;
    assert_eq!(authentication[0], "AUTH");
    let auth_event: SignedEvent = serde_json::from_value(authentication[1].clone()).unwrap();
    auth_event
        .verify(unix_now() + 1, &EventLimits::default())
        .unwrap();
    socket
        .send(Message::Text(
            json!(["OK", auth_event.id, true, "authenticated"])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
    assert_eq!(request[2]["kinds"], json!([NIP17_DM_RELAY_LIST_KIND]));
    assert_eq!(request[2]["authors"], json!([metadata.pubkey]));
    let subscription_id = request[1].as_str().unwrap();
    socket
        .send(Message::Text(
            json!(["EVENT", subscription_id, metadata])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    socket
        .send(Message::Text(
            json!(["EOSE", subscription_id]).to_string().into(),
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
