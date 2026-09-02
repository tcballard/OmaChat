use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    discovery::NIP65_RELAY_LIST_KIND,
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_discovers_seals_and_serves_nip65_relay_lists_offline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let discovery_relay = format!("ws://{}", listener.local_addr().unwrap());
    let participant_secret = [131; 32];
    let participant = xonly_public_key(&participant_secret).unwrap();
    let now = unix_now();
    let relay_list = UnsignedEvent::new(
        hex::encode(participant),
        now,
        NIP65_RELAY_LIST_KIND,
        vec![
            vec!["r".into(), "wss://read.example".into(), "read".into()],
            vec!["r".into(), "wss://write.example".into(), "write".into()],
            vec!["r".into(), "wss://both.example".into()],
        ],
        String::new(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&participant_secret, &[132; 32], &EventLimits::default())
    .unwrap();
    let relay = tokio::spawn(serve_relay_list(listener, relay_list.clone()));
    let state = tempdir().unwrap();
    let config = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        dm_relays: vec![discovery_relay],
        ..DaemonConfig::default()
    };
    let core = DaemonCore::open(state.path(), config.clone(), EventHub::default())
        .await
        .unwrap();

    let discovered = command(
        &core,
        Command::DiscoverNip65Relays {
            public_key: hex::encode(participant),
        },
    )
    .await;
    assert_eq!(discovered["public_key"], hex::encode(participant));
    assert_eq!(discovered["event_id"], relay_list.id);
    assert_eq!(discovered["cache_status"], "stored");
    assert_eq!(discovered["queried_relays"], 1);
    assert_eq!(discovered["completed_relays"], 1);
    assert_eq!(discovered["identity_verified_by_relay_list"], false);
    assert_eq!(
        discovered["relays"],
        json!([
            {"url": "wss://read.example/", "read": true, "write": false},
            {"url": "wss://write.example/", "read": false, "write": true},
            {"url": "wss://both.example/", "read": true, "write": true}
        ])
    );
    relay.await.unwrap();
    drop(core);

    let reopened = DaemonCore::open(state.path(), config, EventHub::default())
        .await
        .unwrap();
    let cached = command(
        &reopened,
        Command::ShowNip65Relays {
            public_key: hex::encode(participant),
        },
    )
    .await;
    assert_eq!(cached["cache_status"], "fresh");
    assert_eq!(cached["relays"], discovered["relays"]);
    assert_eq!(cached["identity_verified_by_relay_list"], false);

    let missing = command(
        &reopened,
        Command::ShowNip65Relays {
            public_key: hex::encode(xonly_public_key(&[133; 32]).unwrap()),
        },
    )
    .await;
    assert_eq!(missing["cache_status"], "missing");
    assert_eq!(missing["relays"], json!([]));
    assert_eq!(missing["identity_verified_by_relay_list"], false);
}

async fn command(core: &DaemonCore, command: Command) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "nip65-relays".into(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("NIP-65 IPC failed: {}", error.message),
    }
}

async fn serve_relay_list(listener: TcpListener, relay_list: SignedEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    let request = next_json(&mut socket).await;
    assert_eq!(request[0], "REQ");
    assert_eq!(request[2]["kinds"], json!([NIP65_RELAY_LIST_KIND]));
    assert_eq!(request[2]["authors"], json!([relay_list.pubkey]));
    let subscription_id = request[1].as_str().unwrap();
    socket
        .send(Message::Text(
            json!(["EVENT", subscription_id, relay_list])
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
