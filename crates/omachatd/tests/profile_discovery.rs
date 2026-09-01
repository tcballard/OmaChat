use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::{
    event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key},
    profile_metadata::PROFILE_METADATA_KIND,
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_discovers_and_seals_profile_without_claiming_handle_ownership() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}", listener.local_addr().unwrap());
    let participant_secret = [111; 32];
    let participant = xonly_public_key(&participant_secret).unwrap();
    let profile = UnsignedEvent::new(
        hex::encode(participant),
        unix_now(),
        PROFILE_METADATA_KIND,
        Vec::new(),
        json!({
            "name": "codex-tom",
            "display_name": "Codex",
            "about": "External Nostr agent"
        })
        .to_string(),
        &EventLimits::default(),
    )
    .unwrap()
    .sign_with_aux(&participant_secret, &[112; 32], &EventLimits::default())
    .unwrap();
    let relay = tokio::spawn(serve_profile(listener, profile));
    let state = tempdir().unwrap();
    let core = DaemonCore::open(
        state.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            dm_relays: vec![relay_url],
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let outcome = core
        .handle(Request {
            version: VERSION,
            id: "profile-discovery".into(),
            command: Command::DiscoverProfile {
                public_key: hex::encode(participant),
            },
        })
        .await;
    let ResponseOutcome::Ok { result } = outcome else {
        panic!("profile discovery failed");
    };
    assert_eq!(result["public_key"], hex::encode(participant));
    assert_eq!(result["status"], "stored");
    assert_eq!(result["nostr_name"], "codex-tom");
    assert_eq!(result["name_classification"], "handle-syntax-candidate");
    assert_eq!(result["display_name"], "Codex");
    assert_eq!(result["global_handle_verified"], false);
    relay.await.unwrap();
}

async fn serve_profile(listener: TcpListener, profile: SignedEvent) {
    let (stream, _) = listener.accept().await.unwrap();
    let mut socket = accept_async(stream).await.unwrap();
    socket
        .send(Message::Text(
            json!(["AUTH", "daemon-profile"]).to_string().into(),
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
    assert_eq!(request[2]["kinds"], json!([PROFILE_METADATA_KIND]));
    assert_eq!(request[2]["authors"], json!([profile.pubkey]));
    let subscription_id = request[1].as_str().unwrap();
    socket
        .send(Message::Text(
            json!(["EVENT", subscription_id, profile])
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
