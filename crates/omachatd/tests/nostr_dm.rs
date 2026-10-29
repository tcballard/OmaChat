//! Two daemons exchange a NIP-17 gift wrap through a loopback relay, and a
//! NIP-05 name resolves to a contact.

use futures_util::{SinkExt, StreamExt};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::tempdir;
use tokio::{
    net::TcpListener,
    time::{sleep, timeout},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[tokio::test]
async fn gift_wrap_round_trip_and_nip05_contact() {
    let relay = TestRelay::start().await;
    let alice_dir = tempdir().unwrap();
    let bob_dir = tempdir().unwrap();
    let url = format!("ws://{}", relay.address);
    let alice = open(alice_dir.path(), &url).await;
    let bob = open(bob_dir.path(), &url).await;
    let alice_key = command(&alice, Command::ChatPrepare).await;
    let bob_key = command(&bob, Command::ChatPrepare).await;
    let bob_npub = bob_key["npub"].as_str().unwrap().to_owned();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http = listener.local_addr().unwrap();
    let document = json!({"names": {"carol": alice_key["pubkey"].as_str().unwrap()}}).to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 2048];
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = stream.read(&mut buffer).await;
        let message = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{document}",
            document.len()
        );
        let _ = stream.write_all(message.as_bytes()).await;
    });
    bob.set_loopback_nip05_for_tests(format!("http://{http}"))
        .await
        .unwrap();
    let contact = command(
        &bob,
        Command::ContactsAdd {
            peer: "carol@example.com".into(),
        },
    )
    .await;
    assert_eq!(contact["contact"]["pubkey"], alice_key["pubkey"]);
    assert_eq!(contact["contact"]["nip05"], "carol@example.com");

    command(
        &alice,
        Command::ContactsAdd {
            peer: bob_npub.clone(),
        },
    )
    .await;
    command(
        &alice,
        Command::Send {
            peer: bob_npub,
            text: "hello from alice".into(),
        },
    )
    .await;

    let found = timeout(Duration::from_secs(8), async {
        loop {
            let messages = command(&bob, Command::Messages).await;
            if messages["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["text"] == "hello from alice")
            {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(found.is_ok(), "bob did not receive the gift wrap");
    let sent = command(&alice, Command::Messages).await;
    assert_eq!(sent["messages"][0]["delivery"], "stored");
    assert_eq!(sent["messages"][0]["outgoing"], true);
}

async fn open(path: &std::path::Path, relay: &str) -> DaemonCore {
    DaemonCore::open(
        path,
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            dm_relays: vec![relay.to_owned()],
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap()
}

async fn command(core: &DaemonCore, command: Command) -> Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "dm-test".into(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("{}", error.message),
    }
}

struct TestRelay {
    address: SocketAddr,
}

impl TestRelay {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(RelayState::default()));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move { serve_relay(stream, state).await });
            }
        });
        Self { address }
    }
}

async fn serve_relay(stream: tokio::net::TcpStream, state: Arc<Mutex<RelayState>>) {
    let Ok(socket) = accept_async(stream).await else {
        return;
    };
    let (mut write, mut read) = socket.split();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<String>();
    loop {
        tokio::select! {
            incoming = read.next() => {
                let Some(Ok(message)) = incoming else { break };
                match message {
                    Message::Text(text) => handle_frame(text.as_ref(), &state, &sender),
                    Message::Ping(payload) => {
                        if write.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            outgoing = receiver.recv() => {
                let Some(frame) = outgoing else { break };
                if write.send(Message::Text(frame.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

fn handle_frame(
    text: &str,
    state: &Mutex<RelayState>,
    sender: &tokio::sync::mpsc::UnboundedSender<String>,
) {
    let Ok(frame) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let Some(kind) = frame[0].as_str() else {
        return;
    };
    if kind == "EVENT" {
        let event = frame[1].clone();
        let id = event["id"].as_str().unwrap_or_default();
        let mut state = state.lock().unwrap();
        state.events.push(event.clone());
        for subscriber in &state.subscribers {
            if matches_filter(&subscriber.filter, &event) {
                let _ = subscriber
                    .sender
                    .send(json!(["EVENT", subscriber.id, event]).to_string());
            }
        }
        let _ = sender.send(json!(["OK", id, true, ""]).to_string());
    } else if kind == "REQ" {
        let id = frame[1].as_str().unwrap_or_default().to_owned();
        let filter = frame.get(2).cloned().unwrap_or_else(|| json!({}));
        let mut state = state.lock().unwrap();
        let replay = state
            .events
            .iter()
            .filter(|event| matches_filter(&filter, event))
            .cloned()
            .collect::<Vec<_>>();
        state.subscribers.push(Subscriber {
            id: id.clone(),
            filter,
            sender: sender.clone(),
        });
        drop(state);
        for event in replay {
            let _ = sender.send(json!(["EVENT", id, event]).to_string());
        }
        let _ = sender.send(json!(["EOSE", id]).to_string());
    }
}

#[derive(Default)]
struct RelayState {
    events: Vec<Value>,
    subscribers: Vec<Subscriber>,
}

struct Subscriber {
    id: String,
    filter: Value,
    sender: tokio::sync::mpsc::UnboundedSender<String>,
}

fn matches_filter(filter: &Value, event: &Value) -> bool {
    if let Some(kinds) = filter["kinds"].as_array()
        && !kinds.iter().any(|kind| kind == &event["kind"])
    {
        return false;
    }
    if let Some(authors) = filter["#p"].as_array() {
        let tags = event["tags"].as_array().cloned().unwrap_or_default();
        let tagged = tags.iter().any(|tag| {
            tag[0].as_str() == Some("p") && authors.iter().any(|author| author == &tag[1])
        });
        if !tagged {
            return false;
        }
    }
    true
}
