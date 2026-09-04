//! End-to-end NIP-29 room flow against a hermetic relay that serves NIP-11
//! and the websocket protocol on one port.

use futures_util::{SinkExt, StreamExt};
use omachat_nostr::event::{EventLimits, SignedEvent, UnsignedEvent, xonly_public_key};
use omachat_proto::ipc::{Command, Event, Request, ResponseOutcome, Topic, VERSION};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, RequestHandler, RoomsConfig, StorageProviderConfig,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

const RELAY_SECRET: [u8; 32] = [5; 32];
const FORGER_SECRET: [u8; 32] = [6; 32];

fn limits() -> EventLimits {
    EventLimits::default()
}

fn pubkey(secret: &[u8; 32]) -> String {
    hex::encode(xonly_public_key(secret).expect("key"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn signed(secret: &[u8; 32], kind: u32, tags: Vec<Vec<String>>, content: &str) -> SignedEvent {
    UnsignedEvent::new(
        pubkey(secret),
        now(),
        kind,
        tags,
        content.to_owned(),
        &limits(),
    )
    .expect("event")
    .sign_with_aux(secret, &[3; 32], &limits())
    .expect("signed")
}

fn tag(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// What the fake relay saw and how it should behave.
#[derive(Default)]
struct RelayLog {
    requests: Mutex<Vec<Value>>,
    events: Mutex<Vec<SignedEvent>>,
    closes: Mutex<Vec<String>>,
    /// Events pushed on the room subscription after the first REQ.
    push_on_req: Mutex<Vec<SignedEvent>>,
    http_hits: AtomicUsize,
}

/// Serve NIP-11 for plain HTTP requests and the Nostr protocol for websocket
/// upgrades on one listener, so the daemon dials a single URL.
async fn fake_relay(listener: TcpListener, information: Value, log: Arc<RelayLog>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let log = Arc::clone(&log);
        let information = information.clone();
        tokio::spawn(async move {
            let mut head = vec![0_u8; 4096];
            let seen = loop {
                let Ok(read) = stream.peek(&mut head).await else {
                    return;
                };
                if read == 0 || head[..read].windows(4).any(|window| window == b"\r\n\r\n") {
                    break read;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            let request = String::from_utf8_lossy(&head[..seen]).to_ascii_lowercase();
            if request.contains("upgrade: websocket") {
                serve_nostr(stream, log).await;
            } else {
                serve_nip11(stream, &information, &log).await;
            }
        });
    }
}

async fn serve_nip11(mut stream: TcpStream, information: &Value, log: &RelayLog) {
    let mut sink = vec![0_u8; 4096];
    let _ = stream.read(&mut sink).await;
    log.http_hits.fetch_add(1, Ordering::SeqCst);
    let body = information.to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn serve_nostr(stream: TcpStream, log: Arc<RelayLog>) {
    let Ok(mut socket) = accept_async(stream).await else {
        return;
    };
    while let Some(Ok(message)) = socket.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Ping(payload) => {
                let _ = socket.send(Message::Pong(payload)).await;
                continue;
            }
            Message::Close(_) => break,
            _ => continue,
        };
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match frame[0].as_str() {
            Some("REQ") => {
                let subscription = frame[1].as_str().unwrap_or_default().to_owned();
                log.requests.lock().expect("lock").push(frame.clone());
                let pushes = std::mem::take(&mut *log.push_on_req.lock().expect("lock"));
                for event in pushes {
                    let _ = socket
                        .send(Message::Text(
                            json!(["EVENT", subscription, event]).to_string().into(),
                        ))
                        .await;
                }
                let _ = socket
                    .send(Message::Text(
                        json!(["EOSE", subscription]).to_string().into(),
                    ))
                    .await;
            }
            Some("CLOSE") => {
                log.closes
                    .lock()
                    .expect("lock")
                    .push(frame[1].as_str().unwrap_or_default().to_owned());
            }
            Some("EVENT") => {
                let event: SignedEvent = serde_json::from_value(frame[1].clone()).expect("event");
                let id = event.id.clone();
                log.events.lock().expect("lock").push(event);
                let _ = socket
                    .send(Message::Text(
                        json!(["OK", id, true, ""]).to_string().into(),
                    ))
                    .await;
            }
            _ => {}
        }
    }
}

fn config(url: &str) -> DaemonConfig {
    config_with_relays(vec![url.to_owned()])
}

fn config_with_relays(relays: Vec<String>) -> DaemonConfig {
    DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        rooms: Some(RoomsConfig {
            relays,
            anchor_provider: Default::default(),
            anchor_directory: None,
        }),
        ..DaemonConfig::default()
    }
}

async fn request(core: &DaemonCore, command: Command) -> Result<Value, String> {
    match core
        .handle(Request {
            version: VERSION,
            id: "test".into(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => Ok(result),
        ResponseOutcome::Error { error } => Err(format!("{:?}: {}", error.code, error.message)),
    }
}

async fn next_event(
    events: &mut mpsc::Receiver<Event>,
    topic: Topic,
    matches: impl Fn(&Value) -> bool,
) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.expect("event stream open");
            if event.topic == topic && matches(&event.payload) {
                return event.payload;
            }
        }
    })
    .await
    .expect("expected IPC event in time")
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition in time");
}

async fn wait_for_identity(core: &DaemonCore) -> String {
    let mut relay_pubkey = None;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(value) = request(core, Command::ListRooms).await
                && let Some(key) = value["relays"][0]["relay_pubkey"].as_str()
            {
                relay_pubkey = Some(key.to_owned());
                if value["relays"][0]["status"] == "connected" {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("relay identity bound in time");
    relay_pubkey.expect("relay pubkey")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rooms_join_receive_send_persist_and_restore() {
    let temporary = tempdir().expect("tempdir");
    let state = temporary.path().join("state");
    let anchors = temporary.path().join("anchors");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let url = format!("ws://{address}");
    let relay = pubkey(&RELAY_SECRET);
    let log = Arc::new(RelayLog::default());
    // Relay-authored state, a room message, and a forged metadata event
    // signed by another key: the forgery is well-formed but not the relay's.
    *log.push_on_req.lock().expect("lock") = vec![
        signed(
            &RELAY_SECRET,
            39000,
            vec![
                tag(&["d", "omarchy"]),
                tag(&["name", "Omarchy"]),
                tag(&["public"]),
            ],
            "",
        ),
        signed(
            &FORGER_SECRET,
            39000,
            vec![
                tag(&["d", "omarchy"]),
                tag(&["name", "Forged"]),
                tag(&["private"]),
            ],
            "",
        ),
        signed(
            &FORGER_SECRET,
            9,
            vec![tag(&["h", "omarchy"])],
            "hello rooms",
        ),
    ];
    tokio::spawn(fake_relay(
        listener,
        json!({"self": relay, "pubkey": relay, "supported_nips": [1, 29], "software": "fake"}),
        Arc::clone(&log),
    ));

    let events = EventHub::default();
    let mut stream = events.subscribe();
    let core = DaemonCore::open(&state, config(&url), events.clone())
        .await
        .expect("core");
    let service = core
        .start_rooms(&state, anchors.clone())
        .expect("rooms start")
        .expect("rooms configured");
    let bound = wait_for_identity(&core).await;
    assert_eq!(bound, relay);
    assert_eq!(log.http_hits.load(Ordering::SeqCst), 1);

    let joined = request(
        &core,
        Command::JoinRoom {
            relay: url.clone(),
            group_id: "omarchy".into(),
            invite_code: None,
        },
    )
    .await
    .expect("join");
    let conversation = format!("room:{relay}:omarchy");
    assert_eq!(joined["conversation"], conversation);
    assert_eq!(joined["request_delivery"], "accepted");

    // The relay saw a subscription whose state kinds are pinned to its key,
    // and a kind 9021 join request signed by the daemon's device identity.
    wait_until(|| !log.events.lock().expect("lock").is_empty()).await;
    let requests = log.requests.lock().expect("lock").clone();
    assert!(requests.iter().all(|frame| frame[0] == "REQ"));
    // Events and relay state are separate subscriptions; relay29 refuses a
    // REQ that mixes metadata kinds with others.
    let state_filter = requests
        .iter()
        .flat_map(|frame| frame.as_array().expect("frame").iter().skip(2))
        .find(|filter| filter["authors"].is_array())
        .cloned()
        .expect("state filter");
    assert!(
        requests
            .iter()
            .flat_map(|frame| frame.as_array().expect("frame").iter().skip(2))
            .all(|filter| filter["authors"].is_array() || filter["#h"].is_array())
    );
    assert_eq!(state_filter["authors"], json!([relay]));
    assert_eq!(state_filter["#d"], json!(["omarchy"]));
    let join_request = log.events.lock().expect("lock")[0].clone();
    assert_eq!(join_request.kind, 9021);
    let status = request(&core, Command::Status).await.expect("status");
    assert_eq!(status["nostr_public_key"], join_request.pubkey);
    assert_eq!(status["room_relay_count"], 1);

    // Only the relay-signed metadata reaches state; the forgery is ignored.
    let message = next_event(&mut stream, Topic::Messages, |payload| {
        payload["text"] == "hello rooms"
    })
    .await;
    assert_eq!(message["conversation"], conversation);
    assert_eq!(message["sender"], pubkey(&FORGER_SECRET));
    let listed = request(&core, Command::ListRooms).await.expect("list");
    let room = &listed["relays"][0]["rooms"][0];
    assert_eq!(room["name"], "Omarchy");
    assert_eq!(room["private"], false);
    assert_eq!(room["subscribed"], true);
    assert_eq!(listed["relays"][0]["identity_source"], "self");

    // Sending into the room publishes a signed kind 9 through that relay.
    let sent = request(
        &core,
        Command::Send {
            conversation: conversation.clone(),
            text: "hi from omachat".into(),
        },
    )
    .await
    .expect("send");
    assert_eq!(sent["delivery"], "stored");
    wait_until(|| log.events.lock().expect("lock").len() >= 2).await;
    let posted = log.events.lock().expect("lock")[1].clone();
    assert_eq!(posted.kind, 9);
    assert_eq!(posted.content, "hi from omachat");
    assert_eq!(posted.pubkey, join_request.pubkey);
    assert!(posted.tags.contains(&tag(&["h", "omarchy"])));

    // A room on an unconfigured relay identity is refused, not guessed.
    assert!(
        request(
            &core,
            Command::Send {
                conversation: format!("room:{}:omarchy", pubkey(&FORGER_SECRET)),
                text: "nope".into(),
            },
        )
        .await
        .is_err()
    );

    service.shutdown().await;
    core.prepare_for_shutdown().await;
    drop(core);

    // Restart on the same state: the joined room, the verified identity,
    // and the reduced metadata come back from sealed state without the
    // relay replaying anything.
    let events = EventHub::default();
    let core = DaemonCore::open(&state, config(&url), events.clone())
        .await
        .expect("core again");
    let service = core
        .start_rooms(&state, anchors.clone())
        .expect("rooms restart")
        .expect("rooms configured");
    assert_eq!(wait_for_identity(&core).await, relay);
    wait_until(|| log.requests.lock().expect("lock").len() >= 2).await;
    let listed = request(&core, Command::ListRooms)
        .await
        .expect("list again");
    let relay_view = &listed["relays"][0];
    assert!(relay_view["state_generation"].as_u64().expect("generation") >= 1);
    assert_eq!(relay_view["rooms"][0]["group_id"], "omarchy");
    assert_eq!(relay_view["rooms"][0]["name"], "Omarchy");

    let left = request(
        &core,
        Command::LeaveRoom {
            relay: url.clone(),
            group_id: "omarchy".into(),
        },
    )
    .await
    .expect("leave");
    assert_eq!(left["left"], "omarchy");
    wait_until(|| !log.closes.lock().expect("lock").is_empty()).await;
    let listed = request(&core, Command::ListRooms)
        .await
        .expect("list after leave");
    assert!(
        listed["relays"][0]["rooms"]
            .as_array()
            .expect("rooms")
            .is_empty()
    );
    assert!(
        request(
            &core,
            Command::Send {
                conversation,
                text: "after leaving".into(),
            },
        )
        .await
        .is_err()
    );
    service.shutdown().await;
    core.prepare_for_shutdown().await;
    assert!(Path::new(&anchors).is_dir());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_without_self_key_stays_unavailable_even_when_it_advertises_nip29() {
    let temporary = tempdir().expect("tempdir");
    let state = temporary.path().join("state");
    let anchors = temporary.path().join("anchors");
    let relay = pubkey(&RELAY_SECRET);

    // No NIP-29 in supported_nips: no identity, rooms stay unavailable.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}", listener.local_addr().expect("address"));
    tokio::spawn(fake_relay(
        listener,
        json!({"pubkey": relay, "supported_nips": [1, 11]}),
        Arc::new(RelayLog::default()),
    ));
    let core = DaemonCore::open(&state, config(&url), EventHub::default())
        .await
        .expect("core");
    let service = core
        .start_rooms(&state, anchors.clone())
        .expect("rooms start")
        .expect("configured");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let listed = request(&core, Command::ListRooms).await.expect("list");
            if listed["relays"][0]["status"] == "no-relay-identity" {
                assert!(listed["relays"][0]["relay_pubkey"].is_null());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("status in time");
    let refused = request(
        &core,
        Command::JoinRoom {
            relay: url.clone(),
            group_id: "omarchy".into(),
            invite_code: None,
        },
    )
    .await
    .expect_err("join must be refused without a relay identity");
    assert!(refused.contains("Unavailable"), "{refused}");
    service.shutdown().await;
    drop(core);

    // Advertising NIP-29 does not turn the administrative contact `pubkey`
    // into the relay signing identity required by NIP-29.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("ws://{}", listener.local_addr().expect("address"));
    tokio::spawn(fake_relay(
        listener,
        json!({"pubkey": relay, "supported_nips": [1, 11, 29]}),
        Arc::new(RelayLog::default()),
    ));
    let state = temporary.path().join("state-2");
    let core = DaemonCore::open(&state, config(&url), EventHub::default())
        .await
        .expect("core");
    let service = core
        .start_rooms(&state, anchors)
        .expect("rooms start")
        .expect("configured");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let listed = request(&core, Command::ListRooms).await.expect("list");
            if listed["relays"][0]["status"] == "no-relay-identity" {
                assert!(listed["relays"][0]["relay_pubkey"].is_null());
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("status in time");
    let refused = request(
        &core,
        Command::JoinRoom {
            relay: url,
            group_id: "omarchy".into(),
            invite_code: None,
        },
    )
    .await
    .expect_err("join must be refused without NIP-11 self");
    assert!(refused.contains("Unavailable"), "{refused}");
    service.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_urls_for_one_relay_identity_stop_both_actors() {
    let temporary = tempdir().expect("tempdir");
    let state = temporary.path().join("state");
    let anchors = temporary.path().join("anchors");
    let relay = pubkey(&RELAY_SECRET);
    let mut urls = Vec::new();

    for _ in 0..2 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        urls.push(format!("ws://{}", listener.local_addr().expect("address")));
        tokio::spawn(fake_relay(
            listener,
            json!({"self": relay, "supported_nips": [1, 11, 29]}),
            Arc::new(RelayLog::default()),
        ));
    }

    let core = DaemonCore::open(
        &state,
        config_with_relays(urls.clone()),
        EventHub::default(),
    )
    .await
    .expect("core");
    let service = core
        .start_rooms(&state, anchors)
        .expect("rooms start")
        .expect("configured");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let listed = request(&core, Command::ListRooms).await.expect("list");
            let relays = listed["relays"].as_array().expect("relays");
            if relays
                .iter()
                .all(|entry| entry["status"] == "identity-conflict")
            {
                for entry in relays {
                    assert_eq!(entry["relay_pubkey"], relay);
                    assert_eq!(entry["detail"]["relay_pubkey"], relay);
                    assert_eq!(
                        entry["detail"]["configured_urls"],
                        json!(urls.iter().collect::<BTreeSet<_>>())
                    );
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("duplicate identity refused in time");

    for url in urls {
        let refused = request(
            &core,
            Command::JoinRoom {
                relay: url,
                group_id: "omarchy".into(),
                invite_code: None,
            },
        )
        .await
        .expect_err("duplicate relay identity must stay unavailable");
        assert!(refused.contains("Unavailable"), "{refused}");
    }

    service.shutdown().await;
}
