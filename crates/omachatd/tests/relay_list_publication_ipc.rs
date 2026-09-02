use futures_util::{SinkExt, StreamExt};
use omachat_proto::ipc::{Command, ErrorCode, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use tempfile::tempdir;
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::{Duration, timeout},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn configured_daemon(relay_url: &str) -> DaemonConfig {
    let mut config = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        ..DaemonConfig::default()
    };
    config.relay_list_publication = Some(
        serde_json::from_value(json!({
            "required_acknowledgements": 1,
            "relays": [{
                "url": relay_url,
                "read": true,
                "write": true
            }]
        }))
        .expect("valid relay-list publication config"),
    );
    config
}

async fn dispatch(core: &DaemonCore, command: Command) -> ResponseOutcome {
    core.handle(Request {
        version: VERSION,
        id: format!("request-{}", REQUEST_ID.fetch_add(1, Ordering::Relaxed)),
        command,
    })
    .await
}

async fn accepting_relay() -> (String, oneshot::Receiver<Value>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback relay");
    let relay_url = format!("ws://{}", listener.local_addr().expect("relay address"));
    let (event_sender, event_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept publisher");
        let mut socket = accept_async(stream).await.expect("WebSocket handshake");
        let mut event_sender = Some(event_sender);
        while let Some(message) = socket.next().await {
            let message = message.expect("relay message");
            let Message::Text(text) = message else {
                if matches!(message, Message::Close(_)) {
                    break;
                }
                continue;
            };
            let frame: Value = serde_json::from_str(text.as_str()).expect("Nostr frame");
            if frame.get(0).and_then(Value::as_str) != Some("EVENT") {
                continue;
            }
            let event = frame.get(1).cloned().expect("published event");
            let event_id = event
                .get("id")
                .and_then(Value::as_str)
                .expect("event ID")
                .to_owned();
            socket
                .send(Message::Text(
                    json!(["OK", event_id, true, "accepted"]).to_string().into(),
                ))
                .await
                .expect("relay acknowledgement");
            event_sender
                .take()
                .expect("one publication")
                .send(event)
                .expect("capture event");
        }
    });
    (relay_url, event_receiver, task)
}

#[tokio::test]
async fn publication_is_truthfully_unavailable_without_explicit_config() {
    let temporary = tempdir().expect("temporary directory");
    let core = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("open daemon");

    let ResponseOutcome::Error { error } = dispatch(&core, Command::PublishNip65Relays).await
    else {
        panic!("unconfigured publication must fail");
    };
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(
        error.message,
        "NIP-65 relay-list publication is not configured"
    );
    core.prepare_for_shutdown().await;
}

#[tokio::test]
async fn ipc_publishes_the_device_authored_configured_relay_list() {
    let (relay_url, captured_event, relay_task) = accepting_relay().await;
    let temporary = tempdir().expect("temporary directory");
    let core = DaemonCore::open(
        temporary.path(),
        configured_daemon(&relay_url),
        EventHub::default(),
    )
    .await
    .expect("open configured daemon");

    let ResponseOutcome::Ok { result } = dispatch(&core, Command::PublishNip65Relays).await else {
        panic!("configured publication must succeed");
    };
    assert_eq!(result["publication_status"], "complete");
    assert_eq!(result["publication_source"], "new");
    assert_eq!(result["required_acknowledgements"], 1);
    let canonical_relay_url = format!("{relay_url}/");
    assert_eq!(result["attempted_relays"], json!([canonical_relay_url]));
    assert_eq!(result["acknowledged_relays"], json!([canonical_relay_url]));
    assert_eq!(result["rejected_relays"], json!([]));
    assert_eq!(result["failed_relays"], json!([]));
    assert_eq!(result["identity_verified_by_relay_list"], false);

    let event = timeout(Duration::from_secs(1), captured_event)
        .await
        .expect("publication arrives")
        .expect("relay captures publication");
    assert_eq!(event["kind"], 10_002);
    assert_eq!(event["id"], result["event_id"]);
    assert_eq!(event["pubkey"], result["public_key"]);

    core.prepare_for_shutdown().await;
    timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("relay task joins")
        .expect("relay task completes");
}
