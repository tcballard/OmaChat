use futures_util::{SinkExt, StreamExt};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::{
    net::TcpListener,
    task::JoinHandle,
    time::{Duration, timeout},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

fn daemon_config(relay_url: Option<&str>) -> DaemonConfig {
    let mut config = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        ..DaemonConfig::default()
    };
    config.relay_list_publication = relay_url.map(|relay_url| {
        serde_json::from_value(json!({
            "required_acknowledgements": 1,
            "relays": [{
                "url": relay_url,
                "read": true,
                "write": true
            }]
        }))
        .expect("valid relay-list publication config")
    });
    config
}

async fn dispatch(core: &DaemonCore, command: Command, id: &str) -> ResponseOutcome {
    core.handle(Request {
        version: VERSION,
        id: id.into(),
        command,
    })
    .await
}

async fn status(core: &DaemonCore, id: &str) -> Value {
    let ResponseOutcome::Ok { result } = dispatch(core, Command::Status, id).await else {
        panic!("status command must succeed");
    };
    result
}

async fn rejecting_relay() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback relay");
    let relay_url = format!("ws://{}", listener.local_addr().expect("relay address"));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept publisher");
        let mut socket = accept_async(stream).await.expect("WebSocket handshake");
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
            let event_id = frame
                .get(1)
                .and_then(|event| event.get("id"))
                .and_then(Value::as_str)
                .expect("event ID");
            socket
                .send(Message::Text(
                    json!(["OK", event_id, false, "rejected for test"])
                        .to_string()
                        .into(),
                ))
                .await
                .expect("relay rejection");
        }
    });
    (relay_url, task)
}

#[tokio::test]
async fn status_distinguishes_disabled_and_ready_publication() {
    let temporary = tempdir().expect("temporary directory");
    let disabled = DaemonCore::open(
        temporary.path().join("disabled"),
        daemon_config(None),
        EventHub::default(),
    )
    .await
    .expect("open disabled daemon");
    let disabled_status = status(&disabled, "disabled").await;
    assert_eq!(disabled_status["relay_list_publication_state"], "disabled");
    assert_eq!(
        disabled_status["relay_list_publication_acknowledged_relays"],
        0
    );
    assert_eq!(
        disabled_status["relay_list_publication_required_acknowledgements"],
        0
    );
    disabled.prepare_for_shutdown().await;

    let ready = DaemonCore::open(
        temporary.path().join("ready"),
        daemon_config(Some("ws://127.0.0.1:19500")),
        EventHub::default(),
    )
    .await
    .expect("open ready daemon");
    let ready_status = status(&ready, "ready").await;
    assert_eq!(ready_status["relay_list_publication_state"], "ready");
    assert_eq!(
        ready_status["relay_list_publication_acknowledged_relays"],
        0
    );
    assert_eq!(
        ready_status["relay_list_publication_required_acknowledgements"],
        1
    );
    ready.prepare_for_shutdown().await;
}

#[tokio::test]
async fn sealed_intent_reports_pending_and_fails_closed_across_policy_changes() {
    let (relay_url, relay_task) = rejecting_relay().await;
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let core = DaemonCore::open(&state, daemon_config(Some(&relay_url)), EventHub::default())
        .await
        .expect("open configured daemon");
    let ResponseOutcome::Ok { result } =
        dispatch(&core, Command::PublishNip65Relays, "publish").await
    else {
        panic!("relay rejection produces a durable pending result");
    };
    assert_eq!(result["publication_status"], "pending");
    let pending = status(&core, "pending").await;
    assert_eq!(pending["relay_list_publication_state"], "pending");
    assert_eq!(pending["relay_list_publication_acknowledged_relays"], 0);
    assert_eq!(
        pending["relay_list_publication_required_acknowledgements"],
        1
    );
    core.prepare_for_shutdown().await;
    timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("relay task joins")
        .expect("relay task completes");

    let changed = DaemonCore::open(
        &state,
        daemon_config(Some("ws://127.0.0.1:19501")),
        EventHub::default(),
    )
    .await
    .expect("open changed-policy daemon");
    assert_eq!(
        status(&changed, "changed").await["relay_list_publication_state"],
        "blocked-policy-mismatch"
    );
    changed.prepare_for_shutdown().await;

    let missing = DaemonCore::open(&state, daemon_config(None), EventHub::default())
        .await
        .expect("open missing-config daemon");
    assert_eq!(
        status(&missing, "missing").await["relay_list_publication_state"],
        "blocked-config-missing"
    );
    missing.prepare_for_shutdown().await;
}
