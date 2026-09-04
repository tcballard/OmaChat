use futures_util::{SinkExt, StreamExt};
use omachat_nostr::georelay::{
    ANDROID_SNAPSHOT_SHA256, COMPATIBILITY_PROFILE_ID, SWIFT_SNAPSHOT_SHA256,
};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler};
use serde_json::{Value, json};
use std::time::Duration;
use tempfile::tempdir;
use tokio::{
    net::TcpListener,
    sync::mpsc,
    time::{sleep, timeout},
};

async fn command(core: &DaemonCore, command: Command) -> ResponseOutcome {
    core.handle(Request {
        version: VERSION,
        id: "geo-test".into(),
        command,
    })
    .await
}

async fn status(core: &DaemonCore) -> Value {
    match command(core, Command::Status).await {
        ResponseOutcome::Ok { result } => result,
        other => panic!("status failed: {other:?}"),
    }
}

fn config(value: Value) -> DaemonConfig {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    DaemonConfig::load(path).unwrap()
}

#[test]
fn pinned_config_is_explicit_bounded_and_preserves_tls_policy() {
    for value in [
        json!({"geo_relays":{"mode":"invalid"}}),
        json!({"geo_relays":{"mode":"replace"}}),
        json!({"geo_relays":{"overrides":["ws://relay.example"]}}),
        json!({"geo_relays":{"overrides":["ws://localhost:1234"]}}),
        json!({"geo_relays":{"overrides":["wss://user@relay.example"]}}),
        json!({"geo_relays":{"overrides":["wss://relay.example?secret=1"]}}),
        json!({"geo_relays":{"overrides":["wss://relay.example", "wss://relay.example/"]}}),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(DaemonConfig::load(path).is_err(), "accepted {value}");
    }
    assert!(config(json!({})).geo_relays.is_none());
    assert!(config(json!({"geo_relays":{}})).geo_relays.is_some());
}

#[tokio::test]
async fn daemon_status_reports_exact_pins_without_claiming_a_running_pool() {
    let dir = tempdir().unwrap();
    let core = DaemonCore::open(
        dir.path(),
        config(json!({"storage_provider":"file", "geo_relays":{}})),
        EventHub::default(),
    )
    .await
    .unwrap();
    let status = status(&core).await;
    assert_eq!(status["geo_relays"]["enabled"], true);
    assert_eq!(status["geo_relays"]["mode"], "supplement");
    assert_eq!(
        status["geo_relays"]["compatibility_profile"],
        COMPATIBILITY_PROFILE_ID
    );
    assert_eq!(
        status["geo_relays"]["swift_snapshot_sha256"],
        SWIFT_SNAPSHOT_SHA256
    );
    assert_eq!(
        status["geo_relays"]["android_snapshot_sha256"],
        ANDROID_SNAPSHOT_SHA256
    );
    assert!(status["geo_relays"]["runtime"].is_null());
    // Enabling pinned mode must never leak cell filters into the legacy pool.
    command(
        &core,
        Command::Join {
            geohash: "gcpvj".into(),
        },
    )
    .await;
    assert!(
        core.nostr_filters(1000)
            .unwrap()
            .iter()
            .all(|filter| filter.get("#g").is_none())
    );
}

#[tokio::test]
async fn runtime_routes_cells_independently_and_leave_removes_the_pool() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let (seen, mut observations) = mpsc::channel::<Value>(64);
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut subscribed_cell = None;
                while let Some(Ok(message)) = socket.next().await {
                    match message {
                        tokio_tungstenite::tungstenite::Message::Text(text) => {
                            let frame: Value = serde_json::from_str(&text).unwrap();
                            if frame[0] == "REQ" {
                                assert_eq!(
                                    frame.as_array().unwrap().len(),
                                    3,
                                    "one cell filter only"
                                );
                                assert_eq!(frame[2]["#g"].as_array().unwrap().len(), 1);
                                assert!(
                                    frame[2].get("#p").is_none(),
                                    "no private mailbox subscription"
                                );
                                subscribed_cell = Some(frame[2]["#g"][0].clone());
                            } else if frame[0] == "EVENT" {
                                let cell = frame[1]["tags"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .find(|tag| tag[0] == "g")
                                    .unwrap()[1]
                                    .clone();
                                assert_eq!(Some(cell), subscribed_cell);
                                socket
                                    .send(tokio_tungstenite::tungstenite::Message::Text(
                                        json!(["OK", frame[1]["id"], true, "stored"])
                                            .to_string()
                                            .into(),
                                    ))
                                    .await
                                    .unwrap();
                            }
                            let _ = seen.send(frame).await;
                        }
                        tokio_tungstenite::tungstenite::Message::Ping(bytes) => {
                            let _ = socket
                                .send(tokio_tungstenite::tungstenite::Message::Pong(bytes))
                                .await;
                        }
                        tokio_tungstenite::tungstenite::Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    });
    let dir = tempdir().unwrap();
    let core = DaemonCore::open(
        dir.path(),
        config(json!({
            "storage_provider":"file", "joined_geohashes":["gcpvj", "u4pruy"],
            "geo_relays":{"mode":"replace", "overrides":[url.clone()]}
        })),
        EventHub::default(),
    )
    .await
    .unwrap();
    let (incoming, mut notifications) = mpsc::channel(256);
    let drain = tokio::spawn(async move { while notifications.recv().await.is_some() {} });
    let service = core.start_geo_relays(incoming).unwrap().unwrap();
    timeout(Duration::from_secs(10), async {
        let mut subscriptions = 0;
        while subscriptions < 2 {
            if observations.recv().await.unwrap()[0] == "REQ" {
                subscriptions += 1;
            }
        }
        loop {
            let value = status(&core).await;
            if value["geo_relays"]["runtime"]["cells"]
                .as_array()
                .unwrap()
                .len()
                == 2
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    for cell in ["gcpvj", "u4pruy"] {
        let sent = command(
            &core,
            Command::Send {
                conversation: cell.into(),
                text: "scoped message".into(),
            },
        )
        .await;
        assert!(matches!(sent, ResponseOutcome::Ok { .. }), "{sent:?}");
    }
    let value = status(&core).await;
    for cell in value["geo_relays"]["runtime"]["cells"].as_array().unwrap() {
        assert_eq!(cell["selected_relays"], json!([url]));
        assert_eq!(cell["swift_snapshot_sha256"], SWIFT_SNAPSHOT_SHA256);
    }
    command(
        &core,
        Command::Leave {
            geohash: "gcpvj".into(),
        },
    )
    .await;
    timeout(Duration::from_secs(5), async {
        loop {
            if status(&core).await["geo_relays"]["runtime"]["cells"]
                .as_array()
                .unwrap()
                .len()
                == 1
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        command(
            &core,
            Command::Send {
                conversation: "gcpvj".into(),
                text: "must not send".into()
            }
        )
        .await,
        ResponseOutcome::Error { .. }
    ));
    // Panic must stop the new pools before destroying keys too.
    assert!(matches!(
        command(
            &core,
            Command::Panic {
                confirmation: "ERASE".into()
            }
        )
        .await,
        ResponseOutcome::Ok { .. }
    ));
    service.shutdown().await;
    server.abort();
    drain.abort();
}

#[tokio::test]
async fn failed_override_is_removed_without_escaping_replace_policy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("ws://{}", listener.local_addr().unwrap());
    // Keep the TCP listener alive but reject every WebSocket handshake.
    let reject = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        }
    });
    let dir = tempdir().unwrap();
    let core = DaemonCore::open(
        dir.path(),
        config(json!({
            "storage_provider":"file", "joined_geohashes":["gcpvj"],
            "geo_relays":{"mode":"replace", "overrides":[dead.clone()]}
        })),
        EventHub::default(),
    )
    .await
    .unwrap();
    let (incoming, mut notifications) = mpsc::channel(256);
    let drain = tokio::spawn(async move { while notifications.recv().await.is_some() {} });
    let service = core.start_geo_relays(incoming).unwrap().unwrap();
    timeout(Duration::from_secs(40), async {
        loop {
            let value = status(&core).await;
            let cell = &value["geo_relays"]["runtime"]["cells"][0];
            if cell["skipped_unhealthy"] == json!([dead]) {
                assert_eq!(cell["selected_relays"], json!([]));
                assert_eq!(cell["pool_active"], false);
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("periodic health fallback must remove the failed endpoint");
    assert!(matches!(
        command(
            &core,
            Command::Send {
                conversation: "gcpvj".into(),
                text: "cannot store".into()
            }
        )
        .await,
        ResponseOutcome::Error { .. }
    ));
    service.shutdown().await;
    reject.abort();
    drain.abort();
}
