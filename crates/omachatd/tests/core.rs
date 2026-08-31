use futures_util::{SinkExt, StreamExt};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use serde_json::Value;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

async fn command(core: &DaemonCore, command: Command) -> serde_json::Value {
    match core
        .handle(Request {
            version: VERSION,
            id: "test".into(),
            command,
        })
        .await
    {
        ResponseOutcome::Ok { result } => result,
        ResponseOutcome::Error { error } => panic!("daemon error: {}", error.message),
    }
}

async fn next_json(socket: &mut WebSocketStream<TcpStream>) -> Value {
    loop {
        match socket.next().await.unwrap().unwrap() {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
            other => panic!("unexpected relay message: {other:?}"),
        }
    }
}

async fn wait_for_connected(
    notifications: &mut tokio::sync::mpsc::Receiver<omachat_nostr::pool::PoolNotification>,
) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(notification) = notifications.recv().await {
            if matches!(
                notification.notification,
                omachat_nostr::relay::RelayNotification::Connected
            ) {
                return;
            }
        }
        panic!("Nostr service stopped before connecting");
    })
    .await
    .expect("relay connection");
}

#[tokio::test]
async fn identity_outbox_and_commands_survive_restart() {
    let temporary = tempdir().expect("temporary directory");
    let config = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        ..DaemonConfig::default()
    };
    let core = DaemonCore::open(temporary.path(), config.clone(), EventHub::default())
        .await
        .expect("open core");
    let first_status = command(&core, Command::Status).await;
    command(
        &core,
        Command::Join {
            geohash: "GCPVJ".into(),
        },
    )
    .await;
    let sent = command(
        &core,
        Command::Send {
            conversation: "07e1870bb208e66b5189c2dc7b1c0018e26871920148706534dd74ee5a126ff4".into(),
            text: "private restart message".into(),
        },
    )
    .await;
    assert_eq!(sent["delivery"], "queued");
    drop(core);

    let reopened = DaemonCore::open(temporary.path(), config, EventHub::default())
        .await
        .expect("reopen core");
    let second_status = command(&reopened, Command::Status).await;
    assert_eq!(first_status["fingerprint"], second_status["fingerprint"]);
    assert_eq!(second_status["outbox_pending"], 1);

    let backing =
        fs::read(temporary.path().join("records/nostr-outbox-v1")).expect("sealed outbox backing");
    assert!(
        !backing
            .windows(23)
            .any(|window| window == b"private restart message")
    );
}

#[tokio::test]
async fn invalid_reload_keeps_the_prior_configuration_active() {
    let temporary = tempdir().expect("temporary directory");
    let core = DaemonCore::open(
        temporary.path().join("state"),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            relays: vec!["wss://relay.example".into()],
            joined_geohashes: vec!["gcpvj".into()],
            nickname: None,
        },
        EventHub::default(),
    )
    .await
    .expect("open core");
    let before = command(&core, Command::Status).await;
    let config_path = temporary.path().join("config.json");
    fs::write(&config_path, br#"{"relays":["http://wrong.example"]}"#).expect("invalid config");
    assert!(core.reload(&config_path).is_err());
    let after = command(&core, Command::Status).await;
    assert_eq!(before["relay_count"], after["relay_count"]);
    assert_eq!(before["joined_geohashes"], after["joined_geohashes"]);
}

#[tokio::test]
async fn panic_requires_confirmation_erases_state_and_rejects_more_work() {
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
    .expect("open core");
    let denied = core
        .handle(Request {
            version: VERSION,
            id: "no".into(),
            command: Command::Panic {
                confirmation: "no".into(),
            },
        })
        .await;
    assert!(matches!(denied, ResponseOutcome::Error { .. }));
    command(
        &core,
        Command::Panic {
            confirmation: "ERASE".into(),
        },
    )
    .await;
    assert!(core.is_panicked());
    assert!(!temporary.path().exists());
    let rejected = core
        .handle(Request {
            version: VERSION,
            id: "after".into(),
            command: Command::Status,
        })
        .await;
    assert!(matches!(rejected, ResponseOutcome::Error { .. }));
}

#[tokio::test]
async fn join_and_leave_replace_the_live_subscription_filters() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let first = next_json(&mut socket).await;
        assert_eq!(first[0], "REQ");
        assert_eq!(first[1], "omachat-main-v1");
        assert_eq!(first[2]["#g"][0], "gcpvj");
        assert_eq!(first[3]["#p"].as_array().unwrap().len(), 1);
        let second = next_json(&mut socket).await;
        assert_eq!(second[0], "REQ");
        assert_eq!(second[1], "omachat-main-v1");
        assert!(second[2]["#p"].is_array());
        while let Some(Ok(message)) = socket.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    });

    let temporary = tempdir().unwrap();
    let core = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let (inbound, mut notifications) = tokio::sync::mpsc::channel(8);
    let service = omachatd::NostrService::spawn(&[url], inbound).unwrap();
    core.attach_nostr(service.handle());
    wait_for_connected(&mut notifications).await;

    let joined = command(
        &core,
        Command::Join {
            geohash: "GCPVJ".into(),
        },
    )
    .await;
    assert_eq!(joined["joined"], "gcpvj");
    let left = command(
        &core,
        Command::Leave {
            geohash: "gcpvj".into(),
        },
    )
    .await;
    assert_eq!(left["left"], "gcpvj");

    service.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn reconnect_drains_a_queued_private_message_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut first = accept_async(stream).await.unwrap();
        let first_event = next_json(&mut first).await;
        assert_eq!(first_event[0], "EVENT");
        first.close(None).await.unwrap();

        let (stream, _) = listener.accept().await.unwrap();
        let mut second = accept_async(stream).await.unwrap();
        let second_event = next_json(&mut second).await;
        assert_eq!(second_event[0], "EVENT");
        assert_eq!(second_event[1]["id"], first_event[1]["id"]);
        second
            .send(Message::Text(
                serde_json::json!(["OK", second_event[1]["id"], true, "retried"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        while let Some(Ok(message)) = second.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    });

    let temporary = tempdir().unwrap();
    let core = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let sent = command(
        &core,
        Command::Send {
            conversation: "07e1870bb208e66b5189c2dc7b1c0018e26871920148706534dd74ee5a126ff4".into(),
            text: "reconnect me".into(),
        },
    )
    .await;
    assert_eq!(sent["delivery"], "queued");

    let (inbound, mut notifications) = tokio::sync::mpsc::channel(32);
    let service = omachatd::NostrService::spawn(&[url], inbound).unwrap();
    core.attach_nostr(service.handle());
    let notification_core = core.clone();
    let forwarding = tokio::spawn(async move {
        while let Some(notification) = notifications.recv().await {
            notification_core.receive_nostr_notification(notification);
        }
    });

    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let status = command(&core, Command::Status).await;
            if status["outbox_pending"] == 0 && status["outbox_failed"] == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("queued message drained after reconnect");

    service.shutdown().await.unwrap();
    forwarding.await.unwrap();
    server.await.unwrap();
}
