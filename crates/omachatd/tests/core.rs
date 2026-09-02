use futures_util::{SinkExt, StreamExt};
use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, PanicState, RequestHandler, StorageProviderConfig,
};
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
    assert_eq!(
        first_status["account"]["account_id"],
        second_status["account"]["account_id"]
    );
    assert_eq!(
        first_status["account"]["device_id"],
        second_status["account"]["device_id"]
    );
    assert_eq!(second_status["account"]["registry_state"], "unconfigured");
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
            dm_relays: Vec::new(),
            profile_publication: None,
            relay_list_publication: None,
            joined_geohashes: vec!["gcpvj".into()],
            account_handle: None,
            account_display_name: None,
            registry: None,
            nickname: None,
            rooms: None,
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
async fn configured_account_profile_is_sealed_restart_stable_and_local_only() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let configured = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        account_handle: Some("@tom".into()),
        account_display_name: Some("Tom Ballard".into()),
        ..DaemonConfig::default()
    };
    let core = DaemonCore::open(&state, configured, EventHub::default())
        .await
        .expect("open configured account");
    let first = command(&core, Command::Status).await;
    assert_eq!(first["account"]["handle"], "tom");
    assert_eq!(first["account"]["display_name"], "Tom Ballard");
    assert_eq!(first["account"]["binding_revision"], 1);
    assert_eq!(first["account"]["registry_state"], "local-only");
    let account_id = first["account"]["account_id"].clone();
    let device_id = first["account"]["device_id"].clone();
    drop(core);

    let backing = fs::read(state.join("records/account-v1")).expect("sealed account backing");
    assert!(!backing.windows(3).any(|window| window == b"tom"));
    assert!(
        !backing
            .windows("Tom Ballard".len())
            .any(|window| window == b"Tom Ballard")
    );

    let reopened = DaemonCore::open(
        &state,
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("reopen without repeating profile config");
    let second = command(&reopened, Command::Status).await;
    assert_eq!(second["account"]["account_id"], account_id);
    assert_eq!(second["account"]["device_id"], device_id);
    assert_eq!(second["account"]["handle"], "tom");
    assert_eq!(second["account"]["display_name"], "Tom Ballard");
    assert_eq!(second["account"]["binding_revision"], 1);
    assert_eq!(second["account"]["registry_state"], "local-only");
}

#[tokio::test]
async fn account_profile_reload_is_validated_revisioned_and_persisted() {
    let temporary = tempdir().expect("temporary directory");
    let state = temporary.path().join("state");
    let core = DaemonCore::open(
        &state,
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("open unconfigured account");
    let before = command(&core, Command::Status).await;
    assert_eq!(before["account"]["binding_revision"], 1);
    assert_eq!(before["account"]["registry_state"], "unconfigured");

    let config_path = temporary.path().join("account.json");
    fs::write(
        &config_path,
        br#"{"storage_provider":"file","account_handle":"@tom","account_display_name":"Tom"}"#,
    )
    .expect("write account config");
    core.reload(&config_path).expect("reload account profile");
    let reloaded = command(&core, Command::Status).await;
    assert_eq!(
        reloaded["account"]["account_id"],
        before["account"]["account_id"]
    );
    assert_eq!(reloaded["account"]["handle"], "tom");
    assert_eq!(reloaded["account"]["display_name"], "Tom");
    assert_eq!(reloaded["account"]["binding_revision"], 2);
    assert_eq!(reloaded["account"]["registry_state"], "local-only");
    drop(core);

    let reopened = DaemonCore::open(
        &state,
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("reopen updated profile");
    let after_restart = command(&reopened, Command::Status).await;
    assert_eq!(after_restart["account"]["handle"], "tom");
    assert_eq!(after_restart["account"]["binding_revision"], 2);
}

#[tokio::test]
async fn global_account_handle_is_not_reused_as_a_geohash_nickname() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let event_frame = next_json(&mut socket).await;
        assert_eq!(event_frame[0], "EVENT");
        assert_eq!(event_frame[1]["content"], "unlinkable hello");
        assert!(
            event_frame[1]["tags"]
                .as_array()
                .unwrap()
                .iter()
                .all(|tag| tag[0] != "n")
        );
        socket
            .send(Message::Text(
                serde_json::json!(["OK", event_frame[1]["id"], true, "stored"])
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
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
            joined_geohashes: vec!["gcpvj".into()],
            account_handle: Some("tom".into()),
            nickname: None,
            rooms: None,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .unwrap();
    let (inbound, mut notifications) = tokio::sync::mpsc::channel(8);
    let service = omachatd::NostrService::spawn(&[url], inbound).unwrap();
    core.attach_nostr(service.handle()).unwrap();
    wait_for_connected(&mut notifications).await;

    let sent = command(
        &core,
        Command::Send {
            conversation: "#gcpvj".into(),
            text: "unlinkable hello".into(),
        },
    )
    .await;
    assert_eq!(sent["delivery"], "stored");

    service.shutdown().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn invalid_account_profile_configuration_fails_before_core_start() {
    let temporary = tempdir().expect("temporary directory");
    let result = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            account_handle: Some("Tom".into()),
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await;
    assert!(result.is_err());
    assert!(!temporary.path().join("storage-mode").exists());
}

#[tokio::test]
async fn panic_requires_confirmation_erases_state_and_rejects_more_work() {
    let temporary = tempdir().expect("temporary directory");
    let reload_directory = tempdir().expect("reload directory");
    let reload_path = reload_directory.path().join("config.json");
    fs::write(&reload_path, b"{}").expect("reload config");
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
    assert_eq!(core.panic_state(), PanicState::Active);
    command(
        &core,
        Command::Panic {
            confirmation: "ERASE".into(),
        },
    )
    .await;
    assert!(core.is_panicked());
    assert_eq!(
        core.wait_for_panic_terminal().await,
        PanicState::CleanupComplete
    );
    assert!(!temporary.path().exists());
    assert!(core.reload(&reload_path).is_err());
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
async fn panic_cleanup_failure_is_terminal_and_never_reenables_the_daemon() {
    let temporary = tempdir().expect("temporary directory");
    let core = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            account_handle: Some("tom".into()),
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("open core");
    fs::remove_file(temporary.path().join("master.key")).expect("inject key cleanup failure");

    let failed = core
        .handle(Request {
            version: VERSION,
            id: "panic-failure".into(),
            command: Command::Panic {
                confirmation: "ERASE".into(),
            },
        })
        .await;
    assert!(matches!(failed, ResponseOutcome::Error { .. }));
    assert!(core.is_panicked());
    assert_eq!(
        core.wait_for_panic_terminal().await,
        PanicState::CleanupFailed
    );

    let rejected = core
        .handle(Request {
            version: VERSION,
            id: "after-failure".into(),
            command: Command::Status,
        })
        .await;
    assert!(matches!(rejected, ResponseOutcome::Error { .. }));
}

#[tokio::test]
async fn panic_cancels_a_slow_publish_before_erasing_and_emits_no_local_message() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let (event_seen_sender, event_seen_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let event = next_json(&mut socket).await;
        assert_eq!(event[0], "EVENT");
        event_seen_sender.send(()).unwrap();
        // Withhold OK so the send command remains inside relay publication
        // until panic quiescence cancels it.
        while let Some(Ok(message)) = socket.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    });

    let temporary = tempdir().unwrap();
    let events = EventHub::default();
    let mut local_events = events.subscribe();
    let core = DaemonCore::open(
        temporary.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            joined_geohashes: vec!["gcpvj".into()],
            ..DaemonConfig::default()
        },
        events,
    )
    .await
    .unwrap();
    let (inbound, mut notifications) = tokio::sync::mpsc::channel(8);
    let service = omachatd::NostrService::spawn(&[url], inbound).unwrap();
    core.attach_nostr(service.handle()).unwrap();
    wait_for_connected(&mut notifications).await;

    let send_core = core.clone();
    let send = tokio::spawn(async move {
        send_core
            .handle(Request {
                version: VERSION,
                id: "slow-send".into(),
                command: Command::Send {
                    conversation: "#gcpvj".into(),
                    text: "must not publish locally after panic".into(),
                },
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), event_seen_receiver)
        .await
        .expect("relay receives slow publish")
        .expect("relay event signal");

    let panic_core = core.clone();
    let panic = tokio::spawn(async move {
        panic_core
            .handle(Request {
                version: VERSION,
                id: "panic-during-send".into(),
                command: Command::Panic {
                    confirmation: "ERASE".into(),
                },
            })
            .await
    });

    let sent = tokio::time::timeout(Duration::from_secs(2), send)
        .await
        .expect("slow send is cancelled")
        .expect("send task");
    assert!(matches!(sent, ResponseOutcome::Error { .. }));
    let erased = tokio::time::timeout(Duration::from_secs(2), panic)
        .await
        .expect("panic cleanup completes after send releases its operation guard")
        .expect("panic task");
    assert!(matches!(erased, ResponseOutcome::Ok { .. }));
    assert_eq!(core.panic_state(), PanicState::CleanupComplete);
    assert!(local_events.try_recv().is_err());
    assert!(
        core.attach_nostr(service.handle()).is_err(),
        "a relay handle cannot be attached after panic starts"
    );

    service.shutdown().await.unwrap();
    server.await.unwrap();
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
    core.attach_nostr(service.handle()).unwrap();
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
    core.attach_nostr(service.handle()).unwrap();
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
