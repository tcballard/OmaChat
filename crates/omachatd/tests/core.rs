use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use std::fs;
use tempfile::tempdir;

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
