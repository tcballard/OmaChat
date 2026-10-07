use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, PanicState, RequestHandler, StorageProviderConfig,
};
use std::fs;
use tempfile::tempdir;
async fn minted_panic_token(core: &DaemonCore) -> String {
    let outcome = core
        .handle(Request {
            version: VERSION,
            id: "panic-token".into(),
            command: Command::RequestPanicConfirmation,
        })
        .await;
    let ResponseOutcome::Ok { result } = outcome else {
        panic!("panic token issuance failed: {outcome:?}");
    };
    let path = result
        .get("token_path")
        .and_then(serde_json::Value::as_str)
        .expect("token_path")
        .to_owned();
    std::fs::read_to_string(path)
        .expect("token file")
        .trim()
        .to_owned()
}

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
    let token = minted_panic_token(&core).await;
    command(
        &core,
        Command::Panic {
            confirmation: token,
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
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("open core");
    fs::remove_file(temporary.path().join("master.key")).expect("inject key cleanup failure");

    let token = minted_panic_token(&core).await;
    let failed = core
        .handle(Request {
            version: VERSION,
            id: "panic-failure".into(),
            command: Command::Panic {
                confirmation: token,
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
async fn draft_ipc_survives_restart_and_refuses_stale_client() {
    let directory = tempdir().unwrap();
    let config = DaemonConfig {
        storage_provider: StorageProviderConfig::File,
        ..DaemonConfig::default()
    };
    let core = DaemonCore::open(directory.path(), config.clone(), EventHub::default())
        .await
        .unwrap();
    assert_eq!(command(&core, Command::Status).await["drafts_version"], 1);
    let saved = command(
        &core,
        Command::SaveDraft {
            conversation: "hosted:general".into(),
            text: "restart draft".into(),
            expected_revision: 0,
        },
    )
    .await;
    assert_eq!(saved["saved"], true);
    drop(core);
    let core = DaemonCore::open(directory.path(), config, EventHub::default())
        .await
        .unwrap();
    assert_eq!(
        command(&core, Command::ListDrafts).await["drafts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let current = command(
        &core,
        Command::GetDraft {
            conversation: "hosted:general".into(),
        },
    )
    .await;
    assert_eq!(current["text"], "restart draft");
    let conflict = command(
        &core,
        Command::SaveDraft {
            conversation: "hosted:general".into(),
            text: "stale text".into(),
            expected_revision: 0,
        },
    )
    .await;
    assert_eq!(conflict["saved"], false);
    assert_eq!(conflict["text"], "restart draft");
}
