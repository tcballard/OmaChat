use omachat_proto::ipc::{Command, Request, ResponseOutcome, VERSION};
use omachatd::{DaemonConfig, DaemonCore, EventHub, RequestHandler, StorageProviderConfig};
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

async fn open_core(state: &std::path::Path) -> DaemonCore {
    DaemonCore::open(
        state,
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("open core")
}

async fn ok_result(core: &DaemonCore, id: &str, command: Command) -> serde_json::Value {
    let outcome = core
        .handle(Request {
            version: VERSION,
            id: id.into(),
            command,
        })
        .await;
    let ResponseOutcome::Ok { result } = outcome else {
        panic!("expected ok outcome, got {outcome:?}");
    };
    result
}

#[tokio::test]
async fn panic_confirmation_request_mints_a_private_token_file() {
    let temporary = tempdir().expect("temporary directory");
    let core = open_core(temporary.path()).await;
    let result = ok_result(&core, "token", Command::RequestPanicConfirmation).await;
    let token_path = result
        .get("token_path")
        .and_then(serde_json::Value::as_str)
        .expect("token_path in result");
    assert!(token_path.starts_with(temporary.path().to_str().expect("utf8 path")));
    let mode = std::fs::metadata(token_path)
        .expect("token metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::read_to_string(token_path)
            .expect("token file")
            .len(),
        64
    );
    assert!(
        result
            .get("expires_at")
            .and_then(serde_json::Value::as_u64)
            .is_some()
    );
    assert_eq!(
        result
            .get("ttl_seconds")
            .and_then(serde_json::Value::as_u64),
        Some(120)
    );
}

#[tokio::test]
async fn claim_confirmation_request_validates_the_handle() {
    let temporary = tempdir().expect("temporary directory");
    let core = open_core(temporary.path()).await;
    let outcome = core
        .handle(Request {
            version: VERSION,
            id: "bad".into(),
            command: Command::RequestRegistryClaimConfirmation {
                handle: "NOT A HANDLE".into(),
            },
        })
        .await;
    assert!(
        matches!(outcome, ResponseOutcome::Error { .. }),
        "invalid handles must not mint tokens"
    );
    let result = ok_result(
        &core,
        "good",
        Command::RequestRegistryClaimConfirmation {
            handle: "tom".into(),
        },
    )
    .await;
    assert!(
        result
            .get("token_path")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
}
