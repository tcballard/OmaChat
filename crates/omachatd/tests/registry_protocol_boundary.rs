use ed25519_dalek::SigningKey;
use omachat_proto::ipc::{Command, ErrorCode, Request, ResponseOutcome, VERSION};
use omachatd::{
    DaemonConfig, DaemonCore, EventHub, RegistryClientConfig, RegistryProtocol, RequestHandler,
    StorageProviderConfig,
};
use tempfile::tempdir;

fn registry_config(protocol: RegistryProtocol) -> RegistryClientConfig {
    RegistryClientConfig {
        endpoint: "ws://127.0.0.1:65535/registry".into(),
        pinned_public_key: hex::encode(
            SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes(),
        ),
        max_age_seconds: 300,
        protocol,
    }
}

async fn request(core: &DaemonCore, command: Command) -> ResponseOutcome {
    core.handle(Request {
        version: VERSION,
        id: "registry-protocol-boundary".into(),
        command,
    })
    .await
}

#[tokio::test]
async fn principal_protocol_opens_its_own_boundary_and_reports_truthful_status() {
    let directory = tempdir().expect("state directory");
    let core = DaemonCore::open(
        directory.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            account_handle: Some("alice".into()),
            registry: Some(registry_config(RegistryProtocol::PrincipalProofV1)),
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("principal boundary");

    let ResponseOutcome::Ok { result: status } = request(&core, Command::Status).await else {
        panic!("status failed");
    };
    assert_eq!(status["registry_protocol"], "principal-proof-v1");
    assert_eq!(status["account"]["registry_state"], "local-only");

    let ResponseOutcome::Error { error } = request(
        &core,
        Command::ShowRegistryHandle {
            handle: "alice".into(),
        },
    )
    .await
    else {
        panic!("root-only command crossed the protocol boundary");
    };
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.message.contains("configured registry protocol"));
}

#[tokio::test]
async fn root_protocol_remains_the_explicit_existing_boundary() {
    let directory = tempdir().expect("state directory");
    let core = DaemonCore::open(
        directory.path(),
        DaemonConfig {
            storage_provider: StorageProviderConfig::File,
            registry: Some(registry_config(RegistryProtocol::RootClaimV2)),
            ..DaemonConfig::default()
        },
        EventHub::default(),
    )
    .await
    .expect("root boundary");

    let ResponseOutcome::Ok { result: status } = request(&core, Command::Status).await else {
        panic!("status failed");
    };
    assert_eq!(status["registry_protocol"], "root-claim-v2");
}
