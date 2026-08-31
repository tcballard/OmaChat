use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
};
use omachat_registry::{CommandId, HandleClaim};
use omachat_registry_host::{RegistryHostLimits, run_registry_host};
use omachat_registry_transport::{RegistryClient, RegistryService, RegistryWebSocketTransport};
use omachat_store::{RequestedProvider, SealedStore};
use std::time::Duration;
use tempfile::tempdir;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::sleep,
};

fn account(seed: u8) -> AccountSecrets {
    AccountSecrets::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
}

fn device_keys(seed: u8) -> DevicePublicKeys {
    let signing = account(seed.wrapping_add(10)).public_identity();
    let nostr = IdentitySecrets::from_seeds(
        [seed.wrapping_add(20); 32],
        [seed.wrapping_add(21); 32],
        [seed.wrapping_add(22); 32],
    )
    .device_nostr_identity()
    .unwrap();
    DevicePublicKeys {
        signing_public_key: signing.account_root_public_key,
        noise_public_key: [seed.wrapping_add(30); 32],
        nostr_public_key: *nostr.public_key(),
    }
}

fn claim(account: &AccountSecrets, handle: &str) -> HandleClaim {
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Host Test").unwrap()),
        device_keys(1),
        1,
        1_788_000_001,
    );
    HandleClaim::sign(CommandId::from_bytes([1; 32]), 0, binding, account).unwrap()
}

#[tokio::test]
async fn host_serves_verified_claim_and_drains_cleanly() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [90; 32]).unwrap();
    let pinned_key = service.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}/registry-v1", listener.local_addr().unwrap());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let host = run_registry_host(
        listener,
        &mut service,
        RegistryHostLimits::default(),
        || 100,
        async {
            let _ = shutdown_rx.await;
        },
    );
    let client = async {
        let transport = RegistryWebSocketTransport::new(&endpoint).unwrap();
        let mut client = RegistryClient::new(transport, pinned_key);
        let receipt = client.claim(&claim(&account(1), "alice")).await.unwrap();
        shutdown_tx.send(()).unwrap();
        receipt
    };
    let (report, receipt) = tokio::join!(host, client);
    let report = report.unwrap();
    assert_eq!(receipt.sequence, 1);
    assert_eq!(report.admitted_connections, 1);
    assert_eq!(report.completed_responses, 1);
    assert!(!report.forced_shutdown);
}

#[tokio::test]
async fn per_ip_limit_recovers_after_idle_admission_timeout() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [91; 32]).unwrap();
    let pinned_key = service.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = format!("ws://{address}/registry-v1");
    let limits = RegistryHostLimits {
        max_connections: 2,
        max_connections_per_ip: 1,
        request_admission_timeout: Duration::from_millis(80),
        shutdown_grace: Duration::from_secs(1),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let host = run_registry_host(listener, &mut service, limits, || 100, async {
        let _ = shutdown_rx.await;
    });
    let client = async {
        let idle = TcpStream::connect(address).await.unwrap();
        sleep(Duration::from_millis(20)).await;
        let transport = RegistryWebSocketTransport::new(&endpoint).unwrap();
        let mut rejected = RegistryClient::new(transport, pinned_key);
        assert!(
            rejected
                .lookup_handle(&GlobalHandle::parse("nobody").unwrap())
                .await
                .is_err()
        );
        sleep(Duration::from_millis(100)).await;
        drop(idle);
        let transport = RegistryWebSocketTransport::new(&endpoint).unwrap();
        let mut recovered = RegistryClient::new(transport, pinned_key);
        assert!(
            recovered
                .lookup_handle(&GlobalHandle::parse("nobody").unwrap())
                .await
                .unwrap()
                .is_none()
        );
        shutdown_tx.send(()).unwrap();
    };
    let (report, ()) = tokio::join!(host, client);
    let report = report.unwrap();
    assert_eq!(report.rejected_per_ip_limit, 1);
    assert_eq!(report.admission_timeouts, 1);
    assert_eq!(report.completed_responses, 1);
}

#[tokio::test]
async fn shutdown_grace_aborts_an_idle_connection() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [92; 32]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let limits = RegistryHostLimits {
        max_connections: 1,
        max_connections_per_ip: 1,
        request_admission_timeout: Duration::from_secs(5),
        shutdown_grace: Duration::from_millis(30),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let host = run_registry_host(listener, &mut service, limits, || 100, async {
        let _ = shutdown_rx.await;
    });
    let client = async {
        let _idle = TcpStream::connect(address).await.unwrap();
        sleep(Duration::from_millis(20)).await;
        shutdown_tx.send(()).unwrap();
        sleep(Duration::from_millis(60)).await;
    };
    let (report, ()) = tokio::join!(host, client);
    let report = report.unwrap();
    assert!(report.forced_shutdown);
    assert_eq!(report.aborted_connections, 1);
}

#[test]
fn invalid_limits_are_rejected() {
    let invalid = RegistryHostLimits {
        max_connections: 1,
        max_connections_per_ip: 2,
        ..RegistryHostLimits::default()
    };
    assert!(invalid.validate().is_err());
}
