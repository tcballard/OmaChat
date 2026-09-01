use std::{
    error::Error,
    fmt,
    future::{Ready, ready},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
    SignedLocalAccountBinding,
};
use omachat_registry::{CommandId, HandleClaim, RegistryState};
use omachat_registry_transport::{
    REGISTRY_TRANSPORT_VERSION, RegistryEvidenceResolution, RegistryOperation,
    RegistryProtocolError, RegistryRecord, RegistryResponse, RegistryResponseOutcome,
    RegistryTransport, decode_request, encode_response,
};
use omachat_store::{RegistryCacheLookup, RequestedProvider, SealedStore, VerifiedRegistryCache};
use omachatd::RegistryEvidenceService;
use tempfile::tempdir;

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
    .expect("Nostr identity");
    DevicePublicKeys {
        signing_public_key: signing.account_root_public_key,
        noise_public_key: [seed.wrapping_add(30); 32],
        nostr_public_key: *nostr.public_key(),
    }
}

fn binding(
    account: &AccountSecrets,
    handle: &str,
    revision: u64,
    device_seed: u8,
) -> SignedLocalAccountBinding {
    account.sign_local_binding(
        Some(GlobalHandle::parse(handle).expect("handle")),
        Some(DisplayName::parse("Registry Service Test").expect("display name")),
        device_keys(device_seed),
        revision,
        1_788_000_000 + revision,
    )
}

fn claim(account: &AccountSecrets, command: u8, handle: &str) -> HandleClaim {
    HandleClaim::sign(
        CommandId::from_bytes([command; 32]),
        0,
        binding(account, handle, 1, command),
        account,
    )
    .expect("claim")
}

#[derive(Clone)]
struct ControlledTransport {
    records: Arc<Vec<RegistryRecord>>,
    offline: Arc<AtomicBool>,
}

impl RegistryTransport for ControlledTransport {
    type Error = ControlledError;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, request: Vec<u8>) -> Self::Exchange<'_> {
        if self.offline.load(Ordering::SeqCst) {
            return ready(Err(ControlledError::Offline));
        }
        let response = decode_request(&request)
            .and_then(|request| {
                let record = match &request.operation {
                    RegistryOperation::LookupHandle { handle } => self
                        .records
                        .iter()
                        .find(|record| record.receipt.handle.as_global_handle() == handle),
                    RegistryOperation::LookupAccount { account_id } => self
                        .records
                        .iter()
                        .find(|record| record.receipt.account_id == *account_id),
                    RegistryOperation::Claim { .. } => None,
                };
                encode_response(&RegistryResponse {
                    version: REGISTRY_TRANSPORT_VERSION,
                    request_id: request.request_id,
                    outcome: record.map_or(RegistryResponseOutcome::NotFound, |record| {
                        RegistryResponseOutcome::Found {
                            record: Box::new(record.clone()),
                        }
                    }),
                })
            })
            .map_err(ControlledError::Protocol);
        ready(response)
    }
}

#[derive(Debug)]
enum ControlledError {
    Offline,
    Protocol(RegistryProtocolError),
}

impl fmt::Display for ControlledError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => formatter.write_str("offline"),
            Self::Protocol(error) => error.fmt(formatter),
        }
    }
}

impl Error for ControlledError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Offline => None,
            Self::Protocol(error) => Some(error),
        }
    }
}

#[tokio::test]
async fn concurrent_resolutions_preserve_both_verified_records() {
    let directory = tempdir().expect("cache directory");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
    let mut registry = RegistryState::from_signing_seed([61; 32]);
    let pinned_key = registry.verifying_key();
    let alice_handle = GlobalHandle::parse("alice").expect("Alice handle");
    let bob_handle = GlobalHandle::parse("bob").expect("Bob handle");
    registry
        .apply(claim(&account(1), 1, "alice"), 100)
        .expect("Alice claim");
    registry
        .apply(claim(&account(2), 2, "bob"), 101)
        .expect("Bob claim");
    let records = vec![
        RegistryRecord::from_record(
            registry
                .handle_record(&alice_handle)
                .expect("Alice lookup")
                .expect("Alice record"),
        ),
        RegistryRecord::from_record(
            registry
                .handle_record(&bob_handle)
                .expect("Bob lookup")
                .expect("Bob record"),
        ),
    ];
    let transport = ControlledTransport {
        records: Arc::new(records),
        offline: Arc::new(AtomicBool::new(false)),
    };
    let service = RegistryEvidenceService::with_transport(transport, pinned_key, 100)
        .expect("evidence service");

    let (alice, bob) = tokio::join!(
        service.resolve_handle(&store, &alice_handle, 1_000),
        service.resolve_handle(&store, &bob_handle, 1_000),
    );
    assert!(matches!(
        alice.expect("Alice resolution"),
        RegistryEvidenceResolution::Online(RegistryCacheLookup::Fresh(_))
    ));
    assert!(matches!(
        bob.expect("Bob resolution"),
        RegistryEvidenceResolution::Online(RegistryCacheLookup::Fresh(_))
    ));
    assert_eq!(
        VerifiedRegistryCache::load_or_create(&store, pinned_key)
            .expect("reload cache")
            .len(),
        2
    );
}

#[tokio::test]
async fn offline_resolution_reopens_sealed_evidence_without_refreshing_it() {
    let directory = tempdir().expect("cache directory");
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .expect("sealed store");
    let mut registry = RegistryState::from_signing_seed([62; 32]);
    let pinned_key = registry.verifying_key();
    let handle = GlobalHandle::parse("portableagent").expect("handle");
    registry
        .apply(claim(&account(3), 3, "portableagent"), 100)
        .expect("claim");
    let transport = ControlledTransport {
        records: Arc::new(vec![RegistryRecord::from_record(
            registry
                .handle_record(&handle)
                .expect("lookup")
                .expect("record"),
        )]),
        offline: Arc::new(AtomicBool::new(false)),
    };
    let service = RegistryEvidenceService::with_transport(transport.clone(), pinned_key, 100)
        .expect("evidence service");
    assert!(matches!(
        service
            .resolve_handle(&store, &handle, 1_000)
            .await
            .expect("online resolution"),
        RegistryEvidenceResolution::Online(RegistryCacheLookup::Fresh(_))
    ));

    transport.offline.store(true, Ordering::SeqCst);
    let reopened = RegistryEvidenceService::with_transport(transport, pinned_key, 100)
        .expect("reopened service");
    assert!(matches!(
        reopened
            .resolve_handle(&store, &handle, 1_101)
            .await
            .expect("offline resolution"),
        RegistryEvidenceResolution::Offline {
            cached: RegistryCacheLookup::OfflineStale(_),
            transport_error: ControlledError::Offline,
        }
    ));
}
