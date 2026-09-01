use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
    SignedLocalAccountBinding,
};
use omachat_registry::{CommandId, HandleClaim, RegistryError, RegistryState};
use omachat_registry_transport::{
    REGISTRY_TRANSPORT_VERSION, RegistryClient, RegistryClientError, RegistryEvidenceClient,
    RegistryEvidenceError, RegistryEvidenceResolution, RegistryRecord, RegistryResponse,
    RegistryResponseOutcome, RegistryService, RegistryServiceError, RegistryTransport,
    decode_request, encode_response,
};
use omachat_store::{RegistryCacheLookup, RequestedProvider, SealedStore, VerifiedRegistryCache};
use std::{
    error::Error,
    fmt,
    future::{Ready, ready},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
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
    .unwrap();
    DevicePublicKeys {
        signing_public_key: signing.account_root_public_key,
        noise_public_key: [seed.wrapping_add(30); 32],
        nostr_public_key: *nostr.public_key(),
    }
}

fn binding(account: &AccountSecrets, handle: &str, revision: u64) -> SignedLocalAccountBinding {
    account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Evidence Test").unwrap()),
        device_keys(revision as u8),
        revision,
        1_788_000_000 + revision,
    )
}

fn claim(account: &AccountSecrets, command: u8, handle: &str) -> HandleClaim {
    HandleClaim::sign(
        CommandId::from_bytes([command; 32]),
        0,
        binding(account, handle, 1),
        account,
    )
    .unwrap()
}

struct LocalTransport<'service, 'store> {
    service: &'service mut RegistryService<'store>,
    accepted_at: u64,
}

impl RegistryTransport for LocalTransport<'_, '_> {
    type Error = RegistryServiceError;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, request: Vec<u8>) -> Self::Exchange<'_> {
        let result = self.service.handle(&request, self.accepted_at);
        self.accepted_at += 1;
        ready(result)
    }
}

#[derive(Debug)]
enum ControlledError {
    Offline,
    Service(RegistryServiceError),
}

impl fmt::Display for ControlledError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offline => formatter.write_str("offline"),
            Self::Service(error) => error.fmt(formatter),
        }
    }
}

impl Error for ControlledError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Offline => None,
            Self::Service(error) => Some(error),
        }
    }
}

struct ControlledTransport<'service, 'store> {
    service: &'service mut RegistryService<'store>,
    offline: Arc<AtomicBool>,
}

impl RegistryTransport for ControlledTransport<'_, '_> {
    type Error = ControlledError;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, request: Vec<u8>) -> Self::Exchange<'_> {
        if self.offline.load(Ordering::SeqCst) {
            ready(Err(ControlledError::Offline))
        } else {
            ready(
                self.service
                    .handle(&request, 200)
                    .map_err(ControlledError::Service),
            )
        }
    }
}

struct NotFoundTransport;

impl RegistryTransport for NotFoundTransport {
    type Error = ControlledError;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, request: Vec<u8>) -> Self::Exchange<'_> {
        let response = decode_request(&request)
            .and_then(|request| {
                encode_response(&RegistryResponse {
                    version: REGISTRY_TRANSPORT_VERSION,
                    request_id: request.request_id,
                    outcome: RegistryResponseOutcome::NotFound,
                })
            })
            .map_err(|error| ControlledError::Service(RegistryServiceError::Protocol(error)));
        ready(response)
    }
}

struct ForgedTransport {
    record: RegistryRecord,
}

impl RegistryTransport for ForgedTransport {
    type Error = ControlledError;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, request: Vec<u8>) -> Self::Exchange<'_> {
        let response = decode_request(&request)
            .and_then(|request| {
                encode_response(&RegistryResponse {
                    version: REGISTRY_TRANSPORT_VERSION,
                    request_id: request.request_id,
                    outcome: RegistryResponseOutcome::Found {
                        record: Box::new(self.record.clone()),
                    },
                })
            })
            .map_err(|error| ControlledError::Service(RegistryServiceError::Protocol(error)));
        ready(response)
    }
}

#[tokio::test]
async fn verified_online_lookup_becomes_explicit_offline_evidence() {
    let service_directory = tempdir().unwrap();
    let cache_directory = tempdir().unwrap();
    let service_store = SealedStore::open(service_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let cache_store = SealedStore::open(cache_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let alice = account(1);
    let alice_claim = claim(&alice, 1, "alice");
    let alice_handle = GlobalHandle::parse("alice").unwrap();
    let nostr_public_key = alice_claim.binding().device_keys.nostr_public_key;
    let mut service = RegistryService::open(&service_store, [90; 32]).unwrap();
    let pinned_key = service.verifying_key();

    let expected_receipt = {
        let transport = LocalTransport {
            service: &mut service,
            accepted_at: 100,
        };
        RegistryClient::new(transport, pinned_key)
            .claim(&alice_claim)
            .await
            .unwrap()
    };
    let offline = Arc::new(AtomicBool::new(false));
    let transport = ControlledTransport {
        service: &mut service,
        offline: Arc::clone(&offline),
    };
    let mut evidence =
        RegistryEvidenceClient::open(transport, &cache_store, pinned_key, 100).unwrap();

    let online = evidence.resolve_handle(&alice_handle, 1_000).await.unwrap();
    assert!(matches!(
        online,
        RegistryEvidenceResolution::Online(RegistryCacheLookup::Fresh(ref cached))
            if cached.record.claim == alice_claim && cached.record.receipt == expected_receipt
    ));
    assert!(matches!(
        evidence.cached_nostr_public_key(&nostr_public_key, 1_001),
        RegistryCacheLookup::Fresh(_)
    ));

    offline.store(true, Ordering::SeqCst);
    let fallback = evidence.resolve_handle(&alice_handle, 1_101).await.unwrap();
    assert!(matches!(
        fallback,
        RegistryEvidenceResolution::Offline {
            cached: RegistryCacheLookup::OfflineStale(_),
            transport_error: ControlledError::Offline
        }
    ));
    drop(evidence);

    let reloaded = VerifiedRegistryCache::load_or_create(&cache_store, pinned_key).unwrap();
    assert!(matches!(
        reloaded.lookup_handle(&alice_handle, 1_101, 100),
        RegistryCacheLookup::OfflineStale(ref cached)
            if cached.record.receipt == expected_receipt
    ));
}

#[tokio::test]
async fn authoritative_not_found_cannot_erase_cached_ownership() {
    let cache_directory = tempdir().unwrap();
    let cache_store = SealedStore::open(cache_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let registry_seed = [91; 32];
    let mut registry = RegistryState::from_signing_seed(registry_seed);
    let pinned_key = registry.verifying_key();
    let alice = account(2);
    let alice_handle = GlobalHandle::parse("alice").unwrap();
    registry.apply(claim(&alice, 1, "alice"), 100).unwrap();
    let record = registry.handle_record(&alice_handle).unwrap().unwrap();
    let mut cache = VerifiedRegistryCache::load_or_create(&cache_store, pinned_key).unwrap();
    cache.observe(&cache_store, record, 1_000).unwrap();

    let mut evidence =
        RegistryEvidenceClient::open(NotFoundTransport, &cache_store, pinned_key, 100).unwrap();
    assert!(matches!(
        evidence.resolve_handle(&alice_handle, 1_001).await,
        Err(RegistryEvidenceError::AuthoritativeRollback)
    ));
    assert!(matches!(
        evidence.cached_handle(&alice_handle, 1_001),
        RegistryCacheLookup::Fresh(_)
    ));
}

#[tokio::test]
async fn forged_online_evidence_is_not_cached_or_used_offline() {
    let cache_directory = tempdir().unwrap();
    let cache_store = SealedStore::open(cache_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let trusted_key = RegistryState::from_signing_seed([92; 32]).verifying_key();
    let alice = account(3);
    let alice_handle = GlobalHandle::parse("alice").unwrap();
    let mut hostile = RegistryState::from_signing_seed([93; 32]);
    hostile.apply(claim(&alice, 1, "alice"), 100).unwrap();
    let forged = hostile.handle_record(&alice_handle).unwrap().unwrap();
    let transport = ForgedTransport {
        record: RegistryRecord::from_record(forged),
    };
    let mut evidence =
        RegistryEvidenceClient::open(transport, &cache_store, trusted_key, 100).unwrap();

    assert!(matches!(
        evidence.resolve_handle(&alice_handle, 1_000).await,
        Err(RegistryEvidenceError::Client(
            RegistryClientError::InvalidReceipt(RegistryError::InvalidReceiptSignature)
        ))
    ));
    assert_eq!(
        evidence.cached_handle(&alice_handle, 1_000),
        RegistryCacheLookup::Missing
    );
    assert!(evidence.cache().is_empty());
}

#[tokio::test]
async fn verified_claim_is_sealed_and_idempotent_replay_refreshes_it() {
    let service_directory = tempdir().unwrap();
    let cache_directory = tempdir().unwrap();
    let service_store = SealedStore::open(service_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let cache_store = SealedStore::open(cache_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&service_store, [94; 32]).unwrap();
    let pinned_key = service.verifying_key();
    let alice_claim = claim(&account(4), 1, "alice");
    let transport = LocalTransport {
        service: &mut service,
        accepted_at: 100,
    };
    let mut evidence =
        RegistryEvidenceClient::open(transport, &cache_store, pinned_key, 100).unwrap();

    let first = evidence.claim_handle(&alice_claim, 1_000).await.unwrap();
    let first_receipt = match first {
        RegistryCacheLookup::Fresh(cached) => cached.record.receipt,
        other => panic!("verified online claim must be fresh, got {other:?}"),
    };
    let replay = evidence.claim_handle(&alice_claim, 1_001).await.unwrap();
    assert!(matches!(
        replay,
        RegistryCacheLookup::Fresh(ref cached)
            if cached.record.receipt == first_receipt && cached.verified_at == 1_001
    ));
    assert_eq!(evidence.cache().len(), 1);
}

#[tokio::test]
async fn claim_transport_failure_is_an_explicit_unknown_outcome() {
    let service_directory = tempdir().unwrap();
    let cache_directory = tempdir().unwrap();
    let service_store = SealedStore::open(service_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let cache_store = SealedStore::open(cache_directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&service_store, [95; 32]).unwrap();
    let pinned_key = service.verifying_key();
    let transport = ControlledTransport {
        service: &mut service,
        offline: Arc::new(AtomicBool::new(true)),
    };
    let mut evidence =
        RegistryEvidenceClient::open(transport, &cache_store, pinned_key, 100).unwrap();

    assert!(matches!(
        evidence
            .claim_handle(&claim(&account(5), 1, "alice"), 1_000)
            .await,
        Err(RegistryEvidenceError::ClaimOutcomeUnknown(
            ControlledError::Offline
        ))
    ));
    assert!(evidence.cache().is_empty());
}
