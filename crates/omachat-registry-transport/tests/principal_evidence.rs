use k256::schnorr::SigningKey as SchnorrSigningKey;
use omachat_crypto::{AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle};
use omachat_registry::{
    CommandId, HandleClaim,
    principal_proof::{
        NostrPrincipalControlPayload, NostrPrincipalControlProof, NostrPrincipalType,
    },
    principal_registry::PrincipalRegistryState,
    proof_bearing_claim::{ProofBearingDeviceHandleClaim, device_authorisation_hash},
};
use omachat_registry_transport::{
    PRINCIPAL_REGISTRY_TRANSPORT_VERSION, PrincipalRegistryClientError,
    PrincipalRegistryEvidenceClient, PrincipalRegistryEvidenceError,
    PrincipalRegistryEvidenceResolution, PrincipalRegistryRecordWire, PrincipalRegistryResponse,
    PrincipalRegistryResponseOutcome, PrincipalRegistryService, PrincipalRegistryServiceError,
    RegistryTransport, encode_principal_response,
};
use omachat_store::{PrincipalRegistryCacheLookup, RequestedProvider, SealedStore};
use std::{convert::Infallible, error::Error, fmt, future::Ready, future::ready};
use tempfile::tempdir;

fn nostr_public_key(secret: &[u8; 32]) -> [u8; 32] {
    SchnorrSigningKey::from_bytes(secret)
        .unwrap()
        .verifying_key()
        .to_bytes()
        .into()
}

fn claim() -> ProofBearingDeviceHandleClaim {
    let account = AccountSecrets::from_seeds([0x11; 32], [0x12; 32]);
    let nostr_secret = [0x31; 32];
    let public_key = nostr_public_key(&nostr_secret);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse("alice").unwrap()),
        Some(DisplayName::parse("Principal Evidence Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: AccountSecrets::from_seeds([0x21; 32], [0x22; 32])
                .public_identity()
                .account_root_public_key,
            noise_public_key: [0x23; 32],
            nostr_public_key: public_key,
        },
        1,
        1_788_000_001,
    );
    let command_id = [0x41; 32];
    let root_claim =
        HandleClaim::sign(CommandId::from_bytes(command_id), 0, binding, &account).unwrap();
    let payload = NostrPrincipalControlPayload::new(
        root_claim.claim_hash(),
        command_id,
        0,
        root_claim.binding().account_id.as_str(),
        "alice",
        NostrPrincipalType::Device,
        public_key,
        device_authorisation_hash(root_claim.binding()),
        1_788_000_002,
    )
    .unwrap();
    let proof = NostrPrincipalControlProof::sign(payload, nostr_secret).unwrap();
    ProofBearingDeviceHandleClaim::new(root_claim, proof).unwrap()
}

struct LocalTransport<'service, 'store> {
    service: &'service mut PrincipalRegistryService<'store>,
    accepted_at: u64,
}

impl RegistryTransport for LocalTransport<'_, '_> {
    type Error = PrincipalRegistryServiceError;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Offline;

impl fmt::Display for Offline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("offline")
    }
}

impl Error for Offline {}

struct OfflineTransport;

impl RegistryTransport for OfflineTransport {
    type Error = Offline;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, _request: Vec<u8>) -> Self::Exchange<'_> {
        ready(Err(Offline))
    }
}

struct FixedTransport(Vec<u8>);

impl RegistryTransport for FixedTransport {
    type Error = Infallible;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, _request: Vec<u8>) -> Self::Exchange<'_> {
        ready(Ok(self.0.clone()))
    }
}

#[tokio::test]
async fn verified_online_evidence_becomes_explicit_offline_state_after_restart() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let key = service.verifying_key();
    let claim = claim();
    let handle = GlobalHandle::parse("alice").unwrap();
    {
        let transport = LocalTransport {
            service: &mut service,
            accepted_at: 1_788_000_003,
        };
        let mut evidence =
            PrincipalRegistryEvidenceClient::open(transport, &store, key, 100).unwrap();
        assert!(matches!(
            evidence.claim_device(&claim, 1_000).await.unwrap(),
            PrincipalRegistryCacheLookup::Fresh(_)
        ));
        let online = evidence.resolve_handle(&handle, 1_001).await.unwrap();
        assert!(online.is_online());
        assert!(matches!(
            online.lookup(),
            PrincipalRegistryCacheLookup::Fresh(_)
        ));
    }

    let mut offline =
        PrincipalRegistryEvidenceClient::open(OfflineTransport, &store, key, 100).unwrap();
    let resolution = offline.resolve_handle(&handle, 1_102).await.unwrap();
    assert!(!resolution.is_online());
    assert!(matches!(
        resolution,
        PrincipalRegistryEvidenceResolution::Offline {
            cached: PrincipalRegistryCacheLookup::OfflineStale(_),
            transport_error: Offline
        }
    ));
}

#[tokio::test]
async fn authoritative_not_found_cannot_erase_cached_principal_ownership() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let key = service.verifying_key();
    let claim = claim();
    {
        let transport = LocalTransport {
            service: &mut service,
            accepted_at: 1_788_000_003,
        };
        let mut evidence =
            PrincipalRegistryEvidenceClient::open(transport, &store, key, 100).unwrap();
        evidence.claim_device(&claim, 1_000).await.unwrap();
    }
    let response = encode_principal_response(&PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: PrincipalRegistryResponseOutcome::NotFound,
    })
    .unwrap();
    let mut evidence =
        PrincipalRegistryEvidenceClient::open(FixedTransport(response), &store, key, 100).unwrap();
    assert!(matches!(
        evidence
            .resolve_handle(&GlobalHandle::parse("alice").unwrap(), 1_001)
            .await,
        Err(PrincipalRegistryEvidenceError::AuthoritativeRollback)
    ));
}

#[tokio::test]
async fn forged_online_evidence_is_terminal_and_never_cached() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let claim = claim();
    let trusted_key = PrincipalRegistryState::from_signing_seed([0x71; 32]).verifying_key();
    let mut hostile = PrincipalRegistryState::from_signing_seed([0x72; 32]);
    let forged = hostile.apply_device(claim, 1_788_000_003).unwrap();
    let response = encode_principal_response(&PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: PrincipalRegistryResponseOutcome::Found {
            record: Box::new(PrincipalRegistryRecordWire::from_record(&forged)),
        },
    })
    .unwrap();
    let handle = GlobalHandle::parse("alice").unwrap();
    let mut evidence =
        PrincipalRegistryEvidenceClient::open(FixedTransport(response), &store, trusted_key, 100)
            .unwrap();
    assert!(matches!(
        evidence.resolve_handle(&handle, 1_000).await,
        Err(PrincipalRegistryEvidenceError::Client(
            PrincipalRegistryClientError::InvalidEvidence(_)
        ))
    ));

    let offline =
        PrincipalRegistryEvidenceClient::open(OfflineTransport, &store, trusted_key, 100).unwrap();
    assert_eq!(
        offline.cached_handle(&handle, 1_001),
        PrincipalRegistryCacheLookup::Missing
    );
}

#[tokio::test]
async fn transport_failure_leaves_claim_outcome_explicitly_unknown() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let key = PrincipalRegistryState::from_signing_seed([0x71; 32]).verifying_key();
    let mut evidence =
        PrincipalRegistryEvidenceClient::open(OfflineTransport, &store, key, 100).unwrap();
    assert!(matches!(
        evidence.claim_device(&claim(), 1_000).await,
        Err(PrincipalRegistryEvidenceError::ClaimOutcomeUnknown(Offline))
    ));
}
