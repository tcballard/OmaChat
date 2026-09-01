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
    PRINCIPAL_REGISTRY_TRANSPORT_VERSION, PrincipalRegistryClient, PrincipalRegistryClientError,
    PrincipalRegistryRecordWire, PrincipalRegistryResponse, PrincipalRegistryResponseOutcome,
    PrincipalRegistryService, PrincipalRegistryServiceError, RegistryTransport,
    encode_principal_response,
};
use omachat_store::{RequestedProvider, SealedStore};
use std::{convert::Infallible, future::Ready, future::ready};
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
        Some(DisplayName::parse("Principal Handle Transport Test").unwrap()),
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
        ready(self.service.handle(&request, self.accepted_at))
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
async fn verified_client_resolves_the_exact_proven_handle() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let key = service.verifying_key();
    let transport = LocalTransport {
        service: &mut service,
        accepted_at: 1_788_000_003,
    };
    let mut client = PrincipalRegistryClient::new(transport, key);
    let claim = claim();
    client.claim_device(&claim).await.unwrap();
    let handle = GlobalHandle::parse("alice").unwrap();
    assert_eq!(
        client
            .lookup_handle(&handle)
            .await
            .unwrap()
            .unwrap()
            .claim(),
        &claim
    );
    assert!(
        client
            .lookup_handle(&GlobalHandle::parse("nobody").unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn valid_evidence_for_another_handle_is_rejected() {
    let claim = claim();
    let mut state = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let record = state.apply_device(claim, 1_788_000_003).unwrap();
    let response = encode_principal_response(&PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: PrincipalRegistryResponseOutcome::Found {
            record: Box::new(PrincipalRegistryRecordWire::from_record(&record)),
        },
    })
    .unwrap();
    let mut client = PrincipalRegistryClient::new(FixedTransport(response), state.verifying_key());
    assert!(matches!(
        client
            .lookup_handle(&GlobalHandle::parse("mallory").unwrap())
            .await,
        Err(PrincipalRegistryClientError::LookupMismatch)
    ));
}
