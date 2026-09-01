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

fn validated_claim(
    account_seed: u8,
    nostr_secret: [u8; 32],
    command: u8,
    handle: &str,
) -> ProofBearingDeviceHandleClaim {
    let account = AccountSecrets::from_seeds([account_seed; 32], [account_seed + 1; 32]);
    let public_key = nostr_public_key(&nostr_secret);
    let device_signer = AccountSecrets::from_seeds([account_seed + 2; 32], [account_seed + 3; 32]);
    let binding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Principal Client Test").unwrap()),
        DevicePublicKeys {
            signing_public_key: device_signer.public_identity().account_root_public_key,
            noise_public_key: [account_seed + 4; 32],
            nostr_public_key: public_key,
        },
        1,
        1_788_000_001,
    );
    let command_id = [command; 32];
    let root_claim =
        HandleClaim::sign(CommandId::from_bytes(command_id), 0, binding, &account).unwrap();
    let payload = NostrPrincipalControlPayload::new(
        root_claim.claim_hash(),
        command_id,
        0,
        root_claim.binding().account_id.as_str(),
        handle,
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

struct FixedTransport {
    response: Vec<u8>,
}

impl RegistryTransport for FixedTransport {
    type Error = Infallible;
    type Exchange<'a>
        = Ready<Result<Vec<u8>, Self::Error>>
    where
        Self: 'a;

    fn exchange(&mut self, _request: Vec<u8>) -> Self::Exchange<'_> {
        ready(Ok(self.response.clone()))
    }
}

#[tokio::test]
async fn verified_client_claims_and_resolves_exact_principals() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = PrincipalRegistryService::open(&store, [0x71; 32], None).unwrap();
    let pinned_key = service.verifying_key();
    let transport = LocalTransport {
        service: &mut service,
        accepted_at: 1_788_000_003,
    };
    let mut client = PrincipalRegistryClient::new(transport, pinned_key);
    let alice = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let public_key = alice.principal_proof().payload().nostr_public_key();
    let account_id = alice.claim().binding().account_id.clone();
    assert_eq!(client.claim_device(&alice).await.unwrap().claim(), &alice);
    assert_eq!(
        client
            .lookup_public_key(&public_key)
            .await
            .unwrap()
            .unwrap()
            .claim(),
        &alice
    );
    assert_eq!(
        client
            .lookup_account(&account_id)
            .await
            .unwrap()
            .unwrap()
            .claim(),
        &alice
    );
    assert!(
        client
            .lookup_public_key(&nostr_public_key(&[0x32; 32]))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn client_rejects_forged_evidence_and_query_mismatch() {
    let alice = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let trusted_key = PrincipalRegistryState::from_signing_seed([0x71; 32]).verifying_key();
    let mut hostile = PrincipalRegistryState::from_signing_seed([0x72; 32]);
    let forged = hostile.apply_device(alice.clone(), 1_788_000_003).unwrap();
    let response = encode_principal_response(&PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: PrincipalRegistryResponseOutcome::Accepted {
            record: Box::new(PrincipalRegistryRecordWire::from_record(&forged)),
        },
    })
    .unwrap();
    let mut client = PrincipalRegistryClient::new(FixedTransport { response }, trusted_key);
    assert!(matches!(
        client.claim_device(&alice).await,
        Err(PrincipalRegistryClientError::InvalidEvidence(_))
    ));

    let mut trusted = PrincipalRegistryState::from_signing_seed([0x71; 32]);
    let record = trusted.apply_device(alice, 1_788_000_003).unwrap();
    let response = encode_principal_response(&PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: PrincipalRegistryResponseOutcome::Found {
            record: Box::new(PrincipalRegistryRecordWire::from_record(&record)),
        },
    })
    .unwrap();
    let mut client = PrincipalRegistryClient::new(FixedTransport { response }, trusted_key);
    assert!(matches!(
        client
            .lookup_public_key(&nostr_public_key(&[0x32; 32]))
            .await,
        Err(PrincipalRegistryClientError::LookupMismatch)
    ));
}

#[tokio::test]
async fn client_rejects_correlation_and_outcome_confusion() {
    let claim = validated_claim(0x11, [0x31; 32], 0x41, "alice");
    let key = PrincipalRegistryState::from_signing_seed([0x71; 32]).verifying_key();
    let response = encode_principal_response(&PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 99,
        outcome: PrincipalRegistryResponseOutcome::NotFound,
    })
    .unwrap();
    let mut client = PrincipalRegistryClient::new(FixedTransport { response }, key);
    assert!(matches!(
        client.claim_device(&claim).await,
        Err(PrincipalRegistryClientError::CorrelationMismatch {
            expected: 1,
            actual: 99
        })
    ));

    let response = encode_principal_response(&PrincipalRegistryResponse {
        version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: PrincipalRegistryResponseOutcome::NotFound,
    })
    .unwrap();
    let mut client = PrincipalRegistryClient::new(FixedTransport { response }, key);
    assert!(matches!(
        client.claim_device(&claim).await,
        Err(PrincipalRegistryClientError::UnexpectedOutcome)
    ));
}
