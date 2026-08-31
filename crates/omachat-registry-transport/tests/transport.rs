use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
    SignedLocalAccountBinding,
};
use omachat_registry::{CommandId, HandleClaim, RegistryError, RegistryState};
use omachat_registry_transport::{
    MAX_REGISTRY_MESSAGE_BYTES, REGISTRY_TRANSPORT_VERSION, RegistryClient, RegistryClientError,
    RegistryProtocolError, RegistryRecord, RegistryRemoteCode, RegistryRequest, RegistryResponse,
    RegistryResponseOutcome, RegistryService, RegistryServiceError, RegistryTransport,
    decode_request, encode_response,
};
use omachat_store::{RequestedProvider, SealedStore};
use std::{convert::Infallible, future::Ready, future::ready};
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
        Some(DisplayName::parse("Transport Test").unwrap()),
        device_keys(revision as u8),
        revision,
        1_788_000_000 + revision,
    )
}

fn claim(
    account: &AccountSecrets,
    command: u8,
    handle: &str,
    expected_revision: u64,
) -> HandleClaim {
    HandleClaim::sign(
        CommandId::from_bytes([command; 32]),
        expected_revision,
        binding(account, handle, expected_revision + 1),
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
async fn verified_claim_is_durable_and_idempotent_across_restart() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let alice = account(1);
    let alice_claim = claim(&alice, 1, "alice", 0);
    let first_receipt;

    {
        let mut service = RegistryService::open(&store, [90; 32]).unwrap();
        let pinned_key = service.verifying_key();
        let transport = LocalTransport {
            service: &mut service,
            accepted_at: 100,
        };
        let mut client = RegistryClient::new(transport, pinned_key);
        first_receipt = client.claim(&alice_claim).await.unwrap();
        let replay = client.claim(&alice_claim).await.unwrap();
        assert_eq!(replay, first_receipt);
    }

    let mut restarted = RegistryService::open(&store, [90; 32]).unwrap();
    let pinned_key = restarted.verifying_key();
    let transport = LocalTransport {
        service: &mut restarted,
        accepted_at: 200,
    };
    let mut client = RegistryClient::new(transport, pinned_key);
    assert_eq!(client.claim(&alice_claim).await.unwrap(), first_receipt);
}

#[tokio::test]
async fn verified_handle_and_account_lookups_survive_restart() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let alice = account(1);
    let alice_id = alice.public_identity().account_id;
    let alice_handle = GlobalHandle::parse("alice").unwrap();
    let alice_claim = claim(&alice, 1, "alice", 0);
    let receipt;

    {
        let mut service = RegistryService::open(&store, [90; 32]).unwrap();
        let pinned_key = service.verifying_key();
        let transport = LocalTransport {
            service: &mut service,
            accepted_at: 100,
        };
        let mut client = RegistryClient::new(transport, pinned_key);
        receipt = client.claim(&alice_claim).await.unwrap();
    }

    let mut restarted = RegistryService::open(&store, [90; 32]).unwrap();
    let pinned_key = restarted.verifying_key();
    let transport = LocalTransport {
        service: &mut restarted,
        accepted_at: 200,
    };
    let mut client = RegistryClient::new(transport, pinned_key);

    let by_handle = client.lookup_handle(&alice_handle).await.unwrap().unwrap();
    assert_eq!(by_handle.claim, alice_claim);
    assert_eq!(by_handle.receipt, receipt);
    let by_account = client.lookup_account(&alice_id).await.unwrap().unwrap();
    assert_eq!(by_account, by_handle);

    assert!(
        client
            .lookup_handle(&GlobalHandle::parse("nobody").unwrap())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .lookup_account(&account(9).public_identity().account_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn duplicate_handle_rejection_crosses_the_adapter_without_mutation() {
    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [90; 32]).unwrap();
    let pinned_key = service.verifying_key();
    let transport = LocalTransport {
        service: &mut service,
        accepted_at: 100,
    };
    let mut client = RegistryClient::new(transport, pinned_key);
    let alice_receipt = client
        .claim(&claim(&account(1), 1, "alice", 0))
        .await
        .unwrap();
    let rejected = client
        .claim(&claim(&account(3), 2, "alice", 0))
        .await
        .unwrap_err();
    assert!(matches!(
        rejected,
        RegistryClientError::Rejected(error) if error.code == RegistryRemoteCode::HandleTaken
    ));
    assert_eq!(client.into_transport().service.verifying_key(), pinned_key);
    assert_eq!(alice_receipt.sequence, 1);
}

#[tokio::test]
async fn client_rejects_forged_and_mismatched_responses() {
    let alice = account(1);
    let alice_claim = claim(&alice, 1, "alice", 0);
    let trusted_key = RegistryState::from_signing_seed([90; 32]).verifying_key();
    let mut hostile_registry = RegistryState::from_signing_seed([91; 32]);
    let forged = hostile_registry.apply(alice_claim.clone(), 100).unwrap();
    let forged_response = encode_response(&RegistryResponse {
        version: REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: RegistryResponseOutcome::Accepted {
            receipt: Box::new(forged),
        },
    })
    .unwrap();
    let mut forged_client = RegistryClient::new(
        FixedTransport {
            response: forged_response,
        },
        trusted_key,
    );
    assert!(matches!(
        forged_client.claim(&alice_claim).await,
        Err(RegistryClientError::InvalidReceipt(
            RegistryError::InvalidReceiptSignature
        ))
    ));

    let mismatched_response = encode_response(&RegistryResponse {
        version: REGISTRY_TRANSPORT_VERSION,
        request_id: 99,
        outcome: RegistryResponseOutcome::Accepted {
            receipt: Box::new(hostile_registry.head().unwrap().clone()),
        },
    })
    .unwrap();
    let mut mismatched_client = RegistryClient::new(
        FixedTransport {
            response: mismatched_response,
        },
        trusted_key,
    );
    assert!(matches!(
        mismatched_client.claim(&alice_claim).await,
        Err(RegistryClientError::CorrelationMismatch {
            expected: 1,
            actual: 99
        })
    ));
}

#[tokio::test]
async fn client_rejects_forged_and_query_mismatched_lookup_records() {
    let alice = account(1);
    let alice_claim = claim(&alice, 1, "alice", 0);
    let trusted_key = RegistryState::from_signing_seed([90; 32]).verifying_key();
    let mut hostile_registry = RegistryState::from_signing_seed([91; 32]);
    hostile_registry.apply(alice_claim.clone(), 100).unwrap();
    let forged_record = hostile_registry
        .handle_record(&GlobalHandle::parse("alice").unwrap())
        .unwrap()
        .unwrap();
    let response = encode_response(&RegistryResponse {
        version: REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: RegistryResponseOutcome::Found {
            record: Box::new(RegistryRecord::from_record(forged_record)),
        },
    })
    .unwrap();
    let mut client = RegistryClient::new(FixedTransport { response }, trusted_key);
    assert!(matches!(
        client
            .lookup_handle(&GlobalHandle::parse("alice").unwrap())
            .await,
        Err(RegistryClientError::InvalidReceipt(
            RegistryError::InvalidReceiptSignature
        ))
    ));

    let mut trusted_registry = RegistryState::from_signing_seed([90; 32]);
    trusted_registry.apply(alice_claim, 100).unwrap();
    let valid_record = trusted_registry
        .handle_record(&GlobalHandle::parse("alice").unwrap())
        .unwrap()
        .unwrap();
    let response = encode_response(&RegistryResponse {
        version: REGISTRY_TRANSPORT_VERSION,
        request_id: 1,
        outcome: RegistryResponseOutcome::Found {
            record: Box::new(RegistryRecord::from_record(valid_record)),
        },
    })
    .unwrap();
    let mut client = RegistryClient::new(FixedTransport { response }, trusted_key);
    assert!(matches!(
        client
            .lookup_handle(&GlobalHandle::parse("bob").unwrap())
            .await,
        Err(RegistryClientError::LookupMismatch)
    ));
}

#[tokio::test]
async fn protocol_rejects_unknown_fields_malformed_and_oversized_messages() {
    let request = RegistryRequest::claim(1, &claim(&account(1), 1, "alice", 0));
    let mut value = serde_json::to_value(request).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert_eq!(
        decode_request(&serde_json::to_vec(&value).unwrap()),
        Err(RegistryProtocolError::Malformed)
    );
    assert_eq!(decode_request(b"{"), Err(RegistryProtocolError::Malformed));
    assert_eq!(
        decode_request(&vec![0_u8; MAX_REGISTRY_MESSAGE_BYTES + 1]),
        Err(RegistryProtocolError::MessageTooLarge)
    );

    let temporary = tempdir().unwrap();
    let store = SealedStore::open(temporary.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [90; 32]).unwrap();
    assert!(matches!(
        service.handle(b"not-json", 100),
        Err(RegistryServiceError::Protocol(
            RegistryProtocolError::Malformed
        ))
    ));
}
