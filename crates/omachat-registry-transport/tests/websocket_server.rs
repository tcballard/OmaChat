use futures_util::{SinkExt, StreamExt};
use omachat_crypto::{
    AccountSecrets, DevicePublicKeys, DisplayName, GlobalHandle, IdentitySecrets,
    SignedLocalAccountBinding,
};
use omachat_registry::{CommandId, HandleClaim};
use omachat_registry_transport::{
    MAX_REGISTRY_REQUESTS_PER_CONNECTION, RegistryClient, RegistryRequest, RegistryService,
    RegistryWebSocketServerError, RegistryWebSocketTransport, accept_registry_websocket_request,
    decode_response, encode_request, serve_registry_websocket_connection,
};
use omachat_store::{RequestedProvider, SealedStore};
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message};

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

fn claim(account: &AccountSecrets, command: u8, handle: &str) -> HandleClaim {
    let binding: SignedLocalAccountBinding = account.sign_local_binding(
        Some(GlobalHandle::parse(handle).unwrap()),
        Some(DisplayName::parse("Server Test").unwrap()),
        device_keys(1),
        1,
        1_788_000_001,
    );
    HandleClaim::sign(CommandId::from_bytes([command; 32]), 0, binding, account).unwrap()
}

#[tokio::test]
async fn live_claim_and_lookup_cross_the_bounded_websocket_adapter() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [90; 32]).unwrap();
    let pinned_key = service.verifying_key();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}/registry-v1", listener.local_addr().unwrap());
    let transport = RegistryWebSocketTransport::new(&endpoint).unwrap();
    let mut client = RegistryClient::new(transport, pinned_key);
    let alice = account(1);
    let alice_claim = claim(&alice, 1, "alice");

    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        serve_registry_websocket_connection(stream, &mut service, || 100).await
    };
    let (served, claimed) = tokio::join!(server, client.claim(&alice_claim));
    served.unwrap();
    let receipt = claimed.unwrap();

    let alice_handle = GlobalHandle::parse("alice").unwrap();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        serve_registry_websocket_connection(stream, &mut service, || 101).await
    };
    let (served, found) = tokio::join!(server, client.lookup_handle(&alice_handle));
    served.unwrap();
    let found = found.unwrap().unwrap();
    assert_eq!(found.claim, alice_claim);
    assert_eq!(found.receipt, receipt);
}

#[tokio::test]
async fn text_requests_fail_before_reaching_registry_state() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [91; 32]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}/registry-v1", listener.local_addr().unwrap());

    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        serve_registry_websocket_connection(stream, &mut service, || 100).await
    };
    let client = async {
        let (mut socket, _) = connect_async(&endpoint).await.unwrap();
        socket.send(Message::Text("{}".into())).await.unwrap();
    };
    let (served, ()) = tokio::join!(server, client);
    assert!(matches!(
        served,
        Err(RegistryWebSocketServerError::UnexpectedMessage)
    ));
    assert!(service.is_available());
}

#[tokio::test]
async fn request_admission_does_not_borrow_authoritative_state() {
    let directory = tempdir().unwrap();
    let store = SealedStore::open(directory.path(), RequestedProvider::File)
        .await
        .unwrap();
    let mut service = RegistryService::open(&store, [92; 32]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}/registry-v1", listener.local_addr().unwrap());

    assert_eq!(MAX_REGISTRY_REQUESTS_PER_CONNECTION, 1);
    let client = tokio::spawn(async move {
        let (mut socket, _) = connect_async(&endpoint).await.unwrap();
        let handle = GlobalHandle::parse("nobody").unwrap();
        let request = encode_request(&RegistryRequest::lookup_handle(1, handle)).unwrap();
        socket.send(Message::Binary(request.into())).await.unwrap();
        socket
    });

    let (stream, _) = listener.accept().await.unwrap();
    let pending = accept_registry_websocket_request(stream).await.unwrap();
    let response = service.handle(pending.request(), 100).unwrap();
    let mut socket = client.await.unwrap();
    let (responded, message) = tokio::join!(pending.respond(response), socket.next());
    responded.unwrap();
    let Message::Binary(response) = message.unwrap().unwrap() else {
        panic!("registry server must return a binary response");
    };
    assert_eq!(decode_response(&response).unwrap().request_id, 1);
    assert!(service.is_available());
}
