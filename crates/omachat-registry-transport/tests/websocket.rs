use futures_util::{SinkExt, StreamExt};
use omachat_crypto::GlobalHandle;
use omachat_registry::RegistryState;
use omachat_registry_transport::{
    REGISTRY_TRANSPORT_VERSION, RegistryClient, RegistryClientError, RegistryResponse,
    RegistryResponseOutcome, RegistryWebSocketError, RegistryWebSocketTransport, decode_request,
    encode_response,
};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[test]
fn endpoint_policy_requires_tls_except_on_loopback() {
    assert!(RegistryWebSocketTransport::new("wss://registry.omachat.example/v1").is_ok());
    assert!(RegistryWebSocketTransport::new("ws://127.0.0.1:9000/v1").is_ok());
    assert!(RegistryWebSocketTransport::new("ws://[::1]:9000/v1").is_ok());
    assert!(matches!(
        RegistryWebSocketTransport::new("ws://registry.omachat.example/v1"),
        Err(RegistryWebSocketError::InsecureRemoteEndpoint)
    ));
    assert!(matches!(
        RegistryWebSocketTransport::new("https://registry.omachat.example/v1"),
        Err(RegistryWebSocketError::UnsupportedScheme)
    ));
    assert!(matches!(
        RegistryWebSocketTransport::new("wss://token@registry.omachat.example/v1"),
        Err(RegistryWebSocketError::CredentialsNotAllowed)
    ));
    assert!(matches!(
        RegistryWebSocketTransport::new("wss://registry.omachat.example/v1?token=secret"),
        Err(RegistryWebSocketError::QueryOrFragmentNotAllowed)
    ));
}

#[tokio::test]
async fn binary_request_response_roundtrip_preserves_registry_correlation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let message = socket.next().await.unwrap().unwrap();
        let Message::Binary(request) = message else {
            panic!("registry client must send binary frames");
        };
        let request = decode_request(&request).unwrap();
        let response = encode_response(&RegistryResponse {
            version: REGISTRY_TRANSPORT_VERSION,
            request_id: request.request_id,
            outcome: RegistryResponseOutcome::NotFound,
        })
        .unwrap();
        socket.send(Message::Binary(response.into())).await.unwrap();
    });

    let transport =
        RegistryWebSocketTransport::new(&format!("ws://{address}/registry-v1")).unwrap();
    let pinned_key = RegistryState::from_signing_seed([44; 32]).verifying_key();
    let mut client = RegistryClient::new(transport, pinned_key);
    assert!(
        client
            .lookup_handle(&GlobalHandle::parse("nobody").unwrap())
            .await
            .unwrap()
            .is_none()
    );
    server.await.unwrap();
}

#[tokio::test]
async fn text_responses_fail_closed_before_protocol_decode() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        socket.next().await.unwrap().unwrap();
        socket.send(Message::Text("{}".into())).await.unwrap();
    });

    let transport =
        RegistryWebSocketTransport::new(&format!("ws://{address}/registry-v1")).unwrap();
    let pinned_key = RegistryState::from_signing_seed([45; 32]).verifying_key();
    let mut client = RegistryClient::new(transport, pinned_key);
    assert!(matches!(
        client
            .lookup_handle(&GlobalHandle::parse("nobody").unwrap())
            .await,
        Err(RegistryClientError::Transport(
            RegistryWebSocketError::UnexpectedMessage
        ))
    ));
    server.await.unwrap();
}
