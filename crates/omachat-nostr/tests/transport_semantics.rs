#[path = "support/transport_probe.rs"]
#[allow(dead_code)]
mod transport_probe;

use futures_util::{SinkExt, StreamExt};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    Connector, accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{Request, Response},
    },
};
use transport_probe::{ProbeError, connect_direct_for_test, roundtrip_on_stream};

const TEST_HOST: &str = "relay.invalid";

#[tokio::test]
async fn direct_and_socks_websockets_preserve_tls_name_remote_dns_and_reconnect()
-> Result<(), ProbeError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![TEST_HOST.to_owned()])?;
    let certificate = cert.der().clone();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], signing_key.into())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let connector = Connector::Rustls(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    let relay = TcpListener::bind("127.0.0.1:0").await?;
    let relay_address = relay.local_addr()?;
    let expected_host = format!("{TEST_HOST}:{}", relay_address.port());
    let relay_task = tokio::spawn(serve_echo(relay, server_config, expected_host, 4));
    let proxy = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy.local_addr()?;
    let (host_sender, mut host_receiver) = mpsc::channel(2);
    let proxy_task = tokio::spawn(serve_socks5(proxy, relay_address, host_sender, 2));
    let url = format!("wss://{TEST_HOST}:{}/probe", relay_address.port());

    for attempt in 0..2 {
        let stream = connect_direct_for_test(relay_address).await?;
        roundtrip_on_stream(
            &url,
            stream,
            connector.clone(),
            &format!("direct-{attempt}"),
        )
        .await?;
    }
    for attempt in 0..2 {
        let stream = tokio_socks::tcp::Socks5Stream::connect(
            proxy_address,
            (TEST_HOST, relay_address.port()),
        )
        .await?;
        roundtrip_on_stream(&url, stream, connector.clone(), &format!("socks-{attempt}")).await?;
    }
    let mut observed = Vec::new();
    while let Some(host) = host_receiver.recv().await {
        observed.push(host);
        if observed.len() == 2 {
            break;
        }
    }
    assert_eq!(observed, vec![TEST_HOST, TEST_HOST]);
    proxy_task.await??;
    relay_task.await??;
    Ok(())
}

#[allow(clippy::result_large_err)]
async fn serve_echo(
    listener: TcpListener,
    config: ServerConfig,
    expected_host: String,
    count: usize,
) -> Result<(), ProbeError> {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    for _ in 0..count {
        let (stream, _) = listener.accept().await?;
        let tls = acceptor.accept(stream).await?;
        assert_eq!(tls.get_ref().1.server_name(), Some(TEST_HOST));
        let expected_host = expected_host.clone();
        let mut websocket = accept_hdr_async(tls, move |request: &Request, response: Response| {
            assert_eq!(
                request.headers().get("host").and_then(|v| v.to_str().ok()),
                Some(expected_host.as_str())
            );
            Ok(response)
        })
        .await?;
        if let Some(message) = websocket.next().await {
            let message = message?;
            assert!(matches!(message, Message::Text(_)));
            websocket.send(message).await?;
        }
    }
    Ok(())
}

async fn serve_socks5(
    listener: TcpListener,
    relay: SocketAddr,
    sender: mpsc::Sender<String>,
    count: usize,
) -> Result<(), ProbeError> {
    for _ in 0..count {
        let (mut client, _) = listener.accept().await?;
        let mut greeting = [0_u8; 2];
        client.read_exact(&mut greeting).await?;
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0_u8; usize::from(greeting[1])];
        client.read_exact(&mut methods).await?;
        assert!(methods.contains(&0));
        client.write_all(&[5, 0]).await?;
        let mut request = [0_u8; 4];
        client.read_exact(&mut request).await?;
        assert_eq!(request, [5, 1, 0, 3]);
        let length = client.read_u8().await?;
        let mut host = vec![0_u8; usize::from(length)];
        client.read_exact(&mut host).await?;
        let host = String::from_utf8(host)?;
        assert_eq!(client.read_u16().await?, relay.port());
        sender.send(host).await?;
        let mut upstream = TcpStream::connect(relay).await?;
        let port = relay.port().to_be_bytes();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    }
    Ok(())
}
