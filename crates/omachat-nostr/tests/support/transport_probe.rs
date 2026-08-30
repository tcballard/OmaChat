use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::{error::Error, net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{
    Connector, WebSocketStream, client_async_tls_with_config, connect_async, tungstenite::Message,
};
use url::Url;

pub type ProbeError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug)]
pub enum Route<'a> {
    Direct,
    Socks5(&'a str),
}

#[derive(Debug, Serialize)]
pub struct ProbeResult {
    pub url: String,
    pub route: &'static str,
    pub attempts: usize,
    pub remote_dns: bool,
    pub tls_server_name: String,
    pub reconnect: &'static str,
}

pub async fn run_probe<'a>(
    url: &'a str,
    route: Route<'a>,
    attempts: usize,
) -> Result<ProbeResult, ProbeError> {
    if attempts < 2 {
        return Err("at least two attempts are required to prove reconnect".into());
    }
    let parsed = Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or("WebSocket URL must contain a host")?;
    let port = parsed
        .port_or_known_default()
        .ok_or("WebSocket URL must contain a known port")?;
    if !matches!(parsed.scheme(), "ws" | "wss") {
        return Err("transport probe accepts only ws:// or wss:// URLs".into());
    }
    for attempt in 0..attempts {
        let payload = format!("omachat-g0-probe-{attempt}");
        match route {
            Route::Direct => {
                let (socket, _) = tokio::time::timeout(Duration::from_secs(20), connect_async(url))
                    .await
                    .map_err(|_| "direct WebSocket connection timed out")??;
                exchange(socket, &payload).await?;
            }
            Route::Socks5(proxy) => {
                let stream = tokio::time::timeout(
                    Duration::from_secs(20),
                    Socks5Stream::connect(proxy, (host, port)),
                )
                .await
                .map_err(|_| "SOCKS5 connection timed out")??;
                let (socket, _) = tokio::time::timeout(
                    Duration::from_secs(20),
                    client_async_tls_with_config(url, stream, None, None),
                )
                .await
                .map_err(|_| "WebSocket-over-SOCKS5 handshake timed out")??;
                exchange(socket, &payload).await?;
            }
        }
    }
    Ok(ProbeResult {
        url: url.to_owned(),
        route: if matches!(route, Route::Direct) {
            "direct"
        } else {
            "socks5"
        },
        attempts,
        remote_dns: matches!(route, Route::Socks5(_)),
        tls_server_name: host.to_owned(),
        reconnect: "passed",
    })
}

pub async fn roundtrip_on_stream<S>(
    url: &str,
    stream: S,
    connector: Connector,
    payload: &str,
) -> Result<(), ProbeError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (socket, _) = client_async_tls_with_config(url, stream, None, Some(connector)).await?;
    exchange(socket, payload).await
}

async fn exchange<S>(mut socket: WebSocketStream<S>, payload: &str) -> Result<(), ProbeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    socket
        .send(Message::Text(payload.to_owned().into()))
        .await?;
    let reply = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .map_err(|_| "WebSocket echo timed out")?
        .ok_or("WebSocket closed before echo")??;
    if reply != Message::Text(payload.to_owned().into()) {
        return Err(format!("unexpected WebSocket echo: {reply:?}").into());
    }
    socket.close(None).await?;
    Ok(())
}

pub async fn connect_direct_for_test(
    address: SocketAddr,
) -> Result<tokio::net::TcpStream, ProbeError> {
    Ok(tokio::net::TcpStream::connect(address).await?)
}
