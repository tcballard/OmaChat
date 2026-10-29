use crate::{
    protocol::{ErrorCode, ServerError},
    service::{ServiceHandle, ServiceRequest},
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const MAX_REQUEST_BYTES: usize = 8 * 1024;

pub async fn serve(mut stream: TcpStream, service: ServiceHandle) {
    let _ = timeout(Duration::from_secs(5), async {
        let mut buffer = Vec::with_capacity(1024);
        while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            if buffer.len() >= MAX_REQUEST_BYTES {
                write_response(&mut stream, 400, &json!({"names": {}})).await?;
                return Ok::<(), std::io::Error>(());
            }
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let head = String::from_utf8_lossy(&buffer);
        let request_line = head.lines().next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        if method == "OPTIONS" {
            write_options(&mut stream).await?;
            return Ok(());
        }
        if method != "GET" && method != "HEAD" {
            write_response(&mut stream, 405, &json!({"names": {}})).await?;
            return Ok(());
        }
        let name = query_name(target);
        let (status, body) = match name {
            Err(()) => (400, json!({"names": {}})),
            Ok(name) => match service.call(ServiceRequest::Nip05 { name }).await {
                Ok(document) => (200, document),
                Err(error) => (status_for(&error), json!({"names": {}})),
            },
        };
        if method == "HEAD" {
            write_head(&mut stream, status, 0).await?;
        } else {
            write_response(&mut stream, status, &body).await?;
        }
        Ok(())
    })
    .await;
}

fn status_for(error: &ServerError) -> u16 {
    match error.code {
        ErrorCode::NotFound => 404,
        ErrorCode::InvalidName | ErrorCode::InvalidRequest => 400,
        _ => 500,
    }
}

fn query_name(target: &str) -> Result<String, ()> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/.well-known/nostr.json" {
        return Err(());
    }
    let mut name = None;
    if !query.is_empty() {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key == "name" {
                name = Some(percent_decode(value)?);
            }
        }
    }
    name.ok_or(())
}

fn percent_decode(value: &str) -> Result<String, ()> {
    let mut output = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => output.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).map_err(|_| ())?;
                output.push(u8::from_str_radix(hex, 16).map_err(|_| ())?);
                index += 2;
            }
            b'%' => return Err(()),
            byte => output.push(byte),
        }
        index += 1;
    }
    String::from_utf8(output).map_err(|_| ())
}

async fn write_response(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let encoded = body.to_string();
    write_head(stream, status, encoded.len()).await?;
    stream.write_all(encoded.as_bytes()).await?;
    stream.flush().await
}

async fn write_head(stream: &mut TcpStream, status: u16, length: usize) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {length}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await
}

async fn write_options(stream: &mut TcpStream) -> std::io::Result<()> {
    let head = "HTTP/1.1 204 No Content\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await
}

#[must_use]
pub fn is_nip05_request(head: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 3] = [
        b"GET /.well-known/nostr.json",
        b"HEAD /.well-known/nostr.json",
        b"OPTIONS /.well-known/nostr.json",
    ];
    PREFIXES.iter().any(|prefix| head.starts_with(prefix))
}
