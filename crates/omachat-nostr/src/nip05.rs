//! NIP-05 handle resolution (`name@domain` → secp256k1 public key).
//!
//! The URL is derived only from the handle. Callers cannot supply an arbitrary
//! address. Plain HTTP is accepted only for a numeric-loopback base used by
//! tests; public handles are always `https://<domain>/.well-known/nostr.json`.

use crate::nip11::{RelayInformationError, fetch_http_document};
use k256::schnorr::VerifyingKey;
use serde_json::Value;
use std::{error::Error, fmt, time::Duration};
use url::Url;

const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedNip05 {
    pub name: String,
    pub domain: String,
    pub public_key: [u8; 32],
}

pub async fn resolve_handle(
    handle: &str,
    loopback_base: Option<&str>,
) -> Result<ResolvedNip05, Nip05Error> {
    let (name, domain) = parse_handle(handle)?;
    let url = match loopback_base {
        Some(base) => loopback_url(base, &name)?,
        None => {
            validate_public_domain(&domain)?;
            format!("https://{domain}/.well-known/nostr.json?name={name}")
        }
    };
    let body = fetch_http_document(&url, "application/json", MAX_DOCUMENT_BYTES, TIMEOUT)
        .await
        .map_err(Nip05Error::Fetch)?;
    let public_key = public_key_from_document(&body, &name)?;
    Ok(ResolvedNip05 {
        name,
        domain,
        public_key,
    })
}

pub fn parse_handle(handle: &str) -> Result<(String, String), Nip05Error> {
    if handle.len() > 320 || handle.chars().any(char::is_whitespace) {
        return Err(Nip05Error::InvalidHandle);
    }
    let Some((name, domain)) = handle.split_once('@') else {
        return Err(Nip05Error::InvalidHandle);
    };
    if name.is_empty()
        || domain.is_empty()
        || name.contains('@')
        || domain.contains('@')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(Nip05Error::InvalidHandle);
    }
    Ok((name.to_ascii_lowercase(), domain.to_ascii_lowercase()))
}

fn validate_public_domain(domain: &str) -> Result<(), Nip05Error> {
    if domain.len() > 253
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || domain.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(Nip05Error::InvalidHandle);
    }
    Ok(())
}

fn loopback_url(base: &str, name: &str) -> Result<String, Nip05Error> {
    let parsed = Url::parse(base).map_err(|_| Nip05Error::InvalidHandle)?;
    let loopback = parsed.scheme() == "http"
        && match parsed.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
    if !loopback || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Nip05Error::InvalidHandle);
    }
    let mut url = parsed;
    url.set_path("/.well-known/nostr.json");
    url.query_pairs_mut().append_pair("name", name);
    Ok(url.to_string())
}

fn public_key_from_document(body: &[u8], name: &str) -> Result<[u8; 32], Nip05Error> {
    let document: Value = serde_json::from_slice(body).map_err(|_| Nip05Error::Malformed)?;
    let names = document
        .get("names")
        .and_then(Value::as_object)
        .ok_or(Nip05Error::Malformed)?;
    let encoded = names
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .ok_or(Nip05Error::NotFound)?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Nip05Error::Malformed);
    }
    let mut public_key = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut public_key).map_err(|_| Nip05Error::Malformed)?;
    VerifyingKey::from_bytes(&public_key).map_err(|_| Nip05Error::Malformed)?;
    Ok(public_key)
}

#[derive(Debug)]
pub enum Nip05Error {
    InvalidHandle,
    NotFound,
    Malformed,
    Fetch(RelayInformationError),
}

impl fmt::Display for Nip05Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandle => formatter.write_str("handle must look like name@domain"),
            Self::NotFound => formatter.write_str("that name is not in the NIP-05 document"),
            Self::Malformed => formatter.write_str("NIP-05 document is malformed"),
            Self::Fetch(error) => write!(formatter, "NIP-05 lookup failed: {error}"),
        }
    }
}

impl Error for Nip05Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Fetch(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
    };

    #[test]
    fn parses_and_rejects_handles() {
        assert_eq!(
            parse_handle("Alice@Example.COM").unwrap(),
            ("alice".into(), "example.com".into())
        );
        for bad in ["alice", "a b@example.com", "@example.com", "alice@"] {
            assert!(parse_handle(bad).is_err(), "{bad}");
        }
        assert!(validate_public_domain("example.com").is_ok());
        for bad in ["localhost", "b", "127.0.0.1", ".example.com"] {
            assert!(validate_public_domain(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn resolves_a_loopback_document_and_rejects_a_missing_name() {
        let secret = SigningKey::from_bytes(&[11_u8; 32]).unwrap();
        let public_key = secret.verifying_key().to_bytes();
        let hex_key = hex::encode(public_key);
        let body = format!(r#"{{"names":{{"alice":"{hex_key}","bob":"00"}}}}"#);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, mut stopped) = oneshot::channel();
        let response = Arc::new(body);
        let server = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.unwrap();
                        let payload = Arc::clone(&response);
                        tokio::spawn(async move {
                            let mut buffer = [0_u8; 1024];
                            let _ = stream.read(&mut buffer).await;
                            let message = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                payload.len(),
                                payload
                            );
                            let _ = stream.write_all(message.as_bytes()).await;
                        });
                    }
                }
            }
        });
        let base = format!("http://{address}");
        let resolved = resolve_handle("alice@example.com", Some(&base))
            .await
            .unwrap();
        assert_eq!(resolved.public_key.as_slice(), public_key.as_slice());
        assert!(matches!(
            resolve_handle("carol@example.com", Some(&base)).await,
            Err(Nip05Error::NotFound)
        ));
        assert!(matches!(
            resolve_handle("bob@example.com", Some(&base)).await,
            Err(Nip05Error::Malformed)
        ));
        let _ = stop.send(());
        server.await.unwrap();
    }
}
