use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{error::Error, fmt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
const JSON_TEXT_ENVELOPE_ALLOWANCE_BYTES: usize = 4 * 1024;
pub const MAX_ENCODED_TEXT_BYTES: usize = MAX_TEXT_BYTES + JSON_TEXT_ENVELOPE_ALLOWANCE_BYTES;
const RESPONSE_ENVELOPE_ALLOWANCE_BYTES: usize = 1024;
pub const MAX_RESULT_BYTES: usize = MAX_FRAME_BYTES - RESPONSE_ENVELOPE_ALLOWANCE_BYTES;

const _: () = {
    assert!(MAX_ENCODED_TEXT_BYTES < MAX_FRAME_BYTES);
    assert!(MAX_RESULT_BYTES < MAX_FRAME_BYTES);
};
pub const MAX_PAGE_ITEMS: u32 = 32;
pub const MAX_REQUEST_ID_BYTES: usize = 64;
pub const MAX_CLIENT_ID_BYTES: usize = 64;
pub const MAX_NAME_BYTES: usize = 64;
pub const MAX_INVITE_CODE_BYTES: usize = 128;
pub const DEFAULT_HISTORY_LIMIT: u32 = 50;
pub const MAX_HISTORY_LIMIT: u32 = 200;

pub const EVENT_MESSAGE: &str = "message";
pub const EVENT_RECEIPT: &str = "receipt";
pub const EVENT_CONVERSATION: &str = "conversation";
pub const EVENT_LAGGED: &str = "lagged";

pub const AUTH_DOMAIN: &[u8] = b"omachat-server-auth-v1\0";
pub const HELLO_DOMAIN: &[u8] = b"omachat-server-hello-v1\0";
pub const KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
/// Domain separator for a Nostr handle binding. Both the device Ed25519 key
/// and the Nostr BIP-340 key sign this transcript.
pub const NOSTR_BIND_DOMAIN: &[u8] = b"omachat-nostr-bind-v1\0";
/// Domain separator for detaching a Nostr key. Only the device key signs it,
/// so a lost `nsec` can still be unbound.
pub const NOSTR_UNBIND_DOMAIN: &[u8] = b"omachat-nostr-unbind-v1\0";
/// Proofs older or newer than this many seconds are rejected.
pub const NOSTR_PROOF_SKEW_SECONDS: u64 = 300;

#[must_use]
pub fn hello_transcript(
    challenge: &[u8; KEY_BYTES],
    device_public_key: &[u8; KEY_BYTES],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(HELLO_DOMAIN.len() + 2 * KEY_BYTES);
    transcript.extend_from_slice(HELLO_DOMAIN);
    transcript.extend_from_slice(challenge);
    transcript.extend_from_slice(device_public_key);
    transcript
}

/// Bytes the device signs to authenticate. Binding the server key means a
/// signature obtained for one server is useless against another.
#[must_use]
pub fn auth_transcript(
    server_public_key: &[u8; KEY_BYTES],
    challenge: &[u8; KEY_BYTES],
    device_public_key: &[u8; KEY_BYTES],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(AUTH_DOMAIN.len() + 3 * KEY_BYTES);
    transcript.extend_from_slice(AUTH_DOMAIN);
    transcript.extend_from_slice(server_public_key);
    transcript.extend_from_slice(challenge);
    transcript.extend_from_slice(device_public_key);
    transcript
}

/// Bytes both keys sign to bind a Nostr public key to this account's handle.
#[must_use]
pub fn nostr_bind_transcript(
    server_public_key: &[u8; KEY_BYTES],
    account_id: &str,
    handle: &str,
    nostr_public_key: &[u8; KEY_BYTES],
    nonce: &[u8; KEY_BYTES],
    timestamp: u64,
) -> Vec<u8> {
    proof_transcript(
        NOSTR_BIND_DOMAIN,
        server_public_key,
        account_id,
        handle,
        nostr_public_key,
        nonce,
        timestamp,
    )
}

#[must_use]
pub fn nostr_unbind_transcript(
    server_public_key: &[u8; KEY_BYTES],
    account_id: &str,
    handle: &str,
    nostr_public_key: &[u8; KEY_BYTES],
    nonce: &[u8; KEY_BYTES],
    timestamp: u64,
) -> Vec<u8> {
    proof_transcript(
        NOSTR_UNBIND_DOMAIN,
        server_public_key,
        account_id,
        handle,
        nostr_public_key,
        nonce,
        timestamp,
    )
}

fn proof_transcript(
    domain: &[u8],
    server_public_key: &[u8; KEY_BYTES],
    account_id: &str,
    handle: &str,
    nostr_public_key: &[u8; KEY_BYTES],
    nonce: &[u8; KEY_BYTES],
    timestamp: u64,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(
        domain.len() + 2 + account_id.len() + 2 + handle.len() + KEY_BYTES * 3 + 8,
    );
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(server_public_key);
    push_str(&mut transcript, account_id);
    push_str(&mut transcript, handle);
    transcript.extend_from_slice(nostr_public_key);
    transcript.extend_from_slice(nonce);
    transcript.extend_from_slice(&timestamp.to_be_bytes());
    transcript
}

fn push_str(transcript: &mut Vec<u8>, value: &str) {
    let length = u16::try_from(value.len()).unwrap_or(u16::MAX);
    transcript.extend_from_slice(&length.to_be_bytes());
    transcript.extend_from_slice(&value.as_bytes()[..usize::from(length)]);
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    UnsupportedVersion,
    InvalidRequest,
    NotAuthenticated,
    AlreadyAuthenticated,
    InvalidSignature,
    InvalidHandle,
    HandleTaken,
    HandleAlreadySet,
    InvalidName,
    NostrPubkeyTaken,
    ReplayedProof,
    NotFound,
    TooLarge,
    RateLimited,
    Storage,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServerError {
    pub code: ErrorCode,
    pub message: String,
}

impl ServerError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl Error for ServerError {}

#[must_use]
pub fn success_frame(id: &str, result: Value) -> String {
    json!({"version": PROTOCOL_VERSION, "id": id, "ok": true, "result": result}).to_string()
}

#[must_use]
pub fn failure_frame(id: &str, error: &ServerError) -> String {
    json!({
        "version": PROTOCOL_VERSION,
        "id": id,
        "ok": false,
        "error": {"code": error.code, "message": error.message},
    })
    .to_string()
}

#[must_use]
pub fn event_frame(kind: &str, data: Value) -> String {
    json!({"version": PROTOCOL_VERSION, "event": kind, "data": data}).to_string()
}

pub fn validate_name(value: &str) -> Result<&str, ServerError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ServerError::new(
            ErrorCode::InvalidName,
            "names are 1 to 64 bytes without control characters or surrounding whitespace",
        ));
    }
    Ok(value)
}

pub fn validate_client_id(value: &str) -> Result<&str, ServerError> {
    if value.is_empty()
        || value.len() > MAX_CLIENT_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ServerError::new(
            ErrorCode::InvalidRequest,
            "client_id is 1 to 64 ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(value)
}

pub fn validate_text(value: &str) -> Result<&str, ServerError> {
    if value.is_empty() {
        return Err(ServerError::new(
            ErrorCode::InvalidRequest,
            "message text is empty",
        ));
    }
    if value.len() > MAX_TEXT_BYTES
        || serde_json::to_string(value)
            .expect("string serialization")
            .len()
            > MAX_ENCODED_TEXT_BYTES
    {
        return Err(ServerError::new(
            ErrorCode::TooLarge,
            format!(
                "message text exceeds {MAX_TEXT_BYTES} UTF-8 bytes or {MAX_ENCODED_TEXT_BYTES} JSON bytes"
            ),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcripts_are_domain_separated_and_bind_every_field() {
        let challenge = [1_u8; KEY_BYTES];
        let device = [2_u8; KEY_BYTES];
        let server = [3_u8; KEY_BYTES];
        let hello = hello_transcript(&challenge, &device);
        let auth = auth_transcript(&server, &challenge, &device);
        assert!(hello.starts_with(HELLO_DOMAIN));
        assert!(auth.starts_with(AUTH_DOMAIN));
        assert_eq!(hello.len(), HELLO_DOMAIN.len() + 2 * KEY_BYTES);
        assert_eq!(auth.len(), AUTH_DOMAIN.len() + 3 * KEY_BYTES);
        assert_ne!(
            auth,
            auth_transcript(&[4_u8; KEY_BYTES], &challenge, &device)
        );
        assert_ne!(auth, auth_transcript(&server, &[4_u8; KEY_BYTES], &device));
        assert_ne!(
            auth,
            auth_transcript(&server, &challenge, &[4_u8; KEY_BYTES])
        );
        let bind = nostr_bind_transcript(&server, "acct", "ada", &device, &challenge, 9);
        assert!(bind.starts_with(NOSTR_BIND_DOMAIN));
        assert_ne!(
            bind,
            nostr_unbind_transcript(&server, "acct", "ada", &device, &challenge, 9)
        );
        assert_ne!(
            bind,
            nostr_bind_transcript(&server, "acct", "bob", &device, &challenge, 9)
        );
        assert_ne!(
            bind,
            nostr_bind_transcript(&server, "acct", "ada", &device, &challenge, 10)
        );
    }

    #[test]
    fn frames_are_single_line_json() {
        let frame = success_frame("1", json!({"x": 1}));
        assert!(!frame.contains('\n'));
        let error = failure_frame("2", &ServerError::new(ErrorCode::NotFound, "gone"));
        assert!(error.contains("\"not-found\""));
        assert!(event_frame(EVENT_MESSAGE, Value::Null).contains("\"event\":\"message\""));
        let parsed: ServerError =
            serde_json::from_str(r#"{"code":"rate-limited","message":"slow down"}"#).unwrap();
        assert_eq!(parsed.code, ErrorCode::RateLimited);
    }

    #[test]
    fn validators_reject_hostile_values() {
        assert!(validate_name(" padded").is_err());
        assert!(validate_name("tab\tname").is_err());
        assert!(validate_name(&"x".repeat(65)).is_err());
        assert!(validate_name("general").is_ok());
        assert!(validate_client_id("a/b").is_err());
        assert!(validate_client_id("msg-0001_a").is_ok());
        assert!(validate_text("").is_err());
        assert_eq!(
            validate_text(&"y".repeat(MAX_TEXT_BYTES + 1))
                .unwrap_err()
                .code,
            ErrorCode::TooLarge
        );
    }
}
