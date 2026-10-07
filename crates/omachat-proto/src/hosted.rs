//! Wire contract shared by the hosted server and its clients.
//!
//! Everything here is pure data: protocol constants, the authentication
//! transcripts both sides sign, error codes, frame builders and value
//! validators. The server (`omachat-server`) and the daemon's hosted
//! transport both depend on this module so neither has to depend on the
//! other. See `docs/hosted-server.md` for the protocol description.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{error::Error, fmt};

pub const PROTOCOL_VERSION: u16 = 1;
/// Upper bound for one WebSocket message in either direction.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
/// Upper bound for one chat message body in bytes of UTF-8.
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
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

/// Domain separator for the device's authentication signature.
pub const AUTH_DOMAIN: &[u8] = b"omachat-server-auth-v1\0";
/// Domain separator for the server's hello signature.
pub const HELLO_DOMAIN: &[u8] = b"omachat-server-hello-v1\0";
pub const KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;

/// Bytes the server signs in its hello reply so a client can pin it.
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    UnsupportedVersion,
    InvalidRequest,
    NotAuthenticated,
    AlreadyAuthenticated,
    InvalidSignature,
    RegistrationClosed,
    InvalidInvite,
    InvalidHandle,
    HandleTaken,
    HandleAlreadySet,
    InvalidName,
    NameTaken,
    NotFound,
    Forbidden,
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

/// Reject names that would be confusing or unbounded: empty, surrounding
/// whitespace, control characters, or more than [`MAX_NAME_BYTES`].
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
    if value.len() > MAX_TEXT_BYTES {
        return Err(ServerError::new(
            ErrorCode::TooLarge,
            format!("message text exceeds {MAX_TEXT_BYTES} bytes"),
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
