//! Wire protocol v1 for the hosted server.
//!
//! Every frame is one UTF-8 JSON text message over a WebSocket. Clients send
//! requests; the server answers each request exactly once, in order, and may
//! interleave unsolicited events for the authenticated account.

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Request {
    pub version: u16,
    pub id: String,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "method", content = "params", rename_all = "kebab-case")]
pub enum Command {
    /// First request on every connection. The reply carries a fresh
    /// challenge and the server's public key.
    Hello {
        minimum_version: u16,
        maximum_version: u16,
        /// Hex-encoded Ed25519 device public key.
        device_public_key: String,
    },
    /// Second request: the device signs the challenge transcript. A device
    /// seen for the first time registers a new account, subject to the
    /// server's registration policy.
    Authenticate {
        /// Hex-encoded Ed25519 signature over [`crate::auth::auth_transcript`].
        signature: String,
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        invite_code: Option<String>,
    },
    Status,
    ClaimHandle {
        handle: String,
    },
    ResolveHandle {
        handle: String,
    },
    CreateWorkspace {
        name: String,
    },
    AddMember {
        workspace_id: String,
        handle: String,
    },
    CreateChannel {
        workspace_id: String,
        name: String,
    },
    OpenDm {
        handle: String,
    },
    ListConversations,
    /// Append one message. `client_id` makes the request idempotent per
    /// device: repeating it after an unknown outcome returns the original
    /// sequence instead of a duplicate.
    Send {
        conversation_id: String,
        client_id: String,
        text: String,
    },
    History {
        conversation_id: String,
        #[serde(default)]
        before_sequence: Option<u64>,
        #[serde(default)]
        limit: Option<u32>,
    },
    MarkDelivered {
        conversation_id: String,
        sequence: u64,
    },
    MarkRead {
        conversation_id: String,
        sequence: u64,
    },
}

impl Command {
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Authenticate { .. } => "authenticate",
            Self::Status => "status",
            Self::ClaimHandle { .. } => "claim-handle",
            Self::ResolveHandle { .. } => "resolve-handle",
            Self::CreateWorkspace { .. } => "create-workspace",
            Self::AddMember { .. } => "add-member",
            Self::CreateChannel { .. } => "create-channel",
            Self::OpenDm { .. } => "open-dm",
            Self::ListConversations => "list-conversations",
            Self::Send { .. } => "send",
            Self::History { .. } => "history",
            Self::MarkDelivered { .. } => "mark-delivered",
            Self::MarkRead { .. } => "mark-read",
        }
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
    fn requests_parse_with_and_without_params() {
        let status: Request =
            serde_json::from_str(r#"{"version":1,"id":"a","method":"status"}"#).unwrap();
        assert_eq!(status.command, Command::Status);
        let send: Request = serde_json::from_str(
            r#"{"version":1,"id":"b","method":"send","params":{"conversation_id":"c","client_id":"k","text":"hi"}}"#,
        )
        .unwrap();
        assert_eq!(send.command.method(), "send");
        assert!(
            serde_json::from_str::<Request>(r#"{"version":1,"id":"c","method":"nope"}"#).is_err()
        );
    }

    #[test]
    fn frames_are_single_line_json() {
        let frame = success_frame("1", json!({"x": 1}));
        assert!(!frame.contains('\n'));
        let error = failure_frame("2", &ServerError::new(ErrorCode::NotFound, "gone"));
        assert!(error.contains("\"not-found\""));
        assert!(event_frame(EVENT_MESSAGE, Value::Null).contains("\"event\":\"message\""));
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
