//! Every frame is one UTF-8 JSON text message over a WebSocket. Clients send
//! requests; the server answers each request exactly once, in order, and may
//! interleave unsolicited events for the authenticated account.

pub use omachat_proto::hosted::{
    DEFAULT_HISTORY_LIMIT, EVENT_CONVERSATION, EVENT_LAGGED, EVENT_MESSAGE, EVENT_RECEIPT,
    ErrorCode, MAX_CLIENT_ID_BYTES, MAX_FRAME_BYTES, MAX_HISTORY_LIMIT, MAX_INVITE_CODE_BYTES,
    MAX_NAME_BYTES, MAX_REQUEST_ID_BYTES, MAX_TEXT_BYTES, PROTOCOL_VERSION, ServerError,
    event_frame, failure_frame, success_frame, validate_client_id, validate_name, validate_text,
};
use serde::Deserialize;

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
    /// seen for the first time registers a new account.
    Authenticate {
        /// Hex-encoded Ed25519 signature over [`crate::auth::auth_transcript`].
        signature: String,
        #[serde(default)]
        display_name: Option<String>,
    },
    Status,
    ClaimHandle {
        handle: String,
    },
    ResolveHandle {
        handle: String,
    },
    BindNostr {
        nostr_public_key: String,
        nonce: String,
        timestamp: u64,
        device_signature: String,
        nostr_signature: String,
    },
    /// Remove this account's Nostr binding. The device key signs; the Nostr
    /// key is not required, so a lost `nsec` can still be detached.
    UnbindNostr {
        nonce: String,
        timestamp: u64,
        device_signature: String,
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
            Self::BindNostr { .. } => "bind-nostr",
            Self::UnbindNostr { .. } => "unbind-nostr",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_with_and_without_params() {
        let status: Request =
            serde_json::from_str(r#"{"version":1,"id":"a","method":"status"}"#).unwrap();
        assert_eq!(status.command, Command::Status);
        let claim: Request = serde_json::from_str(
            r#"{"version":1,"id":"b","method":"claim-handle","params":{"handle":"ada"}}"#,
        )
        .unwrap();
        assert_eq!(claim.command.method(), "claim-handle");
        assert!(
            serde_json::from_str::<Request>(r#"{"version":1,"id":"c","method":"nope"}"#).is_err()
        );
    }
}
