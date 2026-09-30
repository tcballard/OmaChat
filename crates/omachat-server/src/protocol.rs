//! Wire protocol v1 for the hosted server.
//!
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
}
