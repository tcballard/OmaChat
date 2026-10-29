use omachat_proto::ipc::ErrorCode;
use std::{error::Error, fmt};
#[derive(Debug)]
pub enum CoreError {
    Clock,
    ConfirmationExpired,
    ConfirmationRequired,
    Hosted(omachat_proto::hosted::ServerError),
    HostedService(crate::HostedServiceError),
    HostedUnavailable,
    HostedUnconfigured,
    Chat(crate::nostr_chat::ChatError),
    IdentityStore(omachat_store::IdentityStoreError),
    NostrMissing,
    NostrStore(omachat_store::NostrStoreError),
    InvalidCommand,
    InvalidConfig,
    Io(std::io::Error),
    PanicErase,
    Panicked,
    Random,
    RestartRequired,
    Store(omachat_store::StoreError),
}
impl CoreError {
    pub(crate) fn code(&self) -> ErrorCode {
        match self {
            Self::Hosted(error) => match error.code {
                omachat_proto::hosted::ErrorCode::InvalidRequest
                | omachat_proto::hosted::ErrorCode::InvalidHandle
                | omachat_proto::hosted::ErrorCode::InvalidName
                | omachat_proto::hosted::ErrorCode::TooLarge
                | omachat_proto::hosted::ErrorCode::UnsupportedVersion => ErrorCode::InvalidRequest,
                omachat_proto::hosted::ErrorCode::HandleTaken
                | omachat_proto::hosted::ErrorCode::HandleAlreadySet
                | omachat_proto::hosted::ErrorCode::NostrPubkeyTaken
                | omachat_proto::hosted::ErrorCode::ReplayedProof
                | omachat_proto::hosted::ErrorCode::AlreadyAuthenticated => ErrorCode::Conflict,
                omachat_proto::hosted::ErrorCode::NotFound => ErrorCode::NotFound,
                omachat_proto::hosted::ErrorCode::RateLimited
                | omachat_proto::hosted::ErrorCode::Storage
                | omachat_proto::hosted::ErrorCode::InvalidSignature
                | omachat_proto::hosted::ErrorCode::NotAuthenticated => ErrorCode::Unavailable,
                omachat_proto::hosted::ErrorCode::Internal => ErrorCode::Internal,
            },
            Self::Chat(error) => match error {
                crate::nostr_chat::ChatError::InvalidPeer
                | crate::nostr_chat::ChatError::InvalidRelay
                | crate::nostr_chat::ChatError::InvalidText
                | crate::nostr_chat::ChatError::SelfContact => ErrorCode::InvalidRequest,
                crate::nostr_chat::ChatError::NotFound
                | crate::nostr_chat::ChatError::Nip05(omachat_nostr::nip05::Nip05Error::NotFound) => {
                    ErrorCode::NotFound
                }
                crate::nostr_chat::ChatError::NoRelays
                | crate::nostr_chat::ChatError::NotConnected
                | crate::nostr_chat::ChatError::Stopped => ErrorCode::Unavailable,
                crate::nostr_chat::ChatError::TooLarge => ErrorCode::Conflict,
                _ => ErrorCode::Internal,
            },
            Self::NostrMissing => ErrorCode::NotFound,
            Self::NostrStore(omachat_store::NostrStoreError::AlreadyPresent) => ErrorCode::Conflict,
            Self::InvalidConfig | Self::InvalidCommand => ErrorCode::InvalidRequest,
            Self::HostedUnavailable | Self::HostedUnconfigured | Self::Panicked => {
                ErrorCode::Unavailable
            }
            Self::ConfirmationRequired | Self::ConfirmationExpired | Self::RestartRequired => {
                ErrorCode::Conflict
            }
            _ => ErrorCode::Internal,
        }
    }
}
impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock => f.write_str("system clock invalid"),
            Self::ConfirmationExpired => f.write_str("confirmation expired"),
            Self::ConfirmationRequired => f.write_str("confirmation required"),
            Self::Hosted(e) => write!(f, "Hosted: {e}"),
            Self::HostedService(e) => write!(f, "HostedService: {e}"),
            Self::HostedUnavailable => {
                f.write_str("hosted server is unreachable; the request was not confirmed and may be repeated safely")
            }
            Self::HostedUnconfigured => f.write_str("hosted server is not configured"),
            Self::Chat(error) => write!(f, "{error}"),
            Self::IdentityStore(e) => write!(f, "IdentityStore: {e}"),
            Self::NostrMissing => f.write_str("no nostr identity is stored"),
            Self::NostrStore(e) => write!(f, "NostrStore: {e}"),
            Self::InvalidCommand => f.write_str("invalid command"),
            Self::InvalidConfig => {
                f.write_str(
                    "invalid configuration; use storage_provider, hosted, and dm_relays settings only",
                )
            }
            Self::Io(e) => write!(f, "Io: {e}"),
            Self::PanicErase => f.write_str("panic cleanup failed"),
            Self::Panicked => f.write_str("daemon is shutting down"),
            Self::Random => f.write_str("random generation failed"),
            Self::RestartRequired => f.write_str("configuration change requires restart"),
            Self::Store(e) => write!(f, "Store: {e}"),
        }
    }
}
impl Error for CoreError {}
