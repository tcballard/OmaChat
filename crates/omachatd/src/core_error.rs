use omachat_proto::ipc::ErrorCode;
use std::{error::Error, fmt};
#[derive(Debug)]
pub enum CoreError {
    Clock,
    ConfirmationExpired,
    ConfirmationRequired,
    DraftCapacity,
    Encoding,
    Hosted(omachat_proto::hosted::ServerError),
    HostedService(crate::HostedServiceError),
    HostedUnavailable,
    HostedUnconfigured,
    IdentityStore(omachat_store::IdentityStoreError),
    InvalidCommand,
    InvalidConfig,
    InvalidConversation,
    InvalidDraft,
    InvalidMessage,
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
                | omachat_proto::hosted::ErrorCode::NameTaken
                | omachat_proto::hosted::ErrorCode::Forbidden
                | omachat_proto::hosted::ErrorCode::AlreadyAuthenticated => ErrorCode::Conflict,
                omachat_proto::hosted::ErrorCode::NotFound => ErrorCode::NotFound,
                omachat_proto::hosted::ErrorCode::RateLimited
                | omachat_proto::hosted::ErrorCode::Storage
                | omachat_proto::hosted::ErrorCode::RegistrationClosed
                | omachat_proto::hosted::ErrorCode::InvalidInvite
                | omachat_proto::hosted::ErrorCode::InvalidSignature
                | omachat_proto::hosted::ErrorCode::NotAuthenticated => ErrorCode::Unavailable,
                omachat_proto::hosted::ErrorCode::Internal => ErrorCode::Internal,
            },
            Self::InvalidConfig
            | Self::InvalidCommand
            | Self::InvalidMessage
            | Self::InvalidConversation
            | Self::InvalidDraft => ErrorCode::InvalidRequest,
            Self::HostedUnavailable | Self::HostedUnconfigured | Self::Panicked => {
                ErrorCode::Unavailable
            }
            Self::DraftCapacity
            | Self::ConfirmationRequired
            | Self::ConfirmationExpired
            | Self::RestartRequired => ErrorCode::Conflict,
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
            Self::DraftCapacity => f.write_str("draft capacity reached"),
            Self::Encoding => f.write_str("invalid stored data"),
            Self::Hosted(e) => write!(f, "Hosted: {e}"),
            Self::HostedService(e) => write!(f, "HostedService: {e}"),
            Self::HostedUnavailable => {
                f.write_str("hosted server is unreachable; the request was not confirmed and may be repeated safely")
            }
            Self::HostedUnconfigured => f.write_str("hosted server is not configured"),
            Self::IdentityStore(e) => write!(f, "IdentityStore: {e}"),
            Self::InvalidCommand => f.write_str("invalid command"),
            Self::InvalidConfig => {
                f.write_str("invalid configuration; use storage_provider and hosted settings only")
            }
            Self::InvalidConversation => f.write_str("invalid hosted conversation"),
            Self::InvalidDraft => f.write_str("invalid draft"),
            Self::InvalidMessage => f.write_str("message is empty or too large"),
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
