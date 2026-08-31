use omachat_proto::ipc::ErrorCode;
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum CoreError {
    Io(std::io::Error),
    Store(omachat_store::StoreError),
    IdentityStore(omachat_store::IdentityStoreError),
    AccountVault(omachat_store::AccountVaultError),
    Identity(omachat_crypto::IdentityError),
    Outbox(omachat_store::OutboxError),
    RelayPool(omachat_nostr::pool::RelayPoolError),
    InvalidConfig,
    InvalidCommand,
    InvalidGeohash,
    InvalidPublicKey,
    InvalidMessage,
    NotJoined,
    Nostr,
    Encoding,
    Clock,
    Random,
    Subscription,
    ConfirmationRequired,
    PanicErase,
    Panicked,
    RestartRequired,
}
impl CoreError {
    pub(crate) fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidConfig
            | Self::InvalidCommand
            | Self::InvalidGeohash
            | Self::InvalidPublicKey
            | Self::InvalidMessage => ErrorCode::InvalidRequest,
            Self::ConfirmationRequired => ErrorCode::Conflict,
            Self::RestartRequired => ErrorCode::Conflict,
            Self::Panicked => ErrorCode::Unavailable,
            Self::NotJoined => ErrorCode::NotFound,
            Self::Io(_)
            | Self::Store(_)
            | Self::IdentityStore(_)
            | Self::AccountVault(_)
            | Self::Identity(_)
            | Self::Outbox(_)
            | Self::RelayPool(_)
            | Self::Nostr
            | Self::Encoding
            | Self::Clock
            | Self::Random
            | Self::Subscription => ErrorCode::Internal,
            Self::PanicErase => ErrorCode::Internal,
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "daemon I/O failed: {error}"),
            Self::Store(error) => write!(formatter, "sealed store failed: {error}"),
            Self::IdentityStore(error) => write!(formatter, "identity store failed: {error}"),
            Self::AccountVault(error) => write!(formatter, "account store failed: {error}"),
            Self::Identity(error) => write!(formatter, "identity operation failed: {error}"),
            Self::Outbox(error) => write!(formatter, "outbox failed: {error}"),
            Self::RelayPool(error) => write!(formatter, "relay pool failed: {error}"),
            Self::InvalidConfig => formatter.write_str("daemon configuration is invalid"),
            Self::InvalidCommand => formatter.write_str("command is invalid in this context"),
            Self::InvalidGeohash => formatter.write_str("geohash is invalid"),
            Self::InvalidPublicKey => formatter.write_str("Nostr public key is invalid"),
            Self::InvalidMessage => formatter.write_str("message is empty or too large"),
            Self::NotJoined => formatter.write_str("geohash is not joined"),
            Self::Nostr => formatter.write_str("Nostr event creation failed"),
            Self::Encoding => formatter.write_str("daemon state encoding failed"),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
            Self::Random => formatter.write_str("secure random generation failed"),
            Self::Subscription => formatter.write_str("Nostr subscription refresh failed"),
            Self::ConfirmationRequired => {
                formatter.write_str("panic erase requires exact confirmation ERASE")
            }
            Self::PanicErase => {
                formatter.write_str("panic erase cannot run in this runtime context")
            }
            Self::Panicked => formatter.write_str("daemon state has been erased"),
            Self::RestartRequired => formatter.write_str("relay changes require a daemon restart"),
        }
    }
}

impl Error for CoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::IdentityStore(error) => Some(error),
            Self::AccountVault(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Outbox(error) => Some(error),
            Self::RelayPool(error) => Some(error),
            _ => None,
        }
    }
}
