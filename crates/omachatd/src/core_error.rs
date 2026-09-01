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
    DmInbox(crate::dm_inbox_service::DmInboxServiceError),
    DmRelayCache(crate::dm_relay_cache_store::SealedDmRelayCacheError),
    DmRelayDiscovery(omachat_nostr::dm_relay_discovery::DmRelayDiscoveryError),
    ProfileCache(crate::profile_cache_store::SealedProfileCacheError),
    ProfileDiscovery(omachat_nostr::profile_discovery::ProfileDiscoveryError),
    RegistryEvidence(
        omachat_registry_transport::RegistryEvidenceError<
            omachat_registry_transport::RegistryWebSocketError,
        >,
    ),
    RegistryCache(omachat_store::RegistryCacheError),
    PrincipalRegistryCache(omachat_store::PrincipalRegistryCacheError),
    RegistryClaim(omachat_registry::RegistryError),
    RegistryClaimIntent(omachat_store::RegistryClaimIntentError),
    RegistryClaimPreflightOffline,
    RegistryClaimPreflightUnusable,
    RegistryClaimConfirmationRequired,
    RegistryHandleConflict,
    RegistryBindingChanged,
    RegistryUnconfigured,
    RegistryProtocolOperationUnavailable,
    InvalidConfig,
    InvalidCommand,
    InvalidGeohash,
    InvalidHandle,
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
            | Self::InvalidHandle
            | Self::InvalidPublicKey
            | Self::InvalidMessage => ErrorCode::InvalidRequest,
            Self::ConfirmationRequired
            | Self::RegistryClaimConfirmationRequired
            | Self::RegistryHandleConflict
            | Self::RegistryBindingChanged => ErrorCode::Conflict,
            Self::RegistryClaimIntent(
                omachat_store::RegistryClaimIntentError::PendingConflict
                | omachat_store::RegistryClaimIntentError::PendingMissing,
            ) => ErrorCode::Conflict,
            Self::RestartRequired => ErrorCode::Conflict,
            Self::Panicked
            | Self::RegistryUnconfigured
            | Self::RegistryProtocolOperationUnavailable
            | Self::RegistryClaimPreflightOffline => ErrorCode::Unavailable,
            Self::NotJoined => ErrorCode::NotFound,
            Self::Io(_)
            | Self::Store(_)
            | Self::IdentityStore(_)
            | Self::AccountVault(_)
            | Self::Identity(_)
            | Self::Outbox(_)
            | Self::RelayPool(_)
            | Self::DmInbox(_)
            | Self::DmRelayCache(_)
            | Self::DmRelayDiscovery(_)
            | Self::ProfileCache(_)
            | Self::ProfileDiscovery(_)
            | Self::RegistryEvidence(_)
            | Self::RegistryCache(_)
            | Self::PrincipalRegistryCache(_)
            | Self::RegistryClaim(_)
            | Self::RegistryClaimIntent(_)
            | Self::RegistryClaimPreflightUnusable
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
            Self::DmInbox(error) => write!(formatter, "private inbox failed: {error}"),
            Self::DmRelayCache(error) => write!(formatter, "recipient relay cache failed: {error}"),
            Self::DmRelayDiscovery(error) => {
                write!(formatter, "recipient relay discovery failed: {error}")
            }
            Self::ProfileCache(error) => write!(formatter, "profile cache failed: {error}"),
            Self::ProfileDiscovery(error) => write!(formatter, "profile discovery failed: {error}"),
            Self::RegistryEvidence(error) => {
                write!(formatter, "registry evidence resolution failed: {error}")
            }
            Self::RegistryCache(error) => write!(formatter, "registry cache failed: {error}"),
            Self::PrincipalRegistryCache(error) => {
                write!(formatter, "principal registry cache failed: {error}")
            }
            Self::RegistryClaim(error) => write!(formatter, "registry claim failed: {error}"),
            Self::RegistryClaimIntent(error) => {
                write!(formatter, "pending registry claim failed: {error}")
            }
            Self::RegistryClaimPreflightOffline => {
                formatter.write_str("registry must be online before preparing a new handle claim")
            }
            Self::RegistryClaimPreflightUnusable => formatter
                .write_str("registry preflight did not return usable current account state"),
            Self::RegistryClaimConfirmationRequired => {
                formatter.write_str("registry handle claim requires exact handle confirmation")
            }
            Self::RegistryHandleConflict => formatter
                .write_str("requested handle conflicts with local or authoritative account state"),
            Self::RegistryBindingChanged => {
                formatter.write_str("local account binding changed during registry preflight")
            }
            Self::RegistryUnconfigured => {
                formatter.write_str("authoritative registry client is not configured")
            }
            Self::RegistryProtocolOperationUnavailable => {
                formatter.write_str("command is unavailable for the configured registry protocol")
            }
            Self::InvalidConfig => formatter.write_str("daemon configuration is invalid"),
            Self::InvalidCommand => formatter.write_str("command is invalid in this context"),
            Self::InvalidGeohash => formatter.write_str("geohash is invalid"),
            Self::InvalidHandle => formatter.write_str("global handle is invalid"),
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
            Self::DmInbox(error) => Some(error),
            Self::DmRelayCache(error) => Some(error),
            Self::DmRelayDiscovery(error) => Some(error),
            Self::ProfileCache(error) => Some(error),
            Self::ProfileDiscovery(error) => Some(error),
            Self::RegistryEvidence(error) => Some(error),
            Self::RegistryCache(error) => Some(error),
            Self::PrincipalRegistryCache(error) => Some(error),
            Self::RegistryClaim(error) => Some(error),
            Self::RegistryClaimIntent(error) => Some(error),
            _ => None,
        }
    }
}
