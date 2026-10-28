//! Local identity daemon and handle-server client.
mod config;
mod confirmation;
mod core;
mod core_error;
mod hosted_service;
mod ipc_server;
pub use config::{DaemonConfig, HostedConfig, StorageProviderConfig};
pub use confirmation::{
    CONFIRMATION_TTL_SECONDS, ConfirmationAction, ConfirmationError, DestructiveConfirmations,
    IssuedConfirmation,
};
pub use core::{DaemonCore, PanicState};
pub use core_error::CoreError;
pub use hosted_service::{
    HostedAccount, HostedError, HostedEvent, HostedHandle, HostedService, HostedServiceConfig,
    HostedServiceError, HostedState, HostedTimeouts,
};
pub use ipc_server::{EventHub, IpcServer, RequestHandler, ServerError};
