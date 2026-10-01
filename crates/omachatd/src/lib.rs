//! Hosted messaging daemon and local IPC service.
mod chat_history;
mod config;
mod confirmation;
mod core;
mod core_error;
mod drafts;
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
    HOSTED_CONVERSATION_PREFIX, HostedAccount, HostedError, HostedEvent, HostedHandle,
    HostedService, HostedServiceConfig, HostedServiceError, HostedState, HostedTimeouts,
    hosted_conversation_id, parse_hosted_conversation,
};
pub use ipc_server::{EventHub, IpcServer, RequestHandler, ServerError};
