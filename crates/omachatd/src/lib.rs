//! Headless daemon IPC service primitives.

mod config;
mod core;
mod core_error;
mod dm_inbox_service;
mod ipc_server;
mod nostr_service;

pub use config::{DaemonConfig, StorageProviderConfig};
pub use core::{DaemonCore, PanicState};
pub use core_error::CoreError;
pub use dm_inbox_service::{DmInboxHandle, DmInboxService, DmInboxServiceError};
pub use ipc_server::{EventHub, IpcServer, RequestHandler, ServerError};
pub use nostr_service::{NostrHandle, NostrService};
