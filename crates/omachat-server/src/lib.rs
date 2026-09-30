//! Hosted OmaChat server.
//!
//! One loopback WebSocket carries accounts, workspaces, channels, direct
//! messages, history and receipts for clients that trust the operator with
//! message content. A TLS reverse proxy owns the public socket. See
//! `docs/hosted-server.md` for the protocol and threat model.

pub mod auth;
pub mod host;
pub mod process;
pub mod protocol;
pub mod service;
pub mod session;
pub mod storage;

pub use auth::{ServerIdentity, generate_seed_file, load_seed_file};
pub use host::{HostError, HostLimits, HostReport, run_host};
pub use process::{
    SERVERD_HELP, ServerProcessCommand, ServerProcessConfig, ServerProcessConfigError,
    load_invite_codes, parse_server_process_args,
};
pub use protocol::{ErrorCode, PROTOCOL_VERSION, ServerError};
pub use service::{Registration, ServiceConfig, ServiceHandle, spawn_service};
pub use session::{CloseReason, SessionLimits, SessionReport};
pub use storage::{Storage, StorageError};

use std::{
    io,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub const DATABASE_FILE: &str = "messages.db";

/// Create the data directory owner-only if needed and return the database
/// path. An existing directory with group or world permissions is refused.
pub fn prepare_data_dir(path: &Path) -> io::Result<PathBuf> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "data directory path is not a directory",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "data directory must be accessible by its owner only (mode 0700)",
        ));
    }
    Ok(path.join(DATABASE_FILE))
}
