//! File-backed generation anchor for NIP-29 room state.
//!
//! The sealed store's rollback domain is its state directory: restoring that
//! directory from a backup silently rewinds every sealed record. This anchor
//! therefore refuses to live inside, or contain, the sealed state directory,
//! and a stored generation can never be lowered through this API. Restoring
//! the store from backup then leaves the anchor ahead of the record, which
//! [`crate::RoomStateVault`] reports as rollback instead of accepting.
//!
//! Anchor files hold no secrets. They are written by atomic replacement with
//! fsync so a crash leaves either the previous or the new generation.

use crate::{RoomStateAnchorError, RoomStateGenerationAnchor};
use secret_service::{EncryptionType, SecretService};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
use tokio::sync::Mutex as AsyncMutex;

pub const ROOM_STATE_ANCHOR_VERSION: u16 = 1;
const MAX_ANCHOR_FILE_BYTES: u64 = 4 * 1024;
const MAX_ENCODED_CONTEXT_BYTES: usize = 200;
const MAX_CONTEXT_BYTES: usize = 128;
const SECRET_APPLICATION: &str = "org.omachat.OmaChat";
const SECRET_PURPOSE: &str = "nip29-room-state-generation";
const SECRET_CONTENT_TYPE: &str = "application/json";

#[derive(Deserialize, Serialize)]
struct AnchorFile {
    version: u16,
    store_context: String,
    relay_pubkey: String,
    generation: u64,
}

/// Monotonic per-(context, relay) generations in a directory outside the
/// sealed store.
pub struct FileGenerationAnchor {
    directory: PathBuf,
    /// Serializes read-compare-write so two vaults for the same relay cannot
    /// interleave and lower a generation.
    lock: Mutex<()>,
}

impl FileGenerationAnchor {
    /// Open or create the anchor directory. `sealed_state_directory` is the
    /// directory the [`crate::SealedStore`] was opened on; the anchor refuses
    /// to share its rollback domain in either direction.
    pub fn open(
        directory: impl AsRef<Path>,
        sealed_state_directory: impl AsRef<Path>,
    ) -> Result<Self, RoomStateAnchorError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)
            .map_err(|error| io_error("create anchor directory", &error))?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("restrict anchor directory", &error))?;
        let canonical = fs::canonicalize(directory)
            .map_err(|error| io_error("resolve anchor directory", &error))?;
        let sealed = fs::canonicalize(sealed_state_directory.as_ref())
            .map_err(|error| io_error("resolve sealed state directory", &error))?;
        if canonical.starts_with(&sealed) || sealed.starts_with(&canonical) {
            return Err(RoomStateAnchorError::new(
                "generation anchor must live outside the sealed state directory",
            ));
        }
        Ok(Self {
            directory: canonical,
            lock: Mutex::new(()),
        })
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn path_for(
        &self,
        store_context: &str,
        relay_pubkey: &str,
    ) -> Result<PathBuf, RoomStateAnchorError> {
        if relay_pubkey.len() != 64
            || !relay_pubkey
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RoomStateAnchorError::new(
                "anchor relay identity must be a lowercase 32-byte key",
            ));
        }
        let encoded = encode_context(store_context)?;
        Ok(self.directory.join(relay_pubkey).join(encoded))
    }

    fn read_file(
        path: &Path,
        store_context: &str,
        relay_pubkey: &str,
    ) -> Result<Option<u64>, RoomStateAnchorError> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("open anchor", &error)),
        };
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_ANCHOR_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read anchor", &error))?;
        if bytes.len() as u64 > MAX_ANCHOR_FILE_BYTES {
            return Err(RoomStateAnchorError::new("anchor file is too large"));
        }
        let decoded: AnchorFile = serde_json::from_slice(&bytes)
            .map_err(|_| RoomStateAnchorError::new("anchor file is malformed"))?;
        if decoded.version != ROOM_STATE_ANCHOR_VERSION {
            return Err(RoomStateAnchorError::new(format!(
                "unsupported anchor version {}",
                decoded.version
            )));
        }
        if decoded.store_context != store_context || decoded.relay_pubkey != relay_pubkey {
            return Err(RoomStateAnchorError::new(
                "anchor file belongs to another context or relay",
            ));
        }
        Ok(Some(decoded.generation))
    }
}

// Explicit RPIT preserves the trait's `Send` future guarantee.
#[allow(clippy::manual_async_fn)]
impl RoomStateGenerationAnchor for FileGenerationAnchor {
    fn load_generation<'a>(
        &'a self,
        store_context: &'a str,
        relay_pubkey: &'a str,
    ) -> impl std::future::Future<Output = Result<Option<u64>, RoomStateAnchorError>> + Send + 'a
    {
        async move {
            let path = self.path_for(store_context, relay_pubkey)?;
            let _guard = self.lock.lock().expect("anchor mutex poisoned");
            Self::read_file(&path, store_context, relay_pubkey)
        }
    }

    fn store_generation<'a>(
        &'a self,
        store_context: &'a str,
        relay_pubkey: &'a str,
        generation: u64,
    ) -> impl std::future::Future<Output = Result<(), RoomStateAnchorError>> + Send + 'a {
        async move {
            let path = self.path_for(store_context, relay_pubkey)?;
            let _guard = self.lock.lock().expect("anchor mutex poisoned");
            if let Some(current) = Self::read_file(&path, store_context, relay_pubkey)? {
                if current > generation {
                    return Err(RoomStateAnchorError::new(format!(
                        "anchored generation {current} cannot be lowered to {generation}"
                    )));
                }
                if current == generation {
                    return Ok(());
                }
            }
            let parent = path
                .parent()
                .ok_or_else(|| RoomStateAnchorError::new("anchor path has no parent"))?;
            fs::create_dir_all(parent)
                .map_err(|error| io_error("create anchor relay directory", &error))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| io_error("restrict anchor relay directory", &error))?;
            let encoded = encode_anchor(store_context, relay_pubkey, generation)?;
            atomic_write(&path, &encoded)?;
            sync_directory(self.directory.as_path())
        }
    }
}

/// Monotonic per-(context, relay) generations stored as Secret Service items.
pub struct SecretServiceGenerationAnchor {
    lock: AsyncMutex<()>,
}

impl SecretServiceGenerationAnchor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            lock: AsyncMutex::new(()),
        }
    }
}

impl Default for SecretServiceGenerationAnchor {
    fn default() -> Self {
        Self::new()
    }
}

// Explicit RPIT preserves the trait's `Send` future guarantee.
#[allow(clippy::manual_async_fn)]
impl RoomStateGenerationAnchor for SecretServiceGenerationAnchor {
    fn load_generation<'a>(
        &'a self,
        store_context: &'a str,
        relay_pubkey: &'a str,
    ) -> impl std::future::Future<Output = Result<Option<u64>, RoomStateAnchorError>> + Send + 'a
    {
        async move {
            validate_anchor_identity(store_context, relay_pubkey)?;
            let _guard = self.lock.lock().await;
            let service = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(|_| secret_error("connect to Secret Service"))?;
            let collection = service
                .get_default_collection()
                .await
                .map_err(|_| secret_error("open the default collection"))?;
            if collection
                .is_locked()
                .await
                .map_err(|_| secret_error("inspect the default collection"))?
            {
                return Err(secret_error("use a locked default collection"));
            }
            let items = collection
                .search_items(secret_attributes(store_context, relay_pubkey))
                .await
                .map_err(|_| secret_error("search generation anchors"))?;
            if items.len() > 1 {
                return Err(secret_error("use duplicate generation anchors"));
            }
            let Some(item) = items.first() else {
                return Ok(None);
            };
            let bytes = item
                .get_secret()
                .await
                .map_err(|_| secret_error("read generation anchor"))?;
            decode_anchor(&bytes, store_context, relay_pubkey).map(Some)
        }
    }

    fn store_generation<'a>(
        &'a self,
        store_context: &'a str,
        relay_pubkey: &'a str,
        generation: u64,
    ) -> impl std::future::Future<Output = Result<(), RoomStateAnchorError>> + Send + 'a {
        async move {
            validate_anchor_identity(store_context, relay_pubkey)?;
            let _guard = self.lock.lock().await;
            let service = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(|_| secret_error("connect to Secret Service"))?;
            let collection = service
                .get_default_collection()
                .await
                .map_err(|_| secret_error("open the default collection"))?;
            if collection
                .is_locked()
                .await
                .map_err(|_| secret_error("inspect the default collection"))?
            {
                return Err(secret_error("use a locked default collection"));
            }
            let attributes = secret_attributes(store_context, relay_pubkey);
            let items = collection
                .search_items(attributes.clone())
                .await
                .map_err(|_| secret_error("search generation anchors"))?;
            if items.len() > 1 {
                return Err(secret_error("use duplicate generation anchors"));
            }
            let encoded = encode_anchor(store_context, relay_pubkey, generation)?;
            if let Some(item) = items.first() {
                let bytes = item
                    .get_secret()
                    .await
                    .map_err(|_| secret_error("read generation anchor"))?;
                let current = decode_anchor(&bytes, store_context, relay_pubkey)?;
                if current > generation {
                    return Err(RoomStateAnchorError::new(format!(
                        "anchored generation {current} cannot be lowered to {generation}"
                    )));
                }
                if current == generation {
                    return Ok(());
                }
                item.set_secret(&encoded, SECRET_CONTENT_TYPE)
                    .await
                    .map_err(|_| secret_error("update generation anchor"))?;
            } else {
                collection
                    .create_item(
                        "OmaChat NIP-29 room-state generation",
                        attributes,
                        &encoded,
                        false,
                        SECRET_CONTENT_TYPE,
                    )
                    .await
                    .map_err(|_| secret_error("create generation anchor"))?;
            }
            Ok(())
        }
    }
}

fn secret_attributes<'a>(
    store_context: &'a str,
    relay_pubkey: &'a str,
) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        ("application", SECRET_APPLICATION),
        ("purpose", SECRET_PURPOSE),
        ("store-context", store_context),
        ("relay-pubkey", relay_pubkey),
    ])
}

fn validate_anchor_identity(
    store_context: &str,
    relay_pubkey: &str,
) -> Result<(), RoomStateAnchorError> {
    if store_context.is_empty() || store_context.len() > MAX_CONTEXT_BYTES {
        return Err(RoomStateAnchorError::new(
            "anchor context must be 1 to 128 bytes",
        ));
    }
    if relay_pubkey.len() != 64
        || !relay_pubkey
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RoomStateAnchorError::new(
            "anchor relay identity must be a lowercase 32-byte key",
        ));
    }
    Ok(())
}

fn encode_anchor(
    store_context: &str,
    relay_pubkey: &str,
    generation: u64,
) -> Result<Vec<u8>, RoomStateAnchorError> {
    serde_json::to_vec(&AnchorFile {
        version: ROOM_STATE_ANCHOR_VERSION,
        store_context: store_context.to_owned(),
        relay_pubkey: relay_pubkey.to_owned(),
        generation,
    })
    .map_err(|_| RoomStateAnchorError::new("anchor encoding failed"))
}

fn decode_anchor(
    bytes: &[u8],
    store_context: &str,
    relay_pubkey: &str,
) -> Result<u64, RoomStateAnchorError> {
    if bytes.len() as u64 > MAX_ANCHOR_FILE_BYTES {
        return Err(RoomStateAnchorError::new("anchor record is too large"));
    }
    let decoded: AnchorFile = serde_json::from_slice(bytes)
        .map_err(|_| RoomStateAnchorError::new("anchor record is malformed"))?;
    if decoded.version != ROOM_STATE_ANCHOR_VERSION {
        return Err(RoomStateAnchorError::new(format!(
            "unsupported anchor version {}",
            decoded.version
        )));
    }
    if decoded.store_context != store_context || decoded.relay_pubkey != relay_pubkey {
        return Err(RoomStateAnchorError::new(
            "anchor record belongs to another context or relay",
        ));
    }
    Ok(decoded.generation)
}

fn secret_error(action: &str) -> RoomStateAnchorError {
    RoomStateAnchorError::new(format!("Secret Service could not {action}"))
}

fn encode_context(store_context: &str) -> Result<String, RoomStateAnchorError> {
    if store_context.is_empty() || store_context.len() > MAX_CONTEXT_BYTES {
        return Err(RoomStateAnchorError::new(
            "anchor context must be 1 to 128 bytes",
        ));
    }
    let mut encoded = String::with_capacity(store_context.len());
    for byte in store_context.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02x}"));
        }
    }
    if encoded.len() > MAX_ENCODED_CONTEXT_BYTES || encoded.starts_with('.') {
        return Err(RoomStateAnchorError::new(
            "anchor context is too long or starts with a dot",
        ));
    }
    Ok(encoded)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RoomStateAnchorError> {
    let parent = path
        .parent()
        .ok_or_else(|| RoomStateAnchorError::new("anchor path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RoomStateAnchorError::new("anchor path is not UTF-8"))?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random)
        .map_err(|_| RoomStateAnchorError::new("secure random generation failed"))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| io_error("create anchor temporary", &error))?;
        file.write_all(bytes)
            .map_err(|error| io_error("write anchor", &error))?;
        file.sync_all()
            .map_err(|error| io_error("sync anchor", &error))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| io_error("commit anchor", &error))?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), RoomStateAnchorError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("sync anchor directory", &error))
}

fn io_error(action: &str, error: &std::io::Error) -> RoomStateAnchorError {
    RoomStateAnchorError::new(format!("failed to {action}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &str = "device:test";
    const RELAY: &str = "abababababababababababababababababababababababababababababababab";

    #[test]
    fn secret_record_is_exactly_bound_and_bounded() {
        let encoded = encode_anchor(CONTEXT, RELAY, 42).expect("encode");
        assert_eq!(decode_anchor(&encoded, CONTEXT, RELAY).expect("decode"), 42);
        assert!(decode_anchor(&encoded, "device:other", RELAY).is_err());
        assert!(decode_anchor(&encoded, CONTEXT, &"cd".repeat(32)).is_err());
        assert!(
            decode_anchor(&vec![0; MAX_ANCHOR_FILE_BYTES as usize + 1], CONTEXT, RELAY).is_err()
        );
        assert!(decode_anchor(b"not-json", CONTEXT, RELAY).is_err());
    }

    #[test]
    fn secret_record_rejects_unknown_versions() {
        let encoded = serde_json::to_vec(&AnchorFile {
            version: ROOM_STATE_ANCHOR_VERSION + 1,
            store_context: CONTEXT.to_owned(),
            relay_pubkey: RELAY.to_owned(),
            generation: 1,
        })
        .expect("encode");
        assert!(decode_anchor(&encoded, CONTEXT, RELAY).is_err());
    }
}
