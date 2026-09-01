use crate::{SealedStore, StoreError};
use omachat_registry::principal_registry::{
    PrincipalRegistryHead, PrincipalRegistryRestoreError, PrincipalRegistrySnapshot,
    PrincipalRegistryState,
};
use std::{error::Error, fmt, io::Cursor};
use zeroize::Zeroizing;

const PRINCIPAL_REGISTRY_STATE_RECORD: &str = "principal-registry-state-v1";
const PRINCIPAL_REGISTRY_STATE_RECORD_VERSION: u16 = 1;
const MAX_PRINCIPAL_REGISTRY_RECORD_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Sealed atomic persistence boundary for proof-bearing principal state.
pub struct PrincipalRegistryVault;

impl PrincipalRegistryVault {
    /// Loads and replays sealed state, checking an optional stronger head anchor.
    ///
    /// The expected head must come from storage whose rollback guarantees are
    /// independent of this record. Without it, a wholly replayed older valid
    /// sealed record cannot be distinguished from current state.
    pub fn load_or_create(
        store: &SealedStore,
        registry_signing_seed: [u8; 32],
        expected_head: Option<&PrincipalRegistryHead>,
    ) -> Result<PrincipalRegistryState, PrincipalRegistryVaultError> {
        match store.read(PRINCIPAL_REGISTRY_STATE_RECORD) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let snapshot: PrincipalRegistrySnapshot = serde_json::from_slice(&bytes)
                    .map_err(|_| PrincipalRegistryVaultError::Encoding)?;
                if snapshot.version != PRINCIPAL_REGISTRY_STATE_RECORD_VERSION {
                    return Err(PrincipalRegistryVaultError::UnsupportedVersion(
                        snapshot.version,
                    ));
                }
                PrincipalRegistryState::restore(registry_signing_seed, snapshot, expected_head)
                    .map_err(PrincipalRegistryVaultError::Restore)
            }
            Err(StoreError::RecordNotFound) => {
                if expected_head.is_some() {
                    return Err(PrincipalRegistryVaultError::MissingAnchoredState);
                }
                let state = PrincipalRegistryState::from_signing_seed(registry_signing_seed);
                Self::persist(store, &state)?;
                Ok(state)
            }
            Err(error) => Err(PrincipalRegistryVaultError::Store(error)),
        }
    }

    /// Atomically replaces the sealed snapshot and returns its anchorable head.
    pub fn persist(
        store: &SealedStore,
        state: &PrincipalRegistryState,
    ) -> Result<PrincipalRegistryHead, PrincipalRegistryVaultError> {
        let snapshot = state.snapshot();
        if snapshot.version != PRINCIPAL_REGISTRY_STATE_RECORD_VERSION {
            return Err(PrincipalRegistryVaultError::UnsupportedVersion(
                snapshot.version,
            ));
        }
        let head = snapshot.head.clone();
        let mut encoded = Zeroizing::new(vec![0_u8; MAX_PRINCIPAL_REGISTRY_RECORD_PLAINTEXT_BYTES]);
        let encoded_bytes = {
            let mut writer = Cursor::new(&mut encoded[..]);
            serde_json::to_writer(&mut writer, &snapshot)
                .map_err(|_| PrincipalRegistryVaultError::Encoding)?;
            usize::try_from(writer.position()).map_err(|_| PrincipalRegistryVaultError::Encoding)?
        };
        store
            .write(PRINCIPAL_REGISTRY_STATE_RECORD, &encoded[..encoded_bytes])
            .map_err(PrincipalRegistryVaultError::Store)?;
        Ok(head)
    }
}

/// Fail-closed proof-bearing registry persistence failures.
#[derive(Debug)]
pub enum PrincipalRegistryVaultError {
    /// The sealed storage operation failed.
    Store(StoreError),
    /// Signed snapshot replay or rollback validation failed.
    Restore(PrincipalRegistryRestoreError),
    /// JSON or bounded-buffer encoding is invalid.
    Encoding,
    /// The persisted snapshot version is unsupported.
    UnsupportedVersion(u16),
    /// A rollback anchor exists but the corresponding state record is absent.
    MissingAnchoredState,
}

impl fmt::Display for PrincipalRegistryVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "principal registry storage failed: {error}"),
            Self::Restore(error) => {
                write!(formatter, "principal registry restoration failed: {error}")
            }
            Self::Encoding => formatter.write_str("principal registry state encoding is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported principal registry state version {version}"
                )
            }
            Self::MissingAnchoredState => {
                formatter.write_str("anchored principal registry state is missing")
            }
        }
    }
}

impl Error for PrincipalRegistryVaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Restore(error) => Some(error),
            _ => None,
        }
    }
}
