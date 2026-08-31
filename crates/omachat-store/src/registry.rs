use crate::{SealedStore, StoreError};
use omachat_registry::{RegistryError, RegistryState, RegistryStateSnapshot};
use std::{error::Error, fmt, io::Cursor};
use zeroize::Zeroizing;

const REGISTRY_STATE_RECORD: &str = "registry-state-v1";
const REGISTRY_STATE_RECORD_VERSION: u16 = 1;
const MAX_REGISTRY_RECORD_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Persistence boundary for the registry state machine.
pub struct RegistryVault;

impl RegistryVault {
    /// Load and validate the persisted registry state, creating a fresh state only
    /// when no record exists.
    pub fn load_or_create(
        store: &SealedStore,
        registry_signing_seed: [u8; 32],
    ) -> Result<RegistryState, RegistryVaultError> {
        match store.read(REGISTRY_STATE_RECORD) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let snapshot: RegistryStateSnapshot =
                    serde_json::from_slice(&bytes).map_err(|_| RegistryVaultError::Encoding)?;
                RegistryState::restore(registry_signing_seed, snapshot).map_err(|error| match error
                {
                    RegistryError::UnsupportedStateVersion(version) => {
                        RegistryVaultError::UnsupportedVersion(version)
                    }
                    _ => RegistryVaultError::Registry(error),
                })
            }
            Err(StoreError::RecordNotFound) => {
                let state = RegistryState::from_signing_seed(registry_signing_seed);
                Self::persist(store, &state)?;
                Ok(state)
            }
            Err(error) => Err(RegistryVaultError::Store(error)),
        }
    }

    /// Persist a registry snapshot for crash-safe restart behavior.
    pub fn persist(store: &SealedStore, state: &RegistryState) -> Result<(), RegistryVaultError> {
        let snapshot = state.snapshot();
        if snapshot.version != REGISTRY_STATE_RECORD_VERSION {
            return Err(RegistryVaultError::UnsupportedVersion(snapshot.version));
        }

        let mut encoded = Zeroizing::new([0_u8; MAX_REGISTRY_RECORD_PLAINTEXT_BYTES]);
        let encoded_bytes = {
            let mut writer = Cursor::new(&mut encoded[..]);
            serde_json::to_writer(&mut writer, &snapshot)
                .map_err(|_| RegistryVaultError::Encoding)?;
            usize::try_from(writer.position()).map_err(|_| RegistryVaultError::Encoding)?
        };

        store
            .write(REGISTRY_STATE_RECORD, &encoded[..encoded_bytes])
            .map_err(RegistryVaultError::Store)
    }
}

#[derive(Debug)]
pub enum RegistryVaultError {
    Store(StoreError),
    Registry(RegistryError),
    Encoding,
    UnsupportedVersion(u16),
}

impl fmt::Display for RegistryVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "registry state storage failed: {error}"),
            Self::Registry(error) => write!(formatter, "registry state validation failed: {error}"),
            Self::Encoding => formatter.write_str("registry state record encoding is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported registry state version {version}")
            }
        }
    }
}

impl Error for RegistryVaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}
