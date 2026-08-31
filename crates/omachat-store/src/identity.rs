use crate::sealed::{SealedStore, StoreError};
use omachat_crypto::{IdentityError, IdentitySecrets};
use std::{error::Error, fmt};

const IDENTITY_RECORD: &str = "identity-v1";

/// Persistence boundary for the three long-term identity roots.
pub struct IdentityVault;

impl IdentityVault {
    /// Load a valid identity, creating it only when the identity record is
    /// explicitly absent. Corrupt or unreadable state is never regenerated.
    pub fn load_or_create(store: &SealedStore) -> Result<IdentitySecrets, IdentityStoreError> {
        match store.read(IDENTITY_RECORD) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| IdentityStoreError::Encoding),
            Err(StoreError::RecordNotFound) => {
                let identity = IdentitySecrets::generate().map_err(IdentityStoreError::Identity)?;
                let encoded =
                    serde_json::to_vec(&identity).map_err(|_| IdentityStoreError::Encoding)?;
                store
                    .write(IDENTITY_RECORD, &encoded)
                    .map_err(IdentityStoreError::Store)?;
                Ok(identity)
            }
            Err(error) => Err(IdentityStoreError::Store(error)),
        }
    }
}

#[derive(Debug)]
pub enum IdentityStoreError {
    Store(StoreError),
    Identity(IdentityError),
    Encoding,
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "identity storage failed: {error}"),
            Self::Identity(error) => write!(formatter, "identity generation failed: {error}"),
            Self::Encoding => formatter.write_str("identity record encoding is invalid"),
        }
    }
}

impl Error for IdentityStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Encoding => None,
        }
    }
}
