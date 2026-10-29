use crate::sealed::{SealedStore, StoreError};
use omachat_crypto::{NostrIdentityError, NostrSecret};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NOSTR_RECORD: &str = "nostr-identity-v1";

pub struct NostrVault;

impl NostrVault {
    pub fn load(store: &SealedStore) -> Result<Option<NostrSecret>, NostrStoreError> {
        match store.read(NOSTR_RECORD) {
            Ok(bytes) => {
                let stored: StoredNostr =
                    serde_json::from_slice(&bytes).map_err(|_| NostrStoreError::Encoding)?;
                NostrSecret::from_bytes(stored.secret)
                    .map(Some)
                    .map_err(NostrStoreError::Identity)
            }
            Err(StoreError::RecordNotFound) => Ok(None),
            Err(error) => Err(NostrStoreError::Store(error)),
        }
    }

    pub fn save_new(store: &SealedStore, secret: &NostrSecret) -> Result<(), NostrStoreError> {
        if store.read(NOSTR_RECORD).is_ok() {
            return Err(NostrStoreError::AlreadyPresent);
        }
        let stored = StoredNostr {
            secret: *secret_bytes(secret),
        };
        let encoded = serde_json::to_vec(&stored).map_err(|_| NostrStoreError::Encoding)?;
        match store.write(NOSTR_RECORD, &encoded) {
            Ok(()) => Ok(()),
            Err(StoreError::RecordNotFound) => {
                Err(NostrStoreError::Store(StoreError::RecordNotFound))
            }
            Err(error) => Err(NostrStoreError::Store(error)),
        }
    }
}

fn secret_bytes(secret: &NostrSecret) -> &[u8; 32] {
    secret.raw_secret()
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct StoredNostr {
    secret: [u8; 32],
}

#[derive(Debug)]
pub enum NostrStoreError {
    Store(StoreError),
    Identity(NostrIdentityError),
    Encoding,
    AlreadyPresent,
}

impl fmt::Display for NostrStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "nostr identity storage failed: {error}"),
            Self::Identity(error) => write!(formatter, "nostr identity is invalid: {error}"),
            Self::Encoding => formatter.write_str("nostr identity record encoding is invalid"),
            Self::AlreadyPresent => formatter.write_str("a nostr identity is already stored"),
        }
    }
}

impl Error for NostrStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Encoding | Self::AlreadyPresent => None,
        }
    }
}
