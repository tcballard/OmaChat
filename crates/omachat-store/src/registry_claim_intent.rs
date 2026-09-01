use std::{error::Error, fmt, io::Cursor};

use omachat_registry::{HandleClaim, HandleClaimSnapshot, RegistryError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{SealedStore, StoreError};

pub const REGISTRY_CLAIM_INTENT_RECORD_NAME: &str = "registry-claim-intent-v1";
const REGISTRY_CLAIM_INTENT_VERSION: u16 = 1;
const MAX_REGISTRY_CLAIM_INTENT_BYTES: usize = 16 * 1024;

/// Crash-safe pending registry mutation owned by one sealed account store.
///
/// A caller persists an exact signed claim before network transmission and
/// clears it only after the corresponding verified receipt is durable. Any
/// ambiguous transport outcome is retried with this same command ID.
pub struct RegistryClaimIntentStore<'store> {
    store: &'store SealedStore,
}

impl<'store> RegistryClaimIntentStore<'store> {
    #[must_use]
    pub const fn new(store: &'store SealedStore) -> Self {
        Self { store }
    }

    pub fn load(&self) -> Result<Option<HandleClaim>, RegistryClaimIntentError> {
        let encoded = match self.store.read(REGISTRY_CLAIM_INTENT_RECORD_NAME) {
            Ok(encoded) => Zeroizing::new(encoded),
            Err(StoreError::RecordNotFound) => return Ok(None),
            Err(error) => return Err(RegistryClaimIntentError::Store(error)),
        };
        let snapshot: RegistryClaimIntentSnapshot =
            serde_json::from_slice(&encoded).map_err(|_| RegistryClaimIntentError::Encoding)?;
        if snapshot.version != REGISTRY_CLAIM_INTENT_VERSION {
            return Err(RegistryClaimIntentError::UnsupportedVersion(
                snapshot.version,
            ));
        }
        snapshot
            .claim
            .to_claim()
            .map(Some)
            .map_err(RegistryClaimIntentError::Registry)
    }

    /// Persist this exact signed command or return the identical pending
    /// command. A different pending command must be resolved first.
    pub fn prepare(&self, claim: &HandleClaim) -> Result<HandleClaim, RegistryClaimIntentError> {
        claim.verify().map_err(RegistryClaimIntentError::Registry)?;
        if let Some(pending) = self.load()? {
            return if pending == *claim {
                Ok(pending)
            } else {
                Err(RegistryClaimIntentError::PendingConflict)
            };
        }
        persist(self.store, claim)?;
        Ok(claim.clone())
    }

    /// Clear only the exact command whose verified receipt is already sealed.
    pub fn clear(&self, completed: &HandleClaim) -> Result<(), RegistryClaimIntentError> {
        let pending = self
            .load()?
            .ok_or(RegistryClaimIntentError::PendingMissing)?;
        if pending != *completed {
            return Err(RegistryClaimIntentError::PendingConflict);
        }
        self.store
            .delete(REGISTRY_CLAIM_INTENT_RECORD_NAME)
            .map_err(RegistryClaimIntentError::Store)
    }
}

fn persist(store: &SealedStore, claim: &HandleClaim) -> Result<(), RegistryClaimIntentError> {
    let snapshot = RegistryClaimIntentSnapshot {
        version: REGISTRY_CLAIM_INTENT_VERSION,
        claim: HandleClaimSnapshot::from_claim(claim),
    };
    let mut encoded = Zeroizing::new([0_u8; MAX_REGISTRY_CLAIM_INTENT_BYTES]);
    let encoded_bytes = {
        let mut writer = Cursor::new(&mut encoded[..]);
        serde_json::to_writer(&mut writer, &snapshot)
            .map_err(|_| RegistryClaimIntentError::Encoding)?;
        usize::try_from(writer.position()).map_err(|_| RegistryClaimIntentError::Encoding)?
    };
    store
        .write(REGISTRY_CLAIM_INTENT_RECORD_NAME, &encoded[..encoded_bytes])
        .map_err(RegistryClaimIntentError::Store)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryClaimIntentSnapshot {
    version: u16,
    claim: HandleClaimSnapshot,
}

#[derive(Debug)]
pub enum RegistryClaimIntentError {
    Store(StoreError),
    Registry(RegistryError),
    Encoding,
    UnsupportedVersion(u16),
    PendingConflict,
    PendingMissing,
}

impl fmt::Display for RegistryClaimIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => {
                write!(formatter, "registry claim intent storage failed: {error}")
            }
            Self::Registry(error) => write!(formatter, "registry claim intent is invalid: {error}"),
            Self::Encoding => formatter.write_str("registry claim intent encoding is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported registry claim intent version {version}"
                )
            }
            Self::PendingConflict => {
                formatter.write_str("a different registry claim is already pending")
            }
            Self::PendingMissing => formatter.write_str("registry claim intent is missing"),
        }
    }
}

impl Error for RegistryClaimIntentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}
