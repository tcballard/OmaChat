use std::{error::Error, fmt, io::Cursor};

use omachat_registry::{
    HandleClaimSnapshot, RegistryError, principal_proof::NostrPrincipalControlProof,
    proof_bearing_claim::ProofBearingDeviceHandleClaim,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{SealedStore, StoreError};

pub const PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME: &str = "principal-registry-claim-intent-v1";
const PRINCIPAL_REGISTRY_CLAIM_INTENT_VERSION: u16 = 1;
const MAX_PRINCIPAL_REGISTRY_CLAIM_INTENT_BYTES: usize = 16 * 1024;

/// Crash-safe pending proof-bearing registry mutation for one sealed account.
///
/// The exact root claim and principal proof are persisted before transmission.
/// An ambiguous outcome can therefore replay the same dual-signed command, and
/// completion can clear only the command whose verified evidence is durable.
pub struct PrincipalRegistryClaimIntentStore<'store> {
    store: &'store SealedStore,
}

impl<'store> PrincipalRegistryClaimIntentStore<'store> {
    #[must_use]
    pub const fn new(store: &'store SealedStore) -> Self {
        Self { store }
    }

    pub fn load(
        &self,
    ) -> Result<Option<ProofBearingDeviceHandleClaim>, PrincipalRegistryClaimIntentError> {
        let encoded = match self.store.read(PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME) {
            Ok(encoded) => Zeroizing::new(encoded),
            Err(StoreError::RecordNotFound) => return Ok(None),
            Err(error) => return Err(PrincipalRegistryClaimIntentError::Store(error)),
        };
        let snapshot: PrincipalRegistryClaimIntentSnapshot = serde_json::from_slice(&encoded)
            .map_err(|_| PrincipalRegistryClaimIntentError::Encoding)?;
        if snapshot.version != PRINCIPAL_REGISTRY_CLAIM_INTENT_VERSION {
            return Err(PrincipalRegistryClaimIntentError::UnsupportedVersion(
                snapshot.version,
            ));
        }
        let root_claim = snapshot
            .root_claim
            .to_claim()
            .map_err(PrincipalRegistryClaimIntentError::Registry)?;
        let proof_bytes = hex::decode(snapshot.principal_proof_hex)
            .map_err(|_| PrincipalRegistryClaimIntentError::Encoding)?;
        let principal_proof = NostrPrincipalControlProof::from_bytes(&proof_bytes)
            .map_err(|_| PrincipalRegistryClaimIntentError::InvalidPrincipalClaim)?;
        ProofBearingDeviceHandleClaim::new(root_claim, principal_proof)
            .map(Some)
            .map_err(|_| PrincipalRegistryClaimIntentError::InvalidPrincipalClaim)
    }

    /// Persist this exact dual-signed command or return its identical replay.
    pub fn prepare(
        &self,
        claim: &ProofBearingDeviceHandleClaim,
    ) -> Result<ProofBearingDeviceHandleClaim, PrincipalRegistryClaimIntentError> {
        let validated = ProofBearingDeviceHandleClaim::new(
            claim.claim().clone(),
            claim.principal_proof().clone(),
        )
        .map_err(|_| PrincipalRegistryClaimIntentError::InvalidPrincipalClaim)?;
        if let Some(pending) = self.load()? {
            return if pending == validated {
                Ok(pending)
            } else {
                Err(PrincipalRegistryClaimIntentError::PendingConflict)
            };
        }
        persist(self.store, &validated)?;
        Ok(validated)
    }

    /// Clear only the exact command whose verified evidence is already sealed.
    pub fn clear(
        &self,
        completed: &ProofBearingDeviceHandleClaim,
    ) -> Result<(), PrincipalRegistryClaimIntentError> {
        let pending = self
            .load()?
            .ok_or(PrincipalRegistryClaimIntentError::PendingMissing)?;
        if pending != *completed {
            return Err(PrincipalRegistryClaimIntentError::PendingConflict);
        }
        self.store
            .delete(PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME)
            .map_err(PrincipalRegistryClaimIntentError::Store)
    }
}

fn persist(
    store: &SealedStore,
    claim: &ProofBearingDeviceHandleClaim,
) -> Result<(), PrincipalRegistryClaimIntentError> {
    let snapshot = PrincipalRegistryClaimIntentSnapshot {
        version: PRINCIPAL_REGISTRY_CLAIM_INTENT_VERSION,
        root_claim: HandleClaimSnapshot::from_claim(claim.claim()),
        principal_proof_hex: hex::encode(claim.principal_proof().to_bytes()),
    };
    let mut encoded = Zeroizing::new([0_u8; MAX_PRINCIPAL_REGISTRY_CLAIM_INTENT_BYTES]);
    let encoded_bytes = {
        let mut writer = Cursor::new(&mut encoded[..]);
        serde_json::to_writer(&mut writer, &snapshot)
            .map_err(|_| PrincipalRegistryClaimIntentError::Encoding)?;
        usize::try_from(writer.position())
            .map_err(|_| PrincipalRegistryClaimIntentError::Encoding)?
    };
    store
        .write(
            PRINCIPAL_REGISTRY_CLAIM_INTENT_RECORD_NAME,
            &encoded[..encoded_bytes],
        )
        .map_err(PrincipalRegistryClaimIntentError::Store)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrincipalRegistryClaimIntentSnapshot {
    version: u16,
    root_claim: HandleClaimSnapshot,
    principal_proof_hex: String,
}

#[derive(Debug)]
pub enum PrincipalRegistryClaimIntentError {
    Store(StoreError),
    Registry(RegistryError),
    InvalidPrincipalClaim,
    Encoding,
    UnsupportedVersion(u16),
    PendingConflict,
    PendingMissing,
}

impl fmt::Display for PrincipalRegistryClaimIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(
                formatter,
                "principal registry claim intent storage failed: {error}"
            ),
            Self::Registry(error) => write!(
                formatter,
                "principal registry root claim intent is invalid: {error}"
            ),
            Self::InvalidPrincipalClaim => {
                formatter.write_str("principal registry claim intent proof is invalid")
            }
            Self::Encoding => {
                formatter.write_str("principal registry claim intent encoding is invalid")
            }
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported principal registry claim intent version {version}"
            ),
            Self::PendingConflict => {
                formatter.write_str("a different principal registry claim is already pending")
            }
            Self::PendingMissing => {
                formatter.write_str("principal registry claim intent is missing")
            }
        }
    }
}

impl Error for PrincipalRegistryClaimIntentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}
