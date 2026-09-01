//! Unwired authoritative state for proof-bearing device principal claims.

use crate::{
    HandleClaim, RegistryError, RegistryReceipt, RegistryState,
    proof_bearing_claim::{ProofBearingClaimError, ProofBearingDeviceHandleClaim},
};
use omachat_crypto::GlobalHandle;
use std::collections::BTreeMap;

/// An accepted device-principal binding plus its existing v1 registry receipt.
///
/// The v1 receipt verifies the root-signed handle claim but does not bind the
/// principal proof. This record must not cross a trust boundary until a
/// registry-signed proof receipt is added.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRegistryRecord {
    claim: HandleClaim,
    principal_proof: crate::principal_proof::NostrPrincipalControlProof,
    receipt: RegistryReceipt,
}

impl PrincipalRegistryRecord {
    /// Returns the accepted root-signed claim.
    pub fn claim(&self) -> &HandleClaim {
        &self.claim
    }

    /// Returns the accepted Nostr principal proof.
    pub fn principal_proof(&self) -> &crate::principal_proof::NostrPrincipalControlProof {
        &self.principal_proof
    }

    /// Returns the v1 receipt for the root-signed claim.
    pub fn claim_receipt(&self) -> &RegistryReceipt {
        &self.receipt
    }
}

/// In-memory proof-bearing registry state, not yet wired to host transport.
pub struct PrincipalRegistryState {
    registry: RegistryState,
    records_by_command: BTreeMap<[u8; 32], PrincipalRegistryRecord>,
    current_command_by_account: BTreeMap<String, [u8; 32]>,
    current_command_by_public_key: BTreeMap<[u8; 32], [u8; 32]>,
}

impl PrincipalRegistryState {
    /// Creates empty proof-bearing state with the existing registry signer.
    #[must_use]
    pub fn from_signing_seed(signing_seed: [u8; 32]) -> Self {
        Self {
            registry: RegistryState::from_signing_seed(signing_seed),
            records_by_command: BTreeMap::new(),
            current_command_by_account: BTreeMap::new(),
            current_command_by_public_key: BTreeMap::new(),
        }
    }

    /// Applies one fully validated device proof and its root claim atomically.
    pub fn apply_device(
        &mut self,
        validated: ProofBearingDeviceHandleClaim,
        accepted_at: u64,
    ) -> Result<PrincipalRegistryRecord, PrincipalRegistryError> {
        let claim = validated.claim().clone();
        let principal_proof = validated.principal_proof().clone();
        let payload = principal_proof.payload();
        let command_id = payload.command_id();
        let proof_hash = principal_proof.proof_hash();

        if let Some(existing) = self.records_by_command.get(&command_id) {
            if existing.claim == claim && existing.principal_proof.proof_hash() == proof_hash {
                return Ok(existing.clone());
            }
            return Err(PrincipalRegistryError::CommandIdConflict);
        }

        let account_id = payload.account_id().to_owned();
        let handle = payload.handle().clone();
        let public_key = payload.nostr_public_key();
        if let Some(existing_command) = self.current_command_by_public_key.get(&public_key) {
            let existing = self
                .records_by_command
                .get(existing_command)
                .ok_or(PrincipalRegistryError::InconsistentState)?;
            if existing.principal_proof.payload().account_id() != account_id
                || existing.principal_proof.payload().handle() != &handle
            {
                return Err(PrincipalRegistryError::PublicKeyAlreadyBound {
                    account_id: existing.principal_proof.payload().account_id().to_owned(),
                    handle: existing.principal_proof.payload().handle().clone(),
                });
            }
        }

        let receipt = self
            .registry
            .apply(claim.clone(), accepted_at)
            .map_err(PrincipalRegistryError::Registry)?;
        let record = PrincipalRegistryRecord {
            claim,
            principal_proof,
            receipt,
        };

        if let Some(previous_command) = self
            .current_command_by_account
            .insert(account_id, command_id)
        {
            let previous = self
                .records_by_command
                .get(&previous_command)
                .ok_or(PrincipalRegistryError::InconsistentState)?;
            let previous_public_key = previous.principal_proof.payload().nostr_public_key();
            if previous_public_key != public_key {
                self.current_command_by_public_key
                    .remove(&previous_public_key);
            }
        }
        self.current_command_by_public_key
            .insert(public_key, command_id);
        self.records_by_command.insert(command_id, record.clone());
        Ok(record)
    }

    /// Returns the current proof-bearing record for a Nostr public key.
    #[must_use]
    pub fn public_key_record(&self, public_key: &[u8; 32]) -> Option<&PrincipalRegistryRecord> {
        self.current_command_by_public_key
            .get(public_key)
            .and_then(|command| self.records_by_command.get(command))
    }

    /// Returns the current proof-bearing record for an account identifier.
    #[must_use]
    pub fn account_record(&self, account_id: &str) -> Option<&PrincipalRegistryRecord> {
        self.current_command_by_account
            .get(account_id)
            .and_then(|command| self.records_by_command.get(command))
    }

    /// Returns the latest underlying v1 claim receipt.
    #[must_use]
    pub fn head(&self) -> Option<&RegistryReceipt> {
        self.registry.head()
    }

    /// Returns the pinned registry verification key.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.registry.verifying_key()
    }
}

/// Fail-closed proof-bearing registry transition failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalRegistryError {
    /// The combined root claim and principal proof are invalid.
    InvalidProofBearingClaim(ProofBearingClaimError),
    /// The existing registry state machine rejected the root claim.
    Registry(RegistryError),
    /// A command identifier was reused for different proof-bearing content.
    CommandIdConflict,
    /// A Nostr public key is already associated with another live principal.
    PublicKeyAlreadyBound {
        /// Existing owner account identifier.
        account_id: String,
        /// Existing canonical handle.
        handle: GlobalHandle,
    },
    /// Internal indexes disagree; the state must not continue serving results.
    InconsistentState,
}

impl From<ProofBearingClaimError> for PrincipalRegistryError {
    fn from(error: ProofBearingClaimError) -> Self {
        Self::InvalidProofBearingClaim(error)
    }
}

impl std::fmt::Display for PrincipalRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProofBearingClaim(_) => {
                formatter.write_str("proof-bearing handle claim is invalid")
            }
            Self::Registry(_) => formatter.write_str("root handle claim was rejected"),
            Self::CommandIdConflict => {
                formatter.write_str("command identifier was reused for different content")
            }
            Self::PublicKeyAlreadyBound { account_id, handle } => write!(
                formatter,
                "Nostr public key is already bound to {account_id}/{}",
                handle.as_str()
            ),
            Self::InconsistentState => {
                formatter.write_str("proof-bearing registry indexes are inconsistent")
            }
        }
    }
}

impl std::error::Error for PrincipalRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProofBearingClaim(error) => Some(error),
            Self::Registry(error) => Some(error),
            _ => None,
        }
    }
}
