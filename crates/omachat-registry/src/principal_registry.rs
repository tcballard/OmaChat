//! Unwired authoritative state for proof-bearing device principal claims.

use crate::{
    HandleClaim, RegistryError, RegistryReceipt, RegistryState,
    principal_receipt::PrincipalProofReceipt,
    proof_bearing_claim::{ProofBearingClaimError, ProofBearingDeviceHandleClaim},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use omachat_crypto::{GlobalHandle, SignedLocalAccountBinding};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const SNAPSHOT_DOMAIN: &[u8] = b"omachat.principal-registry-snapshot.v1\0";
const SNAPSHOT_VERSION: u16 = 1;
const GENESIS_HASH: [u8; 32] = [0; 32];

/// An accepted device-principal binding with claim and proof receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRegistryRecord {
    claim: HandleClaim,
    principal_proof: crate::principal_proof::NostrPrincipalControlProof,
    receipt: RegistryReceipt,
    principal_receipt: PrincipalProofReceipt,
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

    /// Returns the registry-signed receipt binding the exact principal proof.
    pub fn principal_receipt(&self) -> &PrincipalProofReceipt {
        &self.principal_receipt
    }
}

/// In-memory proof-bearing registry state, not yet wired to host transport.
pub struct PrincipalRegistryState {
    registry: RegistryState,
    proof_signing_key: SigningKey,
    records_by_command: BTreeMap<[u8; 32], PrincipalRegistryRecord>,
    current_command_by_account: BTreeMap<String, [u8; 32]>,
    current_command_by_public_key: BTreeMap<[u8; 32], [u8; 32]>,
    proof_head: Option<PrincipalProofReceipt>,
    account_proof_heads: BTreeMap<String, PrincipalProofReceipt>,
}

/// Signed commitment used to detect stale or rolled-back snapshot state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistryHead {
    /// Number of proof-bearing transitions committed to the snapshot.
    pub entry_count: u64,
    /// Sequence of the final v1 claim receipt, or zero for empty state.
    pub claim_sequence: u64,
    /// Hash of the final v1 claim receipt, or zero for empty state.
    pub claim_receipt_hash: [u8; 32],
    /// Hash of the final principal proof receipt, or zero for empty state.
    pub principal_receipt_hash: [u8; 32],
}

/// One exact replay entry in a signed principal-registry snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistrySnapshotEntry {
    /// Exact idempotency command identifier.
    pub command_id: [u8; 32],
    /// Exact compare-and-swap revision.
    pub expected_revision: u64,
    /// Root-signed local account/device binding.
    pub binding: SignedLocalAccountBinding,
    /// Account-root claim proof bytes.
    pub claim_proof: Vec<u8>,
    /// Hash of the exact reconstructed root claim.
    pub claim_hash: [u8; 32],
    /// Canonical encoded Nostr principal proof bytes.
    pub principal_proof: Vec<u8>,
    /// Authoritative acceptance time used by the state transition.
    pub accepted_at: u64,
    /// Expected regenerated v1 claim-receipt hash.
    pub claim_receipt_hash: [u8; 32],
    /// Expected regenerated principal proof-receipt hash.
    pub principal_receipt_hash: [u8; 32],
}

/// Registry-signed replay log for proof-bearing principal state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistrySnapshot {
    /// Snapshot format version.
    pub version: u16,
    /// Ordered proof-bearing transition log.
    pub entries: Vec<PrincipalRegistrySnapshotEntry>,
    /// Signed final-state commitment.
    pub head: PrincipalRegistryHead,
    /// Registry Ed25519 signature over the canonical snapshot commitment.
    pub signature: Vec<u8>,
}

impl PrincipalRegistryState {
    /// Creates empty proof-bearing state with the existing registry signer.
    #[must_use]
    pub fn from_signing_seed(signing_seed: [u8; 32]) -> Self {
        Self {
            registry: RegistryState::from_signing_seed(signing_seed),
            proof_signing_key: SigningKey::from_bytes(&signing_seed),
            records_by_command: BTreeMap::new(),
            current_command_by_account: BTreeMap::new(),
            current_command_by_public_key: BTreeMap::new(),
            proof_head: None,
            account_proof_heads: BTreeMap::new(),
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
        let previous_proof_receipt_hash = self
            .proof_head
            .as_ref()
            .map(PrincipalProofReceipt::receipt_hash)
            .unwrap_or([0; 32]);
        let previous_account_proof_receipt_hash = self
            .account_proof_heads
            .get(&account_id)
            .map(PrincipalProofReceipt::receipt_hash)
            .unwrap_or([0; 32]);
        let principal_receipt = PrincipalProofReceipt::issue(
            &self.proof_signing_key,
            &validated,
            &receipt,
            previous_proof_receipt_hash,
            previous_account_proof_receipt_hash,
        );
        let record = PrincipalRegistryRecord {
            claim,
            principal_proof,
            receipt,
            principal_receipt: principal_receipt.clone(),
        };

        if let Some(previous_command) = self
            .current_command_by_account
            .insert(account_id.clone(), command_id)
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
        self.proof_head = Some(principal_receipt.clone());
        self.account_proof_heads
            .insert(account_id, principal_receipt);
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

    /// Produces a signed deterministic replay snapshot of current state.
    #[must_use]
    pub fn snapshot(&self) -> PrincipalRegistrySnapshot {
        let mut records: Vec<&PrincipalRegistryRecord> = self.records_by_command.values().collect();
        records.sort_by_key(|record| record.receipt.sequence);
        let entries = records
            .into_iter()
            .map(|record| PrincipalRegistrySnapshotEntry {
                command_id: *record.claim.command_id().as_bytes(),
                expected_revision: record.claim.expected_revision(),
                binding: record.claim.binding().clone(),
                claim_proof: record.claim.proof().to_vec(),
                claim_hash: record.claim.claim_hash(),
                principal_proof: record.principal_proof.to_bytes(),
                accepted_at: record.receipt.accepted_at,
                claim_receipt_hash: record.receipt.receipt_hash(),
                principal_receipt_hash: record.principal_receipt.receipt_hash(),
            })
            .collect();
        let mut snapshot = PrincipalRegistrySnapshot {
            version: SNAPSHOT_VERSION,
            entries,
            head: self.snapshot_head(),
            signature: Vec::new(),
        };
        snapshot.signature = self
            .proof_signing_key
            .sign(
                &snapshot
                    .signing_bytes()
                    .expect("current principal registry state must encode"),
            )
            .to_bytes()
            .to_vec();
        snapshot
    }

    /// Restores only by replaying and independently checking every transition.
    pub fn restore(
        signing_seed: [u8; 32],
        snapshot: PrincipalRegistrySnapshot,
        expected_head: Option<&PrincipalRegistryHead>,
    ) -> Result<Self, PrincipalRegistryRestoreError> {
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(PrincipalRegistryRestoreError::UnsupportedVersion);
        }
        let signature: [u8; 64] = snapshot
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| PrincipalRegistryRestoreError::InvalidEncoding)?;
        VerifyingKey::from(&SigningKey::from_bytes(&signing_seed))
            .verify_strict(
                &snapshot.signing_bytes()?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| PrincipalRegistryRestoreError::InvalidSignature)?;
        if expected_head.is_some_and(|expected| expected != &snapshot.head) {
            return Err(PrincipalRegistryRestoreError::RollbackDetected);
        }

        let mut restored = Self::from_signing_seed(signing_seed);
        for (index, entry) in snapshot.entries.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .map_err(|_| PrincipalRegistryRestoreError::InvalidEncoding)?
                + 1;
            let claim_proof: [u8; 64] = entry
                .claim_proof
                .as_slice()
                .try_into()
                .map_err(|_| PrincipalRegistryRestoreError::InvalidEncoding)?;
            let claim = HandleClaim::from_signed_parts(
                crate::CommandId::from_bytes(entry.command_id),
                entry.expected_revision,
                entry.binding.clone(),
                claim_proof,
            )
            .map_err(|_| PrincipalRegistryRestoreError::InvalidEvidence)?;
            if claim.claim_hash() != entry.claim_hash {
                return Err(PrincipalRegistryRestoreError::InvalidEvidence);
            }
            let principal_proof = crate::principal_proof::NostrPrincipalControlProof::from_bytes(
                &entry.principal_proof,
            )
            .map_err(|_| PrincipalRegistryRestoreError::InvalidEvidence)?;
            let validated = ProofBearingDeviceHandleClaim::new(claim, principal_proof)
                .map_err(|_| PrincipalRegistryRestoreError::InvalidEvidence)?;
            let record = restored
                .apply_device(validated, entry.accepted_at)
                .map_err(PrincipalRegistryRestoreError::Transition)?;
            if record.receipt.sequence != expected_sequence
                || record.receipt.receipt_hash() != entry.claim_receipt_hash
                || record.principal_receipt.receipt_hash() != entry.principal_receipt_hash
            {
                return Err(PrincipalRegistryRestoreError::InvalidEvidence);
            }
        }
        if restored.snapshot_head() != snapshot.head {
            return Err(PrincipalRegistryRestoreError::InvalidHead);
        }
        Ok(restored)
    }

    fn snapshot_head(&self) -> PrincipalRegistryHead {
        PrincipalRegistryHead {
            entry_count: u64::try_from(self.records_by_command.len())
                .expect("principal registry entry count must fit in u64"),
            claim_sequence: self
                .registry
                .head()
                .map(|receipt| receipt.sequence)
                .unwrap_or(0),
            claim_receipt_hash: self
                .registry
                .head()
                .map(RegistryReceipt::receipt_hash)
                .unwrap_or(GENESIS_HASH),
            principal_receipt_hash: self
                .proof_head
                .as_ref()
                .map(PrincipalProofReceipt::receipt_hash)
                .unwrap_or(GENESIS_HASH),
        }
    }
}

impl PrincipalRegistrySnapshot {
    fn signing_bytes(&self) -> Result<Vec<u8>, PrincipalRegistryRestoreError> {
        let entry_count = u64::try_from(self.entries.len())
            .map_err(|_| PrincipalRegistryRestoreError::InvalidEncoding)?;
        if entry_count != self.head.entry_count {
            return Err(PrincipalRegistryRestoreError::InvalidHead);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SNAPSHOT_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&entry_count.to_be_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.claim_hash);
            push_u64(&mut bytes, &entry.principal_proof)?;
            bytes.extend_from_slice(&entry.accepted_at.to_be_bytes());
            bytes.extend_from_slice(&entry.claim_receipt_hash);
            bytes.extend_from_slice(&entry.principal_receipt_hash);
        }
        bytes.extend_from_slice(&self.head.entry_count.to_be_bytes());
        bytes.extend_from_slice(&self.head.claim_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.head.claim_receipt_hash);
        bytes.extend_from_slice(&self.head.principal_receipt_hash);
        Ok(bytes)
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

/// Fail-closed signed snapshot restoration errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalRegistryRestoreError {
    /// The snapshot format version is unsupported.
    UnsupportedVersion,
    /// Hex, lengths, or canonical fields cannot be decoded.
    InvalidEncoding,
    /// The snapshot signature does not verify under the registry key.
    InvalidSignature,
    /// The signed head does not match the entries or replayed state.
    InvalidHead,
    /// The supplied durable head anchor proves this is an older snapshot.
    RollbackDetected,
    /// A claim, principal proof, or regenerated receipt does not match.
    InvalidEvidence,
    /// Replaying a transition failed under authoritative state rules.
    Transition(PrincipalRegistryError),
}

impl std::fmt::Display for PrincipalRegistryRestoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "principal registry snapshot version is unsupported",
            Self::InvalidEncoding => "principal registry snapshot encoding is invalid",
            Self::InvalidSignature => "principal registry snapshot signature is invalid",
            Self::InvalidHead => "principal registry snapshot head is invalid",
            Self::RollbackDetected => "principal registry snapshot rollback was detected",
            Self::InvalidEvidence => "principal registry snapshot evidence is invalid",
            Self::Transition(_) => "principal registry snapshot transition was rejected",
        })
    }
}

impl std::error::Error for PrincipalRegistryRestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transition(error) => Some(error),
            _ => None,
        }
    }
}

fn push_u64(destination: &mut Vec<u8>, value: &[u8]) -> Result<(), PrincipalRegistryRestoreError> {
    let length =
        u64::try_from(value.len()).map_err(|_| PrincipalRegistryRestoreError::InvalidEncoding)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
    Ok(())
}
