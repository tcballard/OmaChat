//! Registry-signed evidence for accepted Nostr principal-control proofs.

use crate::{
    CommandId, RegisteredHandle, RegistryReceipt,
    proof_bearing_claim::ProofBearingDeviceHandleClaim,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use omachat_crypto::AccountId;
use sha2::{Digest, Sha256};

const RECEIPT_DOMAIN: &[u8] = b"omachat.registry.principal-proof-receipt.v1\0";
const RECEIPT_HASH_DOMAIN: &[u8] = b"omachat.registry.principal-proof-receipt-hash.v1\0";
const RECEIPT_VERSION: u16 = 1;
const GENESIS_HASH: [u8; 32] = [0; 32];

/// Registry-signed acceptance of one exact principal proof and v1 claim receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalProofReceipt {
    /// Receipt format version.
    pub version: u16,
    /// Sequence of the corresponding v1 registry transition.
    pub sequence: u64,
    /// Exact idempotency command identifier.
    pub command_id: CommandId,
    /// Owner account identifier.
    pub account_id: AccountId,
    /// Canonical accepted handle.
    pub handle: RegisteredHandle,
    /// Current per-account registry revision.
    pub account_revision: u64,
    /// Hash of the registry-signed v1 claim receipt.
    pub claim_receipt_hash: [u8; 32],
    /// Hash of the complete encoded Nostr principal proof.
    pub principal_proof_hash: [u8; 32],
    /// Proved x-only Nostr public key.
    pub nostr_public_key: [u8; 32],
    /// Previous global proof-receipt hash, or zero for genesis.
    pub previous_proof_receipt_hash: [u8; 32],
    /// Previous proof-receipt hash for this account, or zero for genesis.
    pub previous_account_proof_receipt_hash: [u8; 32],
    /// Authoritative acceptance time copied from the v1 claim receipt.
    pub accepted_at: u64,
    /// Registry Ed25519 signature over [`Self::signing_bytes`].
    pub signature: [u8; 64],
}

impl PrincipalProofReceipt {
    pub(crate) fn issue(
        signing_key: &SigningKey,
        validated: &ProofBearingDeviceHandleClaim,
        claim_receipt: &RegistryReceipt,
        previous_proof_receipt_hash: [u8; 32],
        previous_account_proof_receipt_hash: [u8; 32],
    ) -> Self {
        let payload = validated.principal_proof().payload();
        let mut receipt = Self {
            version: RECEIPT_VERSION,
            sequence: claim_receipt.sequence,
            command_id: claim_receipt.command_id,
            account_id: claim_receipt.account_id.clone(),
            handle: claim_receipt.handle.clone(),
            account_revision: claim_receipt.account_revision,
            claim_receipt_hash: claim_receipt.receipt_hash(),
            principal_proof_hash: validated.principal_proof().proof_hash(),
            nostr_public_key: payload.nostr_public_key(),
            previous_proof_receipt_hash,
            previous_account_proof_receipt_hash,
            accepted_at: claim_receipt.accepted_at,
            signature: [0; 64],
        };
        receipt.signature = signing_key.sign(&receipt.signing_bytes()).to_bytes();
        receipt
    }

    /// Returns the deterministic registry-signed transcript.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let account_id = self.account_id.as_str().as_bytes();
        let handle = self.handle.as_str().as_bytes();
        let mut bytes = Vec::with_capacity(
            RECEIPT_DOMAIN.len()
                + 2
                + 8
                + 32
                + 4
                + account_id.len()
                + 4
                + handle.len()
                + 8
                + 32 * 5
                + 8,
        );
        bytes.extend_from_slice(RECEIPT_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(self.command_id.as_bytes());
        push_u32(&mut bytes, account_id);
        push_u32(&mut bytes, handle);
        bytes.extend_from_slice(&self.account_revision.to_be_bytes());
        bytes.extend_from_slice(&self.claim_receipt_hash);
        bytes.extend_from_slice(&self.principal_proof_hash);
        bytes.extend_from_slice(&self.nostr_public_key);
        bytes.extend_from_slice(&self.previous_proof_receipt_hash);
        bytes.extend_from_slice(&self.previous_account_proof_receipt_hash);
        bytes.extend_from_slice(&self.accepted_at.to_be_bytes());
        bytes
    }

    /// Verifies this receipt against an independently pinned registry key.
    pub fn verify(&self, pinned_registry_key: &[u8; 32]) -> Result<(), PrincipalProofReceiptError> {
        if self.version != RECEIPT_VERSION {
            return Err(PrincipalProofReceiptError::UnsupportedVersion);
        }
        VerifyingKey::from_bytes(pinned_registry_key)
            .map_err(|_| PrincipalProofReceiptError::InvalidRegistryKey)?
            .verify_strict(
                &self.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| PrincipalProofReceiptError::InvalidSignature)
    }

    /// Verifies that this receipt binds the exact claim receipt and proof.
    pub fn verify_for(
        &self,
        pinned_registry_key: &[u8; 32],
        validated: &ProofBearingDeviceHandleClaim,
        claim_receipt: &RegistryReceipt,
    ) -> Result<(), PrincipalProofReceiptError> {
        self.verify(pinned_registry_key)?;
        claim_receipt
            .verify_for_claim(pinned_registry_key, validated.claim())
            .map_err(|_| PrincipalProofReceiptError::EvidenceMismatch)?;
        let payload = validated.principal_proof().payload();
        if self.sequence != claim_receipt.sequence
            || self.command_id != claim_receipt.command_id
            || self.command_id != CommandId::from_bytes(payload.command_id())
            || self.account_id != claim_receipt.account_id
            || self.account_id.as_str() != payload.account_id()
            || self.handle != claim_receipt.handle
            || self.handle.as_str() != payload.handle().as_str()
            || self.account_revision != claim_receipt.account_revision
            || self.claim_receipt_hash != claim_receipt.receipt_hash()
            || self.principal_proof_hash != validated.principal_proof().proof_hash()
            || self.nostr_public_key != payload.nostr_public_key()
            || self.accepted_at != claim_receipt.accepted_at
        {
            return Err(PrincipalProofReceiptError::EvidenceMismatch);
        }
        Ok(())
    }

    /// Verifies the global proof-receipt chain link.
    pub fn verify_after(
        &self,
        pinned_registry_key: &[u8; 32],
        previous: Option<&Self>,
    ) -> Result<(), PrincipalProofReceiptError> {
        self.verify(pinned_registry_key)?;
        let expected = previous.map(Self::receipt_hash).unwrap_or(GENESIS_HASH);
        if self.previous_proof_receipt_hash != expected
            || previous.is_some_and(|receipt| receipt.sequence >= self.sequence)
        {
            return Err(PrincipalProofReceiptError::InvalidGlobalChain);
        }
        Ok(())
    }

    /// Verifies the per-account proof-receipt chain link.
    pub fn verify_account_after(
        &self,
        pinned_registry_key: &[u8; 32],
        previous: Option<&Self>,
    ) -> Result<(), PrincipalProofReceiptError> {
        self.verify(pinned_registry_key)?;
        let expected = previous.map(Self::receipt_hash).unwrap_or(GENESIS_HASH);
        if self.previous_account_proof_receipt_hash != expected
            || previous.is_some_and(|receipt| {
                receipt.sequence >= self.sequence || receipt.account_id != self.account_id
            })
        {
            return Err(PrincipalProofReceiptError::InvalidAccountChain);
        }
        Ok(())
    }

    /// Returns the domain-separated hash chained by later proof receipts.
    #[must_use]
    pub fn receipt_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_HASH_DOMAIN);
        hasher.update(self.signing_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }
}

/// Fail-closed principal proof-receipt verification failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalProofReceiptError {
    /// The receipt version is unsupported.
    UnsupportedVersion,
    /// The independently pinned registry key is invalid.
    InvalidRegistryKey,
    /// The registry signature does not verify.
    InvalidSignature,
    /// The receipt does not bind the supplied root claim receipt and proof.
    EvidenceMismatch,
    /// The global proof-receipt chain is invalid.
    InvalidGlobalChain,
    /// The per-account proof-receipt chain is invalid.
    InvalidAccountChain,
}

impl std::fmt::Display for PrincipalProofReceiptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "principal proof receipt version is unsupported",
            Self::InvalidRegistryKey => "pinned registry key is invalid",
            Self::InvalidSignature => "principal proof receipt signature is invalid",
            Self::EvidenceMismatch => "principal proof receipt evidence does not match",
            Self::InvalidGlobalChain => "principal proof receipt global chain is invalid",
            Self::InvalidAccountChain => "principal proof receipt account chain is invalid",
        })
    }
}

impl std::error::Error for PrincipalProofReceiptError {}

fn push_u32(destination: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated receipt field must fit in u32");
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
}
