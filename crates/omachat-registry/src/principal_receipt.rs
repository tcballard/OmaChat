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
const MAX_ENCODED_RECEIPT_BYTES: usize = 1024;

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

    /// Encodes the exact signed receipt for bounded storage or transport.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = self.signing_bytes();
        encoded.extend_from_slice(&self.signature);
        encoded
    }

    /// Decodes a receipt only in the context of its authoritative v1 receipt.
    pub fn from_bytes_for_claim_receipt(
        encoded: &[u8],
        claim_receipt: &RegistryReceipt,
        pinned_registry_key: &[u8; 32],
    ) -> Result<Self, PrincipalProofReceiptError> {
        if encoded.len() > MAX_ENCODED_RECEIPT_BYTES {
            return Err(PrincipalProofReceiptError::InvalidEncoding);
        }
        claim_receipt
            .verify(pinned_registry_key)
            .map_err(|_| PrincipalProofReceiptError::ContextMismatch)?;
        let mut cursor = ReceiptCursor::new(encoded);
        if cursor.take_slice(RECEIPT_DOMAIN.len())? != RECEIPT_DOMAIN {
            return Err(PrincipalProofReceiptError::InvalidEncoding);
        }
        let version = cursor.take_u16()?;
        if version != RECEIPT_VERSION {
            return Err(PrincipalProofReceiptError::UnsupportedVersion);
        }
        let sequence = cursor.take_u64()?;
        let command_id = CommandId::from_bytes(cursor.take_array()?);
        let account_id = cursor.take_string()?;
        let handle = cursor.take_string()?;
        let account_revision = cursor.take_u64()?;
        let claim_receipt_hash = cursor.take_array()?;
        let principal_proof_hash = cursor.take_array()?;
        let nostr_public_key = cursor.take_array()?;
        let previous_proof_receipt_hash = cursor.take_array()?;
        let previous_account_proof_receipt_hash = cursor.take_array()?;
        let accepted_at = cursor.take_u64()?;
        let signature = cursor.take_array()?;
        if !cursor.is_empty() {
            return Err(PrincipalProofReceiptError::InvalidEncoding);
        }
        if sequence != claim_receipt.sequence
            || command_id != claim_receipt.command_id
            || account_id != claim_receipt.account_id.as_str()
            || handle != claim_receipt.handle.as_str()
            || account_revision != claim_receipt.account_revision
            || claim_receipt_hash != claim_receipt.receipt_hash()
            || accepted_at != claim_receipt.accepted_at
        {
            return Err(PrincipalProofReceiptError::ContextMismatch);
        }

        let receipt = Self {
            version,
            sequence,
            command_id,
            account_id: claim_receipt.account_id.clone(),
            handle: claim_receipt.handle.clone(),
            account_revision,
            claim_receipt_hash,
            principal_proof_hash,
            nostr_public_key,
            previous_proof_receipt_hash,
            previous_account_proof_receipt_hash,
            accepted_at,
            signature,
        };
        receipt.verify(pinned_registry_key)?;
        Ok(receipt)
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
    /// The encoded receipt is oversized, truncated, malformed, or has trailing bytes.
    InvalidEncoding,
    /// The encoded fields do not match the authoritative v1 claim receipt.
    ContextMismatch,
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
            Self::InvalidEncoding => "principal proof receipt encoding is invalid",
            Self::ContextMismatch => "principal proof receipt context does not match",
        })
    }
}

impl std::error::Error for PrincipalProofReceiptError {}

fn push_u32(destination: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated receipt field must fit in u32");
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
}

struct ReceiptCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> ReceiptCursor<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], PrincipalProofReceiptError> {
        if self.remaining.len() < length {
            return Err(PrincipalProofReceiptError::InvalidEncoding);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], PrincipalProofReceiptError> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| PrincipalProofReceiptError::InvalidEncoding)
    }

    fn take_u16(&mut self) -> Result<u16, PrincipalProofReceiptError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, PrincipalProofReceiptError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, PrincipalProofReceiptError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_string(&mut self) -> Result<String, PrincipalProofReceiptError> {
        let length = self.take_u32()? as usize;
        std::str::from_utf8(self.take_slice(length)?)
            .map(str::to_owned)
            .map_err(|_| PrincipalProofReceiptError::InvalidEncoding)
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
