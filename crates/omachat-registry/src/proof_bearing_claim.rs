//! Exact validation of root-authorised, device-principal-proved handle claims.

use crate::{
    CommandId, HandleClaim,
    principal_proof::{NostrPrincipalControlProof, NostrPrincipalProofError, NostrPrincipalType},
};
use omachat_crypto::SignedLocalAccountBinding;
use sha2::{Digest, Sha256};

const DEVICE_AUTHORISATION_HASH_DOMAIN: &[u8] = b"omachat.device-authorisation-hash.v1\0";

/// Hashes the exact root-signed device binding referenced by a principal proof.
#[must_use]
pub fn device_authorisation_hash(binding: &SignedLocalAccountBinding) -> [u8; 32] {
    let transcript = binding.signing_bytes();
    let transcript_length =
        u64::try_from(transcript.len()).expect("binding transcript must fit in u64");
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_AUTHORISATION_HASH_DOMAIN);
    hasher.update(transcript_length.to_be_bytes());
    hasher.update(transcript);
    hasher.update(binding.signature);
    hasher.finalize().into()
}

/// A v1 handle claim independently authorised by its bound device Nostr key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofBearingDeviceHandleClaim {
    claim: HandleClaim,
    principal_proof: NostrPrincipalControlProof,
}

impl ProofBearingDeviceHandleClaim {
    /// Validates both signatures and every duplicated claim/binding field.
    pub fn new(
        claim: HandleClaim,
        principal_proof: NostrPrincipalControlProof,
    ) -> Result<Self, ProofBearingClaimError> {
        let claim = HandleClaim::from_signed_parts(
            claim.command_id(),
            claim.expected_revision(),
            claim.binding().clone(),
            *claim.proof(),
        )
        .map_err(|_| ProofBearingClaimError::InvalidHandleClaim)?;
        principal_proof
            .verify()
            .map_err(ProofBearingClaimError::InvalidPrincipalProof)?;

        let payload = principal_proof.payload();
        let binding = claim.binding();
        let binding_handle = binding
            .handle
            .as_ref()
            .ok_or(ProofBearingClaimError::MissingHandle)?;

        if payload.principal_type() != NostrPrincipalType::Device {
            return Err(ProofBearingClaimError::PrincipalTypeMismatch);
        }
        if payload.claim_hash() != claim.claim_hash() {
            return Err(ProofBearingClaimError::ClaimHashMismatch);
        }
        if CommandId::from_bytes(payload.command_id()) != claim.command_id() {
            return Err(ProofBearingClaimError::CommandIdMismatch);
        }
        if payload.expected_registry_revision() != claim.expected_revision() {
            return Err(ProofBearingClaimError::ExpectedRevisionMismatch);
        }
        if payload.account_id() != binding.account_id.as_str() {
            return Err(ProofBearingClaimError::AccountMismatch);
        }
        if payload.handle() != binding_handle {
            return Err(ProofBearingClaimError::HandleMismatch);
        }
        if payload.nostr_public_key() != binding.device_keys.nostr_public_key {
            return Err(ProofBearingClaimError::NostrPublicKeyMismatch);
        }
        if payload.authorisation_hash() != device_authorisation_hash(binding) {
            return Err(ProofBearingClaimError::AuthorisationHashMismatch);
        }
        if payload.created_at() < binding.issued_at {
            return Err(ProofBearingClaimError::ProofPredatesAuthorisation);
        }

        Ok(Self {
            claim,
            principal_proof,
        })
    }

    /// Returns the independently validated root-signed handle claim.
    pub fn claim(&self) -> &HandleClaim {
        &self.claim
    }

    /// Returns the independently validated device principal proof.
    pub fn principal_proof(&self) -> &NostrPrincipalControlProof {
        &self.principal_proof
    }
}

/// Fail-closed mismatches between a root claim and a device principal proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofBearingClaimError {
    /// The account-root claim does not verify.
    InvalidHandleClaim,
    /// The principal proof does not verify.
    InvalidPrincipalProof(NostrPrincipalProofError),
    /// The root-signed binding has no handle.
    MissingHandle,
    /// The proof is not for a device principal.
    PrincipalTypeMismatch,
    /// The proof names another exact claim.
    ClaimHashMismatch,
    /// The proof names another command identifier.
    CommandIdMismatch,
    /// The proof names another compare-and-swap revision.
    ExpectedRevisionMismatch,
    /// The proof names another owner account.
    AccountMismatch,
    /// The proof names another handle.
    HandleMismatch,
    /// The proving Nostr key is not the root-bound device Nostr key.
    NostrPublicKeyMismatch,
    /// The proof names another root-signed device authorisation.
    AuthorisationHashMismatch,
    /// The principal proof predates the root-signed device binding.
    ProofPredatesAuthorisation,
}

impl std::fmt::Display for ProofBearingClaimError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHandleClaim => "account-root handle claim is invalid",
            Self::InvalidPrincipalProof(_) => "Nostr principal proof is invalid",
            Self::MissingHandle => "root-signed binding has no handle",
            Self::PrincipalTypeMismatch => "principal proof is not a device proof",
            Self::ClaimHashMismatch => "principal proof claim hash does not match",
            Self::CommandIdMismatch => "principal proof command identifier does not match",
            Self::ExpectedRevisionMismatch => "principal proof registry revision does not match",
            Self::AccountMismatch => "principal proof account does not match",
            Self::HandleMismatch => "principal proof handle does not match",
            Self::NostrPublicKeyMismatch => "principal proof key is not the bound device key",
            Self::AuthorisationHashMismatch => "principal proof authorisation hash does not match",
            Self::ProofPredatesAuthorisation => "principal proof predates device authorisation",
        })
    }
}

impl std::error::Error for ProofBearingClaimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPrincipalProof(error) => Some(error),
            _ => None,
        }
    }
}
