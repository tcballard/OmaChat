//! Nostr principal-control proofs bound to exact registry claims.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use omachat_crypto::GlobalHandle;
use sha2::{Digest, Sha256};

const PROOF_DOMAIN: &[u8] = b"omachat.nostr-principal-control.v1\0";
const PROOF_VERSION: u16 = 1;
const ZERO_AUXILIARY_RANDOMNESS: [u8; 32] = [0; 32];

/// The role of a Nostr key in an account-root-authorised registry binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NostrPrincipalType {
    /// A Nostr key bound to one authorised device.
    Device = 1,
    /// An independently authoring Nostr agent key.
    Agent = 2,
    /// A future explicitly bound account-wide human Nostr principal.
    Account = 3,
}

/// The exact canonical payload signed by a Nostr principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrPrincipalControlPayload {
    claim_hash: [u8; 32],
    command_id: [u8; 32],
    expected_registry_revision: u64,
    account_id: String,
    handle: GlobalHandle,
    principal_type: NostrPrincipalType,
    nostr_public_key: [u8; 32],
    authorisation_hash: [u8; 32],
    created_at: u64,
}

impl NostrPrincipalControlPayload {
    /// Constructs and validates a proof payload without signing it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        claim_hash: [u8; 32],
        command_id: [u8; 32],
        expected_registry_revision: u64,
        account_id: &str,
        handle: &str,
        principal_type: NostrPrincipalType,
        nostr_public_key: [u8; 32],
        authorisation_hash: [u8; 32],
        created_at: u64,
    ) -> Result<Self, NostrPrincipalProofError> {
        if claim_hash == [0; 32] {
            return Err(NostrPrincipalProofError::InvalidClaimHash);
        }
        if command_id == [0; 32] {
            return Err(NostrPrincipalProofError::InvalidCommandId);
        }
        if !valid_account_id(account_id) {
            return Err(NostrPrincipalProofError::InvalidAccountId);
        }
        let handle =
            GlobalHandle::parse(handle).map_err(|_| NostrPrincipalProofError::InvalidHandle)?;
        VerifyingKey::from_bytes(&nostr_public_key)
            .map_err(|_| NostrPrincipalProofError::InvalidNostrPublicKey)?;
        if authorisation_hash == [0; 32] {
            return Err(NostrPrincipalProofError::InvalidAuthorisationHash);
        }
        if created_at == 0 {
            return Err(NostrPrincipalProofError::InvalidCreationTime);
        }

        Ok(Self {
            claim_hash,
            command_id,
            expected_registry_revision,
            account_id: account_id.to_owned(),
            handle,
            principal_type,
            nostr_public_key,
            authorisation_hash,
            created_at,
        })
    }

    /// Returns the canonical binary transcript covered by the proof.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let account_id = self.account_id.as_bytes();
        let handle = self.handle.as_str().as_bytes();
        let mut bytes = Vec::with_capacity(
            PROOF_DOMAIN.len()
                + 2
                + 32
                + 32
                + 8
                + 4
                + account_id.len()
                + 4
                + handle.len()
                + 1
                + 32
                + 32
                + 8,
        );
        bytes.extend_from_slice(PROOF_DOMAIN);
        bytes.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.claim_hash);
        bytes.extend_from_slice(&self.command_id);
        bytes.extend_from_slice(&self.expected_registry_revision.to_be_bytes());
        push_u32(&mut bytes, account_id);
        push_u32(&mut bytes, handle);
        bytes.push(self.principal_type as u8);
        bytes.extend_from_slice(&self.nostr_public_key);
        bytes.extend_from_slice(&self.authorisation_hash);
        bytes.extend_from_slice(&self.created_at.to_be_bytes());
        bytes
    }

    /// Returns the SHA-256 digest signed with BIP-340.
    pub fn proof_digest(&self) -> [u8; 32] {
        Sha256::digest(self.signing_bytes()).into()
    }

    /// Returns the claim hash bound by this proof.
    pub fn claim_hash(&self) -> [u8; 32] {
        self.claim_hash
    }

    /// Returns the registry command identifier bound by this proof.
    pub fn command_id(&self) -> [u8; 32] {
        self.command_id
    }

    /// Returns the exact compare-and-swap revision bound by this proof.
    pub fn expected_registry_revision(&self) -> u64 {
        self.expected_registry_revision
    }

    /// Returns the owner account identifier.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the canonical handle.
    pub fn handle(&self) -> &GlobalHandle {
        &self.handle
    }

    /// Returns the principal role.
    pub fn principal_type(&self) -> NostrPrincipalType {
        self.principal_type
    }

    /// Returns the x-only Nostr public key.
    pub fn nostr_public_key(&self) -> [u8; 32] {
        self.nostr_public_key
    }

    /// Returns the root-signed principal authorisation hash.
    pub fn authorisation_hash(&self) -> [u8; 32] {
        self.authorisation_hash
    }

    /// Returns the proof creation time.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
}

/// A validated payload and its Nostr principal's BIP-340 signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrPrincipalControlProof {
    payload: NostrPrincipalControlPayload,
    signature: [u8; 64],
}

impl NostrPrincipalControlProof {
    /// Signs a payload after proving that the secret matches its public key.
    pub fn sign(
        payload: NostrPrincipalControlPayload,
        nostr_secret_key: [u8; 32],
    ) -> Result<Self, NostrPrincipalProofError> {
        let signing_key = SigningKey::from_bytes(&nostr_secret_key)
            .map_err(|_| NostrPrincipalProofError::InvalidNostrSecretKey)?;
        let derived_public_key: [u8; 32] = signing_key.verifying_key().to_bytes().into();
        if derived_public_key != payload.nostr_public_key {
            return Err(NostrPrincipalProofError::PublicKeyMismatch);
        }
        let signature: [u8; 64] = signing_key
            .sign_raw(&payload.proof_digest(), &ZERO_AUXILIARY_RANDOMNESS)
            .map_err(|_| NostrPrincipalProofError::SigningFailed)?
            .to_bytes();
        Ok(Self { payload, signature })
    }

    /// Reconstructs a proof from wire parts and rejects invalid signatures.
    pub fn from_parts(
        payload: NostrPrincipalControlPayload,
        signature: [u8; 64],
    ) -> Result<Self, NostrPrincipalProofError> {
        let proof = Self { payload, signature };
        proof.verify()?;
        Ok(proof)
    }

    /// Verifies the signature against the payload's x-only Nostr key.
    pub fn verify(&self) -> Result<(), NostrPrincipalProofError> {
        let verifying_key = VerifyingKey::from_bytes(&self.payload.nostr_public_key)
            .map_err(|_| NostrPrincipalProofError::InvalidNostrPublicKey)?;
        let signature = Signature::try_from(&self.signature[..])
            .map_err(|_| NostrPrincipalProofError::InvalidSignature)?;
        verifying_key
            .verify_raw(&self.payload.proof_digest(), &signature)
            .map_err(|_| NostrPrincipalProofError::InvalidSignature)
    }

    /// Returns the signed payload.
    pub fn payload(&self) -> &NostrPrincipalControlPayload {
        &self.payload
    }

    /// Returns the canonical 64-byte BIP-340 signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Fail-closed construction and verification errors for principal proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrPrincipalProofError {
    /// The claim hash is the reserved all-zero value.
    InvalidClaimHash,
    /// The command identifier is the reserved all-zero value.
    InvalidCommandId,
    /// The account identifier is not canonical.
    InvalidAccountId,
    /// The handle is not a valid registry candidate.
    InvalidHandle,
    /// The x-only Nostr public key is invalid.
    InvalidNostrPublicKey,
    /// The root-signed authorisation hash is the reserved all-zero value.
    InvalidAuthorisationHash,
    /// The proof creation time is invalid.
    InvalidCreationTime,
    /// The Nostr secret key is invalid.
    InvalidNostrSecretKey,
    /// The Nostr secret and public keys do not match.
    PublicKeyMismatch,
    /// BIP-340 signing failed.
    SigningFailed,
    /// The BIP-340 signature is malformed or does not verify.
    InvalidSignature,
}

impl std::fmt::Display for NostrPrincipalProofError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidClaimHash => "claim hash must not be all zero",
            Self::InvalidCommandId => "command identifier must not be all zero",
            Self::InvalidAccountId => "account identifier is not canonical",
            Self::InvalidHandle => "handle is not a valid registry candidate",
            Self::InvalidNostrPublicKey => "Nostr public key is invalid",
            Self::InvalidAuthorisationHash => "authorisation hash must not be all zero",
            Self::InvalidCreationTime => "proof creation time must be non-zero",
            Self::InvalidNostrSecretKey => "Nostr secret key is invalid",
            Self::PublicKeyMismatch => "Nostr secret key does not match the proof public key",
            Self::SigningFailed => "Nostr principal proof signing failed",
            Self::InvalidSignature => "Nostr principal proof signature is invalid",
        })
    }
}

impl std::error::Error for NostrPrincipalProofError {}

fn push_u32(destination: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated proof field must fit in u32");
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
}

fn valid_account_id(candidate: &str) -> bool {
    let Some(encoded) = candidate.strip_prefix("oa1_") else {
        return false;
    };
    encoded.len() == 64
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
