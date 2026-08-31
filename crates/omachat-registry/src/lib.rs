//! Transport-independent state machine for OmaChat's authoritative handle registry.
//!
//! Receipts form a publicly verifiable append-only hash chain when a client
//! already has the registry key and a trusted prior receipt. This crate does
//! not provide key transparency or protect a fresh client from a registry
//! presenting a consistent alternative history.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use omachat_crypto::{
    AccountError, AccountId, AccountSecrets, GlobalHandle, SignedLocalAccountBinding,
    verify_registry_handle_claim,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt};

const CLAIM_VERSION: u16 = 1;
const RECEIPT_VERSION: u16 = 1;
const CLAIM_DOMAIN: &[u8] = b"omachat.registry.handle-claim.v1\0";
const CLAIM_HASH_DOMAIN: &[u8] = b"omachat.registry.handle-claim-hash.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"omachat.registry.receipt.v1\0";
const RECEIPT_HASH_DOMAIN: &[u8] = b"omachat.registry.receipt-hash.v1\0";
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const GENESIS_HASH: [u8; KEY_BYTES] = [0_u8; KEY_BYTES];

/// Caller-generated, fixed-width idempotency key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommandId([u8; KEY_BYTES]);

impl CommandId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

/// A handle whose authoritative registration was accepted by this state
/// machine and is represented by a signed [`RegistryReceipt`].
///
/// This is intentionally distinct from [`GlobalHandle`], which proves only
/// that a candidate has valid syntax.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegisteredHandle(GlobalHandle);

impl RegisteredHandle {
    #[must_use]
    pub fn as_global_handle(&self) -> &GlobalHandle {
        &self.0
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for RegisteredHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A strict account-root-authorized request to claim or retain one handle.
///
/// Construction verifies the nested local binding and the independent claim
/// proof. `expected_revision` is the registry's per-account CAS revision; it
/// is deliberately independent from the binding's local profile revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleClaim {
    version: u16,
    command_id: CommandId,
    expected_revision: u64,
    binding: SignedLocalAccountBinding,
    proof: [u8; SIGNATURE_BYTES],
}

impl HandleClaim {
    /// Build and sign a claim with the account root that signed `binding`.
    pub fn sign(
        command_id: CommandId,
        expected_revision: u64,
        binding: SignedLocalAccountBinding,
        account: &AccountSecrets,
    ) -> Result<Self, RegistryError> {
        validate_binding(&binding)?;
        let public = account.public_identity();
        if binding.account_id != public.account_id
            || binding.account_root_public_key != public.account_root_public_key
        {
            return Err(RegistryError::ClaimAccountMismatch);
        }

        let mut claim = Self {
            version: CLAIM_VERSION,
            command_id,
            expected_revision,
            binding,
            proof: [0_u8; SIGNATURE_BYTES],
        };
        let digest = claim.proof_digest();
        claim.proof = account.sign_registry_handle_claim(&digest);
        claim.verify()?;
        Ok(claim)
    }

    /// Reconstruct a received claim, rejecting it unless all signatures and
    /// structural invariants verify.
    pub fn from_signed_parts(
        command_id: CommandId,
        expected_revision: u64,
        binding: SignedLocalAccountBinding,
        proof: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, RegistryError> {
        let claim = Self {
            version: CLAIM_VERSION,
            command_id,
            expected_revision,
            binding,
            proof,
        };
        claim.verify()?;
        Ok(claim)
    }

    pub fn verify(&self) -> Result<(), RegistryError> {
        if self.version != CLAIM_VERSION {
            return Err(RegistryError::UnsupportedClaimVersion(self.version));
        }
        validate_binding(&self.binding)?;
        verify_registry_handle_claim(
            &self.binding.account_root_public_key,
            &self.proof_digest(),
            &self.proof,
        )
        .map_err(|_| RegistryError::InvalidClaimProof)
    }

    #[must_use]
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }

    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    #[must_use]
    pub const fn binding(&self) -> &SignedLocalAccountBinding {
        &self.binding
    }

    #[must_use]
    pub const fn proof(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.proof
    }

    fn proof_digest(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(CLAIM_DOMAIN);
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.command_id.as_bytes());
        hasher.update(self.expected_revision.to_be_bytes());
        push_bytes(&mut hasher, &self.binding.signing_bytes());
        hasher.update(self.binding.signature);
        hasher.finalize().into()
    }

    fn hash(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(CLAIM_HASH_DOMAIN);
        hasher.update(self.proof_digest());
        hasher.update(self.proof);
        hasher.finalize().into()
    }
}

/// Registry-signed evidence for one accepted state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryReceipt {
    pub version: u16,
    pub sequence: u64,
    pub command_id: CommandId,
    pub account_id: AccountId,
    pub handle: RegisteredHandle,
    pub previous_handle: Option<RegisteredHandle>,
    pub account_revision: u64,
    pub claim_hash: [u8; KEY_BYTES],
    pub previous_receipt_hash: [u8; KEY_BYTES],
    pub accepted_at: u64,
    pub signature: [u8; SIGNATURE_BYTES],
}

impl RegistryReceipt {
    /// Verify this receipt against a separately pinned registry public key.
    pub fn verify(&self, pinned_registry_key: &[u8; KEY_BYTES]) -> Result<(), RegistryError> {
        if self.version != RECEIPT_VERSION {
            return Err(RegistryError::UnsupportedReceiptVersion(self.version));
        }
        if self.sequence == 0 {
            return Err(RegistryError::InvalidReceiptSequence);
        }
        if (self.sequence == 1) != (self.previous_receipt_hash == GENESIS_HASH) {
            return Err(RegistryError::InvalidReceiptChain);
        }
        VerifyingKey::from_bytes(pinned_registry_key)
            .map_err(|_| RegistryError::InvalidRegistryKey)?
            .verify_strict(
                &self.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| RegistryError::InvalidReceiptSignature)
    }

    /// Verify this receipt and its link to an already trusted predecessor.
    pub fn verify_after(
        &self,
        pinned_registry_key: &[u8; KEY_BYTES],
        previous: Option<&Self>,
    ) -> Result<(), RegistryError> {
        self.verify(pinned_registry_key)?;
        match previous {
            None if self.sequence == 1 && self.previous_receipt_hash == GENESIS_HASH => Ok(()),
            Some(previous) => {
                previous.verify(pinned_registry_key)?;
                let expected_sequence = previous
                    .sequence
                    .checked_add(1)
                    .ok_or(RegistryError::InvalidReceiptChain)?;
                if self.sequence != expected_sequence
                    || self.previous_receipt_hash != previous.receipt_hash()
                {
                    return Err(RegistryError::InvalidReceiptChain);
                }
                Ok(())
            }
            None => Err(RegistryError::InvalidReceiptChain),
        }
    }

    #[must_use]
    pub fn receipt_hash(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_HASH_DOMAIN);
        push_bytes(&mut hasher, &self.signing_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(RECEIPT_DOMAIN);
        output.extend_from_slice(&self.version.to_be_bytes());
        output.extend_from_slice(&self.sequence.to_be_bytes());
        output.extend_from_slice(self.command_id.as_bytes());
        push_vec_bytes(&mut output, self.account_id.as_str().as_bytes());
        push_vec_bytes(&mut output, self.handle.as_str().as_bytes());
        push_optional_handle(&mut output, self.previous_handle.as_ref());
        output.extend_from_slice(&self.account_revision.to_be_bytes());
        output.extend_from_slice(&self.claim_hash);
        output.extend_from_slice(&self.previous_receipt_hash);
        output.extend_from_slice(&self.accepted_at.to_be_bytes());
        output
    }
}

/// Immutable marker preventing a retired handle from being reassigned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleTombstone {
    pub handle: RegisteredHandle,
    pub account_id: AccountId,
    pub retired_at_revision: u64,
    pub receipt_hash: [u8; KEY_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccountRecord {
    binding: SignedLocalAccountBinding,
    registry_revision: u64,
    registered_handle: RegisteredHandle,
    last_receipt_hash: [u8; KEY_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcceptedCommand {
    claim_hash: [u8; KEY_BYTES],
    receipt: RegistryReceipt,
}

/// Single-authority in-memory registry state.
///
/// `apply` validates every failure mode before committing maps, so a rejected
/// command cannot partially reserve, release, or tombstone a handle.
pub struct RegistryState {
    signing_key: SigningKey,
    accounts: BTreeMap<AccountId, AccountRecord>,
    active_handles: BTreeMap<RegisteredHandle, AccountId>,
    tombstones: BTreeMap<GlobalHandle, HandleTombstone>,
    commands: BTreeMap<CommandId, AcceptedCommand>,
    head: Option<RegistryReceipt>,
}

impl RegistryState {
    #[must_use]
    pub fn from_signing_seed(seed: [u8; KEY_BYTES]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            accounts: BTreeMap::new(),
            active_handles: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            commands: BTreeMap::new(),
            head: None,
        }
    }

    #[must_use]
    pub fn verifying_key(&self) -> [u8; KEY_BYTES] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Atomically accept an initial claim, profile update, or handle rename.
    pub fn apply(
        &mut self,
        claim: HandleClaim,
        accepted_at: u64,
    ) -> Result<RegistryReceipt, RegistryError> {
        let claim_hash = claim.hash();
        if let Some(accepted) = self.commands.get(&claim.command_id) {
            return if accepted.claim_hash == claim_hash {
                Ok(accepted.receipt.clone())
            } else {
                Err(RegistryError::CommandIdConflict)
            };
        }

        claim.verify()?;
        let binding = &claim.binding;
        let handle = binding
            .handle
            .as_ref()
            .ok_or(RegistryError::MissingHandle)?;
        let current = self.accounts.get(&binding.account_id);
        let current_registry_revision = current.map_or(0, |record| record.registry_revision);
        if claim.expected_revision != current_registry_revision {
            return Err(RegistryError::StaleRevision {
                expected: claim.expected_revision,
                current: current_registry_revision,
            });
        }
        if let Some(current) = current
            && binding.revision <= current.binding.revision
        {
            return Err(RegistryError::StaleBindingRevision {
                proposed: binding.revision,
                current: current.binding.revision,
            });
        }
        let next_registry_revision = current_registry_revision
            .checked_add(1)
            .ok_or(RegistryError::RevisionExhausted)?;

        let previous_handle = current.map(|record| record.registered_handle.clone());
        let is_rename = previous_handle
            .as_ref()
            .is_some_and(|old| old.as_global_handle() != handle);
        let registered_handle = RegisteredHandle(handle.clone());

        if self.tombstones.contains_key(handle) {
            return Err(RegistryError::HandleTombstoned(handle.clone()));
        }
        if let Some(owner) = self.active_handles.get(&registered_handle)
            && owner != &binding.account_id
        {
            return Err(RegistryError::HandleTaken(handle.clone()));
        }

        let sequence = match self.head.as_ref() {
            Some(receipt) => receipt
                .sequence
                .checked_add(1)
                .ok_or(RegistryError::SequenceExhausted)?,
            None => 1,
        };
        let previous_receipt_hash = self
            .head
            .as_ref()
            .map_or(GENESIS_HASH, RegistryReceipt::receipt_hash);
        let mut receipt = RegistryReceipt {
            version: RECEIPT_VERSION,
            sequence,
            command_id: claim.command_id,
            account_id: binding.account_id.clone(),
            handle: registered_handle.clone(),
            previous_handle: if is_rename {
                previous_handle.clone()
            } else {
                None
            },
            account_revision: next_registry_revision,
            claim_hash,
            previous_receipt_hash,
            accepted_at,
            signature: [0_u8; SIGNATURE_BYTES],
        };
        receipt.signature = self.signing_key.sign(&receipt.signing_bytes()).to_bytes();
        let receipt_hash = receipt.receipt_hash();

        if let Some(old_handle) = previous_handle.filter(|old| old.as_global_handle() != handle) {
            self.active_handles.remove(&old_handle);
            self.tombstones.insert(
                old_handle.as_global_handle().clone(),
                HandleTombstone {
                    handle: old_handle,
                    account_id: binding.account_id.clone(),
                    retired_at_revision: next_registry_revision,
                    receipt_hash,
                },
            );
        }
        self.active_handles
            .insert(registered_handle.clone(), binding.account_id.clone());
        self.accounts.insert(
            binding.account_id.clone(),
            AccountRecord {
                binding: binding.clone(),
                registry_revision: next_registry_revision,
                registered_handle,
                last_receipt_hash: receipt_hash,
            },
        );
        self.commands.insert(
            claim.command_id,
            AcceptedCommand {
                claim_hash,
                receipt: receipt.clone(),
            },
        );
        self.head = Some(receipt.clone());
        Ok(receipt)
    }

    #[must_use]
    pub fn handle_owner(&self, handle: &GlobalHandle) -> Option<&AccountId> {
        self.active_handles.get(&RegisteredHandle(handle.clone()))
    }

    #[must_use]
    pub fn account_binding(&self, account_id: &AccountId) -> Option<&SignedLocalAccountBinding> {
        self.accounts.get(account_id).map(|record| &record.binding)
    }

    /// Return the authoritative per-account CAS revision.
    #[must_use]
    pub fn account_revision(&self, account_id: &AccountId) -> Option<u64> {
        self.accounts
            .get(account_id)
            .map(|record| record.registry_revision)
    }

    #[must_use]
    pub fn registered_handle(&self, account_id: &AccountId) -> Option<&RegisteredHandle> {
        self.accounts
            .get(account_id)
            .map(|record| &record.registered_handle)
    }

    #[must_use]
    pub fn account_receipt_hash(&self, account_id: &AccountId) -> Option<[u8; KEY_BYTES]> {
        self.accounts
            .get(account_id)
            .map(|record| record.last_receipt_hash)
    }

    #[must_use]
    pub fn tombstone(&self, handle: &GlobalHandle) -> Option<&HandleTombstone> {
        self.tombstones.get(handle)
    }

    #[must_use]
    pub const fn head(&self) -> Option<&RegistryReceipt> {
        self.head.as_ref()
    }
}

fn validate_binding(binding: &SignedLocalAccountBinding) -> Result<(), RegistryError> {
    binding.verify().map_err(RegistryError::InvalidBinding)?;
    if binding.handle.is_none() {
        return Err(RegistryError::MissingHandle);
    }
    if binding.revision == 0 {
        return Err(RegistryError::InvalidBindingRevision {
            minimum: 1,
            actual: binding.revision,
        });
    }
    Ok(())
}

fn push_bytes(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("claim transcript length fits u64");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn push_vec_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("bounded registry field length fits u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn push_optional_handle(output: &mut Vec<u8>, handle: Option<&RegisteredHandle>) {
    match handle {
        Some(handle) => {
            output.push(1);
            push_vec_bytes(output, handle.as_str().as_bytes());
        }
        None => output.push(0),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    InvalidBinding(AccountError),
    MissingHandle,
    ClaimAccountMismatch,
    InvalidClaimProof,
    InvalidBindingRevision { minimum: u64, actual: u64 },
    StaleBindingRevision { proposed: u64, current: u64 },
    RevisionExhausted,
    StaleRevision { expected: u64, current: u64 },
    CommandIdConflict,
    HandleTaken(GlobalHandle),
    HandleTombstoned(GlobalHandle),
    SequenceExhausted,
    UnsupportedClaimVersion(u16),
    UnsupportedReceiptVersion(u16),
    InvalidRegistryKey,
    InvalidReceiptSequence,
    InvalidReceiptSignature,
    InvalidReceiptChain,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinding(error) => write!(formatter, "invalid account binding: {error}"),
            Self::MissingHandle => formatter.write_str("account binding has no configured handle"),
            Self::ClaimAccountMismatch => {
                formatter.write_str("claim signer does not match the bound account root")
            }
            Self::InvalidClaimProof => formatter.write_str("invalid registry handle-claim proof"),
            Self::InvalidBindingRevision { minimum, actual } => write!(
                formatter,
                "binding revision {actual} is below the minimum {minimum}"
            ),
            Self::StaleBindingRevision { proposed, current } => write!(
                formatter,
                "binding revision {proposed} does not advance stored binding revision {current}"
            ),
            Self::RevisionExhausted => {
                formatter.write_str("registry account revision is exhausted")
            }
            Self::StaleRevision { expected, current } => write!(
                formatter,
                "claim expected registry account revision {expected}, current revision is {current}"
            ),
            Self::CommandIdConflict => {
                formatter.write_str("command ID was already used for a different claim")
            }
            Self::HandleTaken(handle) => write!(formatter, "handle @{handle} is already claimed"),
            Self::HandleTombstoned(handle) => {
                write!(formatter, "handle @{handle} is permanently retired")
            }
            Self::SequenceExhausted => formatter.write_str("registry sequence is exhausted"),
            Self::UnsupportedClaimVersion(version) => {
                write!(formatter, "unsupported handle claim version {version}")
            }
            Self::UnsupportedReceiptVersion(version) => {
                write!(formatter, "unsupported registry receipt version {version}")
            }
            Self::InvalidRegistryKey => formatter.write_str("invalid pinned registry key"),
            Self::InvalidReceiptSequence => {
                formatter.write_str("invalid registry receipt sequence")
            }
            Self::InvalidReceiptSignature => {
                formatter.write_str("invalid registry receipt signature")
            }
            Self::InvalidReceiptChain => formatter.write_str("invalid registry receipt hash chain"),
        }
    }
}

impl Error for RegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBinding(error) => Some(error),
            _ => None,
        }
    }
}
