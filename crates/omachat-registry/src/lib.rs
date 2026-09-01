//! Transport-independent state machine for OmaChat's authoritative handle registry.
//!
//! Receipts form a publicly verifiable global append-only hash chain when a
//! client has the registry key and the immediately preceding global receipt.
//! A second per-account predecessor lets a client validate its next account
//! transition without downloading unrelated accounts' receipts. This crate
//! does not provide key transparency or protect a fresh client from a registry
//! presenting a consistent alternative history.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use omachat_crypto::{
    AccountError, AccountId, AccountSecrets, GlobalHandle, SignedLocalAccountBinding,
    verify_registry_handle_claim,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt};

mod agent_claim;
pub mod principal_proof;
pub mod proof_bearing_claim;

pub use agent_claim::{
    AgentHandleClaim, AgentHandleClaimError, AgentHandleClaimSnapshot, AgentRegistrySubject,
};

const CLAIM_VERSION: u16 = 1;
const REGISTRY_STATE_VERSION: u16 = 1;
const RECEIPT_VERSION: u16 = 1;
const CLAIM_DOMAIN: &[u8] = b"omachat.registry.handle-claim.v1\0";
const CLAIM_HASH_DOMAIN: &[u8] = b"omachat.registry.handle-claim-hash.v1\0";
const RECEIPT_DOMAIN: &[u8] = b"omachat.registry.receipt.v1\0";
const RECEIPT_HASH_DOMAIN: &[u8] = b"omachat.registry.receipt-hash.v1\0";
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const GENESIS_HASH: [u8; KEY_BYTES] = [0_u8; KEY_BYTES];

mod serde_signature {
    use super::SIGNATURE_BYTES;
    use serde::de::Deserialize;
    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; SIGNATURE_BYTES], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_BYTES], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Vec<u8> = Vec::deserialize(deserializer)?;
        if value.len() != SIGNATURE_BYTES {
            return Err(Error::invalid_length(value.len(), &"a 64-byte signature"));
        }
        let mut signature = [0_u8; SIGNATURE_BYTES];
        signature.copy_from_slice(&value);
        Ok(signature)
    }
}

/// Caller-generated, fixed-width idempotency key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleClaimSnapshot {
    pub version: u16,
    pub command_id: CommandId,
    pub expected_revision: u64,
    pub binding: SignedLocalAccountBinding,
    #[serde(with = "serde_signature")]
    pub proof: [u8; SIGNATURE_BYTES],
}

impl HandleClaimSnapshot {
    #[must_use]
    pub fn from_claim(claim: &HandleClaim) -> Self {
        Self {
            version: claim.version,
            command_id: claim.command_id,
            expected_revision: claim.expected_revision,
            binding: claim.binding.clone(),
            proof: claim.proof,
        }
    }

    pub fn to_claim(&self) -> Result<HandleClaim, RegistryError> {
        if self.version != CLAIM_VERSION {
            return Err(RegistryError::UnsupportedClaimVersion(self.version));
        }
        HandleClaim::from_signed_parts(
            self.command_id,
            self.expected_revision,
            self.binding.clone(),
            self.proof,
        )
    }
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

    /// Deterministic digest authorized by the account-root claim proof.
    #[must_use]
    pub fn proof_digest(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(CLAIM_DOMAIN);
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.command_id.as_bytes());
        hasher.update(self.expected_revision.to_be_bytes());
        push_bytes(&mut hasher, &self.binding.signing_bytes());
        hasher.update(self.binding.signature);
        hasher.finalize().into()
    }

    /// Hash the complete signed claim for binding into an acceptance receipt.
    #[must_use]
    pub fn claim_hash(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(CLAIM_HASH_DOMAIN);
        hasher.update(self.proof_digest());
        hasher.update(self.proof);
        hasher.finalize().into()
    }
}

/// Registry-signed evidence for one accepted state transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistryReceipt {
    pub version: u16,
    pub sequence: u64,
    pub command_id: CommandId,
    pub account_id: AccountId,
    pub handle: RegisteredHandle,
    pub account_revision: u64,
    pub claim_hash: [u8; KEY_BYTES],
    /// Immediate predecessor in the registry-wide chain.
    pub previous_receipt_hash: [u8; KEY_BYTES],
    /// Immediate predecessor for this account, regardless of intervening
    /// receipts belonging to other accounts.
    pub previous_account_receipt_hash: [u8; KEY_BYTES],
    pub accepted_at: u64,
    #[serde(with = "serde_signature")]
    pub signature: [u8; SIGNATURE_BYTES],
}

/// Complete, independently verifiable evidence for one accepted claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedRegistryRecord {
    pub claim: HandleClaim,
    pub receipt: RegistryReceipt,
}

impl AcceptedRegistryRecord {
    pub fn verify(&self, pinned_registry_key: &[u8; KEY_BYTES]) -> Result<(), RegistryError> {
        self.receipt
            .verify_for_claim(pinned_registry_key, &self.claim)
    }
}

impl RegistryReceipt {
    /// Verify this receipt's structure and registry signature against a
    /// separately pinned registry public key.
    ///
    /// This authenticates the receipt itself. Call [`Self::verify_for_claim`]
    /// as well when proving that the registry accepted a particular claim.
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
        if self.account_revision == 0
            || (self.account_revision == 1) != (self.previous_account_receipt_hash == GENESIS_HASH)
        {
            return Err(RegistryError::InvalidAccountReceiptChain);
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

    /// Verify this receipt as the next transition after a trusted receipt for
    /// the same account. Global sequence numbers may have gaps because other
    /// accounts can have accepted transitions between the two receipts.
    pub fn verify_account_after(
        &self,
        pinned_registry_key: &[u8; KEY_BYTES],
        previous: Option<&Self>,
    ) -> Result<(), RegistryError> {
        self.verify(pinned_registry_key)?;
        match previous {
            None if self.account_revision == 1
                && self.previous_account_receipt_hash == GENESIS_HASH =>
            {
                Ok(())
            }
            Some(previous) => {
                previous.verify(pinned_registry_key)?;
                let expected_revision = previous
                    .account_revision
                    .checked_add(1)
                    .ok_or(RegistryError::InvalidAccountReceiptChain)?;
                if self.account_id != previous.account_id
                    || self.account_revision != expected_revision
                    || self.sequence <= previous.sequence
                    || self.previous_account_receipt_hash != previous.receipt_hash()
                {
                    return Err(RegistryError::InvalidAccountReceiptChain);
                }
                Ok(())
            }
            None => Err(RegistryError::InvalidAccountReceiptChain),
        }
    }

    /// Verify that this receipt accepted exactly `claim`, not merely a claim
    /// for a similarly named account or handle.
    pub fn verify_for_claim(
        &self,
        pinned_registry_key: &[u8; KEY_BYTES],
        claim: &HandleClaim,
    ) -> Result<(), RegistryError> {
        self.verify(pinned_registry_key)?;
        claim.verify()?;
        let handle = claim
            .binding
            .handle
            .as_ref()
            .ok_or(RegistryError::MissingHandle)?;
        let expected_revision = claim
            .expected_revision
            .checked_add(1)
            .ok_or(RegistryError::ReceiptClaimMismatch)?;
        if self.command_id != claim.command_id
            || self.account_id != claim.binding.account_id
            || self.handle.as_global_handle() != handle
            || self.account_revision != expected_revision
            || self.claim_hash != claim.claim_hash()
        {
            return Err(RegistryError::ReceiptClaimMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn receipt_hash(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_HASH_DOMAIN);
        push_bytes(&mut hasher, &self.signing_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    /// Deterministic domain-separated transcript covered by the registry key.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(RECEIPT_DOMAIN);
        output.extend_from_slice(&self.version.to_be_bytes());
        output.extend_from_slice(&self.sequence.to_be_bytes());
        output.extend_from_slice(self.command_id.as_bytes());
        push_vec_bytes(&mut output, self.account_id.as_str().as_bytes());
        push_vec_bytes(&mut output, self.handle.as_str().as_bytes());
        output.extend_from_slice(&self.account_revision.to_be_bytes());
        output.extend_from_slice(&self.claim_hash);
        output.extend_from_slice(&self.previous_receipt_hash);
        output.extend_from_slice(&self.previous_account_receipt_hash);
        output.extend_from_slice(&self.accepted_at.to_be_bytes());
        output
    }
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
    claim: Option<HandleClaim>,
    claim_hash: [u8; KEY_BYTES],
    receipt: RegistryReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryStateSnapshot {
    pub version: u16,
    pub accounts: Vec<RegistryAccountSnapshot>,
    pub commands: Vec<RegistryCommandSnapshot>,
    pub head: Option<RegistryReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryAccountSnapshot {
    pub account_id: AccountId,
    pub binding: SignedLocalAccountBinding,
    pub registry_revision: u64,
    pub registered_handle: RegisteredHandle,
    pub last_receipt_hash: [u8; KEY_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCommandSnapshot {
    pub command_id: CommandId,
    pub claim_hash: [u8; KEY_BYTES],
    pub receipt: RegistryReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<HandleClaimSnapshot>,
}

/// Single-authority in-memory registry state.
///
/// `apply` validates every failure mode before committing maps, so a rejected
/// command cannot partially reserve or alter a handle. Rename and released-
/// handle reuse are deliberately deferred until service policy is specified.
pub struct RegistryState {
    signing_key: SigningKey,
    accounts: BTreeMap<AccountId, AccountRecord>,
    active_handles: BTreeMap<RegisteredHandle, AccountId>,
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
            commands: BTreeMap::new(),
            head: None,
        }
    }

    #[must_use]
    pub fn verifying_key(&self) -> [u8; KEY_BYTES] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Atomically accept an initial claim or an update retaining its handle.
    pub fn apply(
        &mut self,
        claim: HandleClaim,
        accepted_at: u64,
    ) -> Result<RegistryReceipt, RegistryError> {
        let claim_hash = claim.claim_hash();
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

        if let Some(current) = current
            && current.registered_handle.as_global_handle() != handle
        {
            return Err(RegistryError::HandleRenameDeferred);
        }
        let registered_handle = RegisteredHandle(handle.clone());

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
        let previous_account_receipt_hash =
            current.map_or(GENESIS_HASH, |record| record.last_receipt_hash);
        let mut receipt = RegistryReceipt {
            version: RECEIPT_VERSION,
            sequence,
            command_id: claim.command_id,
            account_id: binding.account_id.clone(),
            handle: registered_handle.clone(),
            account_revision: next_registry_revision,
            claim_hash,
            previous_receipt_hash,
            previous_account_receipt_hash,
            accepted_at,
            signature: [0_u8; SIGNATURE_BYTES],
        };
        receipt.signature = self.signing_key.sign(&receipt.signing_bytes()).to_bytes();
        let receipt_hash = receipt.receipt_hash();

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
                claim: Some(claim),
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

    /// Return complete claim evidence for an account, failing closed when a
    /// legacy snapshot predates persisted claim proofs.
    pub fn account_record(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<AcceptedRegistryRecord>, RegistryError> {
        let Some(account) = self.accounts.get(account_id) else {
            return Ok(None);
        };
        let command = self
            .commands
            .values()
            .find(|command| command.receipt.receipt_hash() == account.last_receipt_hash)
            .ok_or(RegistryError::InvalidRegistryState)?;
        let claim = command
            .claim
            .clone()
            .ok_or(RegistryError::HistoricalClaimUnavailable)?;
        Ok(Some(AcceptedRegistryRecord {
            claim,
            receipt: command.receipt.clone(),
        }))
    }

    /// Resolve a registered handle to complete accepted claim evidence.
    pub fn handle_record(
        &self,
        handle: &GlobalHandle,
    ) -> Result<Option<AcceptedRegistryRecord>, RegistryError> {
        let Some(account_id) = self.handle_owner(handle) else {
            return Ok(None);
        };
        self.account_record(account_id)
    }

    #[must_use]
    pub const fn head(&self) -> Option<&RegistryReceipt> {
        self.head.as_ref()
    }

    /// Export the complete authoritative state for sealed persistence.
    #[must_use]
    pub fn snapshot(&self) -> RegistryStateSnapshot {
        RegistryStateSnapshot {
            version: REGISTRY_STATE_VERSION,
            accounts: self
                .accounts
                .iter()
                .map(|(account_id, record)| RegistryAccountSnapshot {
                    account_id: account_id.clone(),
                    binding: record.binding.clone(),
                    registry_revision: record.registry_revision,
                    registered_handle: record.registered_handle.clone(),
                    last_receipt_hash: record.last_receipt_hash,
                })
                .collect(),
            commands: self
                .commands
                .iter()
                .map(|(command_id, command)| RegistryCommandSnapshot {
                    command_id: *command_id,
                    claim_hash: command.claim_hash,
                    receipt: command.receipt.clone(),
                    claim: command.claim.as_ref().map(HandleClaimSnapshot::from_claim),
                })
                .collect(),
            head: self.head.clone(),
        }
    }

    /// Rebuild an in-memory registry from a persisted snapshot.
    pub fn restore(
        seed: [u8; KEY_BYTES],
        snapshot: RegistryStateSnapshot,
    ) -> Result<Self, RegistryError> {
        if snapshot.version != REGISTRY_STATE_VERSION {
            return Err(RegistryError::UnsupportedStateVersion(snapshot.version));
        }
        let command_count = snapshot.commands.len();
        let mut commands: BTreeMap<CommandId, AcceptedCommand> = BTreeMap::new();
        for command in snapshot.commands {
            if commands
                .insert(
                    command.command_id,
                    AcceptedCommand {
                        claim: command.claim.map(|claim| claim.to_claim()).transpose()?,
                        claim_hash: command.claim_hash,
                        receipt: command.receipt,
                    },
                )
                .is_some()
            {
                return Err(RegistryError::InvalidRegistryState);
            }
        }

        let pinned_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut global_receipts: Vec<RegistryReceipt> = commands
            .iter()
            .map(|(command_id, command)| {
                if *command_id != command.receipt.command_id {
                    return Err(RegistryError::InvalidRegistryState);
                }
                if command.claim_hash != command.receipt.claim_hash {
                    return Err(RegistryError::InvalidRegistryState);
                }
                command.receipt.verify(&pinned_key)?;
                if let Some(claim) = &command.claim {
                    if claim.command_id != *command_id || claim.claim_hash() != command.claim_hash {
                        return Err(RegistryError::InvalidRegistryState);
                    }
                    command.receipt.verify_for_claim(&pinned_key, claim)?;
                }
                Ok(command.receipt.clone())
            })
            .collect::<Result<_, RegistryError>>()?;
        global_receipts.sort_by_key(|receipt| receipt.sequence);
        let mut receipts_by_hash = BTreeMap::new();
        let mut account_latest = BTreeMap::new();
        let mut previous: Option<&RegistryReceipt> = None;
        for receipt in &global_receipts {
            receipt.verify_after(&pinned_key, previous)?;
            let previous_account = account_latest.get(&receipt.account_id);
            receipt.verify_account_after(&pinned_key, previous_account)?;
            let hash = receipt.receipt_hash();
            if receipts_by_hash.insert(hash, receipt.clone()).is_some() {
                return Err(RegistryError::InvalidRegistryState);
            }
            account_latest.insert(receipt.account_id.clone(), receipt.clone());
            previous = Some(receipt);
        }

        if command_count == 0 {
            if snapshot.head.is_some() {
                return Err(RegistryError::InvalidRegistryState);
            }
        } else {
            let expected_head = global_receipts
                .last()
                .cloned()
                .expect("non-empty command list must have a head");
            if snapshot.head != Some(expected_head) {
                return Err(RegistryError::InvalidRegistryState);
            }
        }

        let mut accounts = BTreeMap::new();
        let mut active_handles = BTreeMap::new();
        for account_snapshot in snapshot.accounts {
            if account_snapshot.registry_revision == 0
                || account_snapshot.account_id != account_snapshot.binding.account_id
            {
                return Err(RegistryError::InvalidRegistryState);
            }
            account_snapshot
                .binding
                .verify()
                .map_err(RegistryError::InvalidBinding)?;
            if account_snapshot
                .binding
                .handle
                .as_ref()
                .is_none_or(|handle| {
                    handle != account_snapshot.registered_handle.as_global_handle()
                })
            {
                return Err(RegistryError::InvalidRegistryState);
            }
            let previous = active_handles.insert(
                account_snapshot.registered_handle.clone(),
                account_snapshot.account_id.clone(),
            );
            if let Some(previous_owner) = previous
                && previous_owner != account_snapshot.account_id
            {
                return Err(RegistryError::InvalidRegistryState);
            }
            if accounts.contains_key(&account_snapshot.account_id) {
                return Err(RegistryError::InvalidRegistryState);
            }

            let latest = receipts_by_hash
                .get(&account_snapshot.last_receipt_hash)
                .ok_or(RegistryError::InvalidRegistryState)?;
            if latest.account_id != account_snapshot.account_id
                || latest.account_revision != account_snapshot.registry_revision
                || latest.handle != account_snapshot.registered_handle
            {
                return Err(RegistryError::InvalidRegistryState);
            }
            let latest_command = commands
                .get(&latest.command_id)
                .ok_or(RegistryError::InvalidRegistryState)?;
            if let Some(claim) = &latest_command.claim
                && claim.binding != account_snapshot.binding
            {
                return Err(RegistryError::InvalidRegistryState);
            }
            if let Some(account_chain) = account_latest.get(&account_snapshot.account_id) {
                if account_chain.receipt_hash() != account_snapshot.last_receipt_hash {
                    return Err(RegistryError::InvalidRegistryState);
                }
            } else {
                return Err(RegistryError::InvalidRegistryState);
            }
            accounts.insert(
                account_snapshot.account_id,
                AccountRecord {
                    binding: account_snapshot.binding,
                    registry_revision: account_snapshot.registry_revision,
                    registered_handle: account_snapshot.registered_handle,
                    last_receipt_hash: account_snapshot.last_receipt_hash,
                },
            );
        }

        if accounts.len() != account_latest.len() {
            return Err(RegistryError::InvalidRegistryState);
        }
        for command in commands.values() {
            if !accounts.contains_key(&command.receipt.account_id) {
                return Err(RegistryError::InvalidRegistryState);
            }
        }

        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
            accounts,
            active_handles,
            commands,
            head: snapshot.head,
        })
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    UnsupportedStateVersion(u16),
    InvalidRegistryState,
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
    HandleRenameDeferred,
    SequenceExhausted,
    UnsupportedClaimVersion(u16),
    UnsupportedReceiptVersion(u16),
    InvalidRegistryKey,
    InvalidReceiptSequence,
    InvalidReceiptSignature,
    InvalidReceiptChain,
    InvalidAccountReceiptChain,
    ReceiptClaimMismatch,
    HistoricalClaimUnavailable,
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
            Self::HandleRenameDeferred => formatter
                .write_str("handle rename is deferred until registry reuse policy is specified"),
            Self::SequenceExhausted => formatter.write_str("registry sequence is exhausted"),
            Self::UnsupportedClaimVersion(version) => {
                write!(formatter, "unsupported handle claim version {version}")
            }
            Self::UnsupportedReceiptVersion(version) => {
                write!(formatter, "unsupported registry receipt version {version}")
            }
            Self::UnsupportedStateVersion(version) => {
                write!(formatter, "unsupported registry state version {version}")
            }
            Self::InvalidRegistryState => {
                formatter.write_str("registry state snapshot is internally inconsistent")
            }
            Self::InvalidRegistryKey => formatter.write_str("invalid pinned registry key"),
            Self::InvalidReceiptSequence => {
                formatter.write_str("invalid registry receipt sequence")
            }
            Self::InvalidReceiptSignature => {
                formatter.write_str("invalid registry receipt signature")
            }
            Self::InvalidReceiptChain => formatter.write_str("invalid registry receipt hash chain"),
            Self::InvalidAccountReceiptChain => {
                formatter.write_str("invalid per-account registry receipt hash chain")
            }
            Self::ReceiptClaimMismatch => {
                formatter.write_str("registry receipt does not match the exact handle claim")
            }
            Self::HistoricalClaimUnavailable => formatter
                .write_str("legacy registry state does not contain the accepted claim proof"),
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
