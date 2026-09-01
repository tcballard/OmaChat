use std::error::Error;
use std::fmt;

use k256::schnorr::{
    Signature as SchnorrSignature, SigningKey as SchnorrSigningKey,
    VerifyingKey as SchnorrVerifyingKey,
};
use omachat_crypto::{
    AccountId, AccountSecrets, AgentAuthorizationId, GlobalHandle, SignedAgentAuthorization,
    SignedAgentRevocation, verify_registry_handle_claim,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::CommandId;

const VERSION: u16 = 1;
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const CLAIM_DOMAIN: &[u8] = b"omachat.registry.agent-handle-claim.v1\0";
const OWNER_DOMAIN: &[u8] = b"omachat.registry.agent-handle-owner-proof.v1\0";
const CLAIM_HASH_DOMAIN: &[u8] = b"omachat.registry.agent-handle-claim-hash.v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRegistrySubject {
    pub account_id: AccountId,
    pub authorization_id: AgentAuthorizationId,
    pub agent_public_key: [u8; KEY_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentHandleClaim {
    version: u16,
    command_id: CommandId,
    expected_revision: u64,
    handle: GlobalHandle,
    authorization: SignedAgentAuthorization,
    agent_proof: [u8; SIGNATURE_BYTES],
    owner_proof: [u8; SIGNATURE_BYTES],
}

impl AgentHandleClaim {
    pub fn sign(
        command_id: CommandId,
        expected_revision: u64,
        handle: GlobalHandle,
        authorization: SignedAgentAuthorization,
        agent_secret_key: &[u8; KEY_BYTES],
        owner: &AccountSecrets,
        auxiliary_randomness: &[u8; KEY_BYTES],
    ) -> Result<Self, AgentHandleClaimError> {
        authorization
            .verify()
            .map_err(|error| AgentHandleClaimError::InvalidAuthorization(error.to_string()))?;
        let owner_public = owner.public_identity();
        if owner_public.account_id != authorization.account_id
            || owner_public.account_root_public_key != authorization.account_root_public_key
        {
            return Err(AgentHandleClaimError::AccountMismatch);
        }
        let signing_key = SchnorrSigningKey::from_bytes(agent_secret_key)
            .map_err(|_| AgentHandleClaimError::InvalidAgentSecretKey)?;
        if signing_key.verifying_key().to_bytes().as_slice() != authorization.agent_public_key() {
            return Err(AgentHandleClaimError::AgentKeyMismatch);
        }

        let mut claim = Self {
            version: VERSION,
            command_id,
            expected_revision,
            handle,
            authorization,
            agent_proof: [0; SIGNATURE_BYTES],
            owner_proof: [0; SIGNATURE_BYTES],
        };
        claim.agent_proof = signing_key
            .sign_raw(&claim.claim_digest(), auxiliary_randomness)
            .map_err(|_| AgentHandleClaimError::AgentSigning)?
            .to_bytes();
        claim.owner_proof = owner.sign_registry_handle_claim(&claim.owner_digest());
        claim.verify()?;
        Ok(claim)
    }

    pub fn from_signed_parts(
        command_id: CommandId,
        expected_revision: u64,
        handle: GlobalHandle,
        authorization: SignedAgentAuthorization,
        agent_proof: [u8; SIGNATURE_BYTES],
        owner_proof: [u8; SIGNATURE_BYTES],
    ) -> Result<Self, AgentHandleClaimError> {
        let claim = Self {
            version: VERSION,
            command_id,
            expected_revision,
            handle,
            authorization,
            agent_proof,
            owner_proof,
        };
        claim.verify()?;
        Ok(claim)
    }

    pub fn verify(&self) -> Result<(), AgentHandleClaimError> {
        if self.version != VERSION {
            return Err(AgentHandleClaimError::UnsupportedVersion(self.version));
        }
        self.authorization
            .verify()
            .map_err(|error| AgentHandleClaimError::InvalidAuthorization(error.to_string()))?;
        let agent_key = SchnorrVerifyingKey::from_bytes(self.authorization.agent_public_key())
            .map_err(|_| AgentHandleClaimError::InvalidAgentPublicKey)?;
        let agent_signature = SchnorrSignature::try_from(self.agent_proof.as_slice())
            .map_err(|_| AgentHandleClaimError::InvalidAgentProof)?;
        agent_key
            .verify_raw(&self.claim_digest(), &agent_signature)
            .map_err(|_| AgentHandleClaimError::InvalidAgentProof)?;
        verify_registry_handle_claim(
            &self.authorization.account_root_public_key,
            &self.owner_digest(),
            &self.owner_proof,
        )
        .map_err(|_| AgentHandleClaimError::InvalidOwnerProof)
    }

    pub fn verify_current(
        &self,
        revocation: Option<&SignedAgentRevocation>,
    ) -> Result<(), AgentHandleClaimError> {
        self.verify()?;
        self.authorization
            .verify_current(revocation)
            .map_err(|error| AgentHandleClaimError::InvalidAuthorization(error.to_string()))
    }

    pub fn subject(&self) -> AgentRegistrySubject {
        AgentRegistrySubject {
            account_id: self.authorization.account_id.clone(),
            authorization_id: self.authorization.authorization_id.clone(),
            agent_public_key: *self.authorization.agent_public_key(),
        }
    }

    pub fn command_id(&self) -> CommandId {
        self.command_id
    }

    pub fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    pub fn handle(&self) -> &GlobalHandle {
        &self.handle
    }

    pub fn authorization(&self) -> &SignedAgentAuthorization {
        &self.authorization
    }

    pub fn agent_proof(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.agent_proof
    }

    pub fn owner_proof(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.owner_proof
    }

    pub fn claim_digest(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(CLAIM_DOMAIN);
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.command_id.as_bytes());
        hasher.update(self.expected_revision.to_be_bytes());
        push_bytes(&mut hasher, self.handle.as_str().as_bytes());
        hasher.update(self.authorization.authorization_hash());
        hasher.finalize().into()
    }

    pub fn claim_hash(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(CLAIM_HASH_DOMAIN);
        hasher.update(self.claim_digest());
        hasher.update(self.agent_proof);
        hasher.update(self.owner_proof);
        hasher.finalize().into()
    }

    fn owner_digest(&self) -> [u8; KEY_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(OWNER_DOMAIN);
        hasher.update(self.claim_digest());
        hasher.update(self.agent_proof);
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentHandleClaimSnapshot {
    pub version: u16,
    pub command_id: CommandId,
    pub expected_revision: u64,
    pub handle: GlobalHandle,
    pub authorization: SignedAgentAuthorization,
    #[serde(with = "crate::serde_signature")]
    pub agent_proof: [u8; SIGNATURE_BYTES],
    #[serde(with = "crate::serde_signature")]
    pub owner_proof: [u8; SIGNATURE_BYTES],
}

impl AgentHandleClaimSnapshot {
    pub fn from_claim(claim: &AgentHandleClaim) -> Self {
        Self {
            version: claim.version,
            command_id: claim.command_id,
            expected_revision: claim.expected_revision,
            handle: claim.handle.clone(),
            authorization: claim.authorization.clone(),
            agent_proof: claim.agent_proof,
            owner_proof: claim.owner_proof,
        }
    }

    pub fn to_claim(&self) -> Result<AgentHandleClaim, AgentHandleClaimError> {
        if self.version != VERSION {
            return Err(AgentHandleClaimError::UnsupportedVersion(self.version));
        }
        AgentHandleClaim::from_signed_parts(
            self.command_id,
            self.expected_revision,
            self.handle.clone(),
            self.authorization.clone(),
            self.agent_proof,
            self.owner_proof,
        )
    }
}

fn push_bytes(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("agent claim field length fits u64");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentHandleClaimError {
    UnsupportedVersion(u16),
    InvalidAuthorization(String),
    AccountMismatch,
    InvalidAgentSecretKey,
    InvalidAgentPublicKey,
    AgentKeyMismatch,
    AgentSigning,
    InvalidAgentProof,
    InvalidOwnerProof,
}

impl fmt::Display for AgentHandleClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported agent handle claim version {version}"
                )
            }
            Self::InvalidAuthorization(error) => {
                write!(formatter, "invalid agent authorization: {error}")
            }
            Self::AccountMismatch => formatter.write_str("agent owner account does not match"),
            Self::InvalidAgentSecretKey => formatter.write_str("invalid agent secret key"),
            Self::InvalidAgentPublicKey => formatter.write_str("invalid agent public key"),
            Self::AgentKeyMismatch => {
                formatter.write_str("agent key does not match the owner authorization")
            }
            Self::AgentSigning => formatter.write_str("agent handle claim signing failed"),
            Self::InvalidAgentProof => formatter.write_str("invalid agent handle proof"),
            Self::InvalidOwnerProof => formatter.write_str("invalid owner handle approval"),
        }
    }
}

impl Error for AgentHandleClaimError {}

#[cfg(test)]
mod tests {
    use super::*;
    use omachat_crypto::AgentAuthorizationRequest;

    fn authorization(owner: &AccountSecrets, agent_secret: &[u8; 32]) -> SignedAgentAuthorization {
        let request = AgentAuthorizationRequest::sign(
            agent_secret,
            owner.public_identity().account_id,
            None,
            1_788_100_000,
            &[0x42; 32],
        )
        .expect("agent request");
        owner
            .authorize_agent(request, 1, 1_788_100_001)
            .expect("agent authorization")
    }

    fn claim(
        owner: &AccountSecrets,
        agent_secret: &[u8; 32],
        command_byte: u8,
        handle: &str,
    ) -> AgentHandleClaim {
        AgentHandleClaim::sign(
            CommandId::from_bytes([command_byte; 32]),
            0,
            GlobalHandle::parse(handle).expect("handle"),
            authorization(owner, agent_secret),
            agent_secret,
            owner,
            &[0x43; 32],
        )
        .expect("agent handle claim")
    }

    #[test]
    fn claim_requires_both_agent_and_owner_for_the_exact_handle() {
        let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
        let claim = claim(&owner, &[0x31; 32], 1, "codex_tom");
        claim.verify_current(None).expect("current claim");
        assert_eq!(claim.handle().as_str(), "codex_tom");
        assert_eq!(
            claim.subject().agent_public_key,
            *claim.authorization().agent_public_key()
        );

        let snapshot = AgentHandleClaimSnapshot::from_claim(&claim);
        let encoded = serde_json::to_vec(&snapshot).expect("claim JSON");
        let decoded: AgentHandleClaimSnapshot =
            serde_json::from_slice(&encoded).expect("strict claim JSON");
        assert_eq!(decoded.to_claim().expect("verified snapshot"), claim);

        let mut forged_handle = snapshot;
        forged_handle.handle = GlobalHandle::parse("research_tom").expect("handle");
        assert!(matches!(
            forged_handle.to_claim(),
            Err(AgentHandleClaimError::InvalidAgentProof)
        ));
    }

    #[test]
    fn wrong_agent_wrong_owner_and_revoked_authorization_fail_closed() {
        let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
        let other = AccountSecrets::from_seeds([3; 32], [4; 32]);
        let authorization = authorization(&owner, &[0x31; 32]);
        assert_eq!(
            AgentHandleClaim::sign(
                CommandId::from_bytes([2; 32]),
                0,
                GlobalHandle::parse("codex_tom").expect("handle"),
                authorization.clone(),
                &[0x32; 32],
                &owner,
                &[0x43; 32],
            ),
            Err(AgentHandleClaimError::AgentKeyMismatch)
        );
        assert_eq!(
            AgentHandleClaim::sign(
                CommandId::from_bytes([2; 32]),
                0,
                GlobalHandle::parse("codex_tom").expect("handle"),
                authorization.clone(),
                &[0x31; 32],
                &other,
                &[0x43; 32],
            ),
            Err(AgentHandleClaimError::AccountMismatch)
        );

        let claim = claim(&owner, &[0x31; 32], 3, "codex_tom");
        let revocation = owner
            .revoke_agent(&authorization, 2, 1_788_100_100)
            .expect("revocation");
        assert!(matches!(
            claim.verify_current(Some(&revocation)),
            Err(AgentHandleClaimError::InvalidAuthorization(_))
        ));
    }

    #[test]
    fn two_agents_under_one_account_are_distinct_registry_subjects() {
        let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
        let first = claim(&owner, &[0x31; 32], 4, "codex_tom").subject();
        let second = claim(&owner, &[0x32; 32], 5, "research_tom").subject();
        assert_eq!(first.account_id, second.account_id);
        assert_ne!(first.authorization_id, second.authorization_id);
        assert_ne!(first.agent_public_key, second.agent_public_key);
    }
}
