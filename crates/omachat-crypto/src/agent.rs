use crate::{AccountId, AccountSecrets, DisplayName};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use k256::schnorr::{
    Signature as SchnorrSignature, SigningKey as SchnorrSigningKey,
    VerifyingKey as SchnorrVerifyingKey,
};
use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const VERSION: u16 = 1;
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const ID_HEX_BYTES: usize = 64;
const AUTHORIZATION_ID_PREFIX: &str = "oag1_";
const AUTHORIZATION_ID_DOMAIN: &[u8] = b"omachat.agent-authorization-id.v1\0";
const REQUEST_DOMAIN: &[u8] = b"omachat.agent-authorization-request.v1\0";
const AUTHORIZATION_DOMAIN: &[u8] = b"omachat.agent-authorization.v1\0";
const AUTHORIZATION_HASH_DOMAIN: &[u8] = b"omachat.agent-authorization-hash.v1\0";
const REVOCATION_DOMAIN: &[u8] = b"omachat.agent-revocation.v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    Agent,
}

impl PrincipalType {
    fn transcript_code(self) -> u8 {
        match self {
            Self::Agent => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AgentAuthorizationId(String);

impl AgentAuthorizationId {
    pub fn parse(value: impl Into<String>) -> Result<Self, AgentError> {
        let value = value.into();
        let Some(digest) = value.strip_prefix(AUTHORIZATION_ID_PREFIX) else {
            return Err(AgentError::InvalidAuthorizationId);
        };
        if digest.len() != ID_HEX_BYTES
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AgentError::InvalidAuthorizationId);
        }
        Ok(Self(value))
    }

    pub fn derive(account_id: &AccountId, agent_public_key: &[u8; KEY_BYTES]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(AUTHORIZATION_ID_DOMAIN);
        hasher.update(account_id.as_str().as_bytes());
        hasher.update(agent_public_key);
        Self(format!(
            "{AUTHORIZATION_ID_PREFIX}{}",
            hex::encode(hasher.finalize())
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentAuthorizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for AgentAuthorizationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentAuthorizationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationRequest {
    pub version: u16,
    pub account_id: AccountId,
    #[serde(with = "bytes32_hex")]
    pub agent_public_key: [u8; KEY_BYTES],
    pub principal_type: PrincipalType,
    pub label: Option<DisplayName>,
    pub requested_at: u64,
    #[serde(with = "signature_hex")]
    pub agent_proof: [u8; SIGNATURE_BYTES],
}

impl AgentAuthorizationRequest {
    pub fn sign(
        agent_secret_key: &[u8; KEY_BYTES],
        account_id: AccountId,
        label: Option<DisplayName>,
        requested_at: u64,
        auxiliary_randomness: &[u8; KEY_BYTES],
    ) -> Result<Self, AgentError> {
        let signing_key = SchnorrSigningKey::from_bytes(agent_secret_key)
            .map_err(|_| AgentError::InvalidAgentSecretKey)?;
        let agent_public_key = signing_key.verifying_key().to_bytes().into();
        let mut request = Self {
            version: VERSION,
            account_id,
            agent_public_key,
            principal_type: PrincipalType::Agent,
            label,
            requested_at,
            agent_proof: [0; SIGNATURE_BYTES],
        };
        request.agent_proof = signing_key
            .sign_raw(&request.proof_digest(), auxiliary_randomness)
            .map_err(|_| AgentError::AgentSigning)?
            .to_bytes();
        Ok(request)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(REQUEST_DOMAIN);
        output.extend_from_slice(&self.version.to_be_bytes());
        push_bytes(&mut output, self.account_id.as_str().as_bytes());
        output.extend_from_slice(&self.agent_public_key);
        output.push(self.principal_type.transcript_code());
        push_optional_string(&mut output, self.label.as_ref().map(DisplayName::as_str));
        output.extend_from_slice(&self.requested_at.to_be_bytes());
        output
    }

    pub fn proof_digest(&self) -> [u8; KEY_BYTES] {
        Sha256::digest(self.signing_bytes()).into()
    }

    pub fn verify(&self) -> Result<(), AgentError> {
        if self.version != VERSION {
            return Err(AgentError::UnsupportedVersion(self.version));
        }
        let verifying_key = SchnorrVerifyingKey::from_bytes(&self.agent_public_key)
            .map_err(|_| AgentError::InvalidAgentPublicKey)?;
        let signature = SchnorrSignature::try_from(self.agent_proof.as_slice())
            .map_err(|_| AgentError::InvalidAgentProof)?;
        verifying_key
            .verify_raw(&self.proof_digest(), &signature)
            .map_err(|_| AgentError::InvalidAgentProof)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentAuthorization {
    pub version: u16,
    pub authorization_id: AgentAuthorizationId,
    pub account_id: AccountId,
    #[serde(with = "bytes32_hex")]
    pub account_root_public_key: [u8; KEY_BYTES],
    pub request: AgentAuthorizationRequest,
    pub revision: u64,
    pub authorized_at: u64,
    #[serde(with = "signature_hex")]
    pub signature: [u8; SIGNATURE_BYTES],
}

impl SignedAgentAuthorization {
    pub fn agent_public_key(&self) -> &[u8; KEY_BYTES] {
        &self.request.agent_public_key
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let request_bytes = self.request.signing_bytes();
        let mut output = Vec::new();
        output.extend_from_slice(AUTHORIZATION_DOMAIN);
        output.extend_from_slice(&self.version.to_be_bytes());
        push_bytes(&mut output, self.authorization_id.as_str().as_bytes());
        push_bytes(&mut output, self.account_id.as_str().as_bytes());
        output.extend_from_slice(&self.account_root_public_key);
        push_bytes(&mut output, &request_bytes);
        output.extend_from_slice(&self.request.agent_proof);
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.extend_from_slice(&self.authorized_at.to_be_bytes());
        output
    }

    pub fn authorization_hash(&self) -> [u8; KEY_BYTES] {
        let transcript = self.signing_bytes();
        let mut hasher = Sha256::new();
        hasher.update(AUTHORIZATION_HASH_DOMAIN);
        push_hash_bytes(&mut hasher, &transcript);
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    pub fn verify(&self) -> Result<(), AgentError> {
        if self.version != VERSION {
            return Err(AgentError::UnsupportedVersion(self.version));
        }
        if self.revision == 0 {
            return Err(AgentError::InvalidRevision);
        }
        if self.authorized_at < self.request.requested_at {
            return Err(AgentError::InvalidAuthorizationTime);
        }
        if self.request.account_id != self.account_id {
            return Err(AgentError::AccountMismatch);
        }
        self.request.verify()?;
        let expected_account_id = AccountId::derive(&self.account_root_public_key);
        if expected_account_id != self.account_id {
            return Err(AgentError::AccountMismatch);
        }
        let expected_authorization_id =
            AgentAuthorizationId::derive(&self.account_id, &self.request.agent_public_key);
        if expected_authorization_id != self.authorization_id {
            return Err(AgentError::AuthorizationMismatch);
        }
        let verifying_key = Ed25519VerifyingKey::from_bytes(&self.account_root_public_key)
            .map_err(|_| AgentError::InvalidAccountRootPublicKey)?;
        verifying_key
            .verify_strict(
                &self.signing_bytes(),
                &Ed25519Signature::from_bytes(&self.signature),
            )
            .map_err(|_| AgentError::InvalidAccountSignature)
    }

    pub fn verify_current(
        &self,
        revocation: Option<&SignedAgentRevocation>,
    ) -> Result<(), AgentError> {
        self.verify()?;
        if let Some(revocation) = revocation {
            revocation.verify(self)?;
            return Err(AgentError::Revoked);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentRevocation {
    pub version: u16,
    pub authorization_id: AgentAuthorizationId,
    pub account_id: AccountId,
    #[serde(with = "bytes32_hex")]
    pub account_root_public_key: [u8; KEY_BYTES],
    #[serde(with = "bytes32_hex")]
    pub agent_public_key: [u8; KEY_BYTES],
    #[serde(with = "bytes32_hex")]
    pub authorization_hash: [u8; KEY_BYTES],
    pub authorization_revision: u64,
    pub revision: u64,
    pub revoked_at: u64,
    #[serde(with = "signature_hex")]
    pub signature: [u8; SIGNATURE_BYTES],
}

impl SignedAgentRevocation {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(REVOCATION_DOMAIN);
        output.extend_from_slice(&self.version.to_be_bytes());
        push_bytes(&mut output, self.authorization_id.as_str().as_bytes());
        push_bytes(&mut output, self.account_id.as_str().as_bytes());
        output.extend_from_slice(&self.account_root_public_key);
        output.extend_from_slice(&self.agent_public_key);
        output.extend_from_slice(&self.authorization_hash);
        output.extend_from_slice(&self.authorization_revision.to_be_bytes());
        output.extend_from_slice(&self.revision.to_be_bytes());
        output.extend_from_slice(&self.revoked_at.to_be_bytes());
        output
    }

    pub fn verify(&self, authorization: &SignedAgentAuthorization) -> Result<(), AgentError> {
        authorization.verify()?;
        if self.version != VERSION {
            return Err(AgentError::UnsupportedVersion(self.version));
        }
        if self.authorization_id != authorization.authorization_id
            || self.account_id != authorization.account_id
            || self.account_root_public_key != authorization.account_root_public_key
            || self.agent_public_key != *authorization.agent_public_key()
            || self.authorization_hash != authorization.authorization_hash()
            || self.authorization_revision != authorization.revision
        {
            return Err(AgentError::AuthorizationMismatch);
        }
        if self.revision <= authorization.revision {
            return Err(AgentError::InvalidRevision);
        }
        if self.revoked_at < authorization.authorized_at {
            return Err(AgentError::InvalidRevocationTime);
        }
        let verifying_key = Ed25519VerifyingKey::from_bytes(&self.account_root_public_key)
            .map_err(|_| AgentError::InvalidAccountRootPublicKey)?;
        verifying_key
            .verify_strict(
                &self.signing_bytes(),
                &Ed25519Signature::from_bytes(&self.signature),
            )
            .map_err(|_| AgentError::InvalidAccountSignature)
    }
}

impl AccountSecrets {
    pub fn authorize_agent(
        &self,
        request: AgentAuthorizationRequest,
        revision: u64,
        authorized_at: u64,
    ) -> Result<SignedAgentAuthorization, AgentError> {
        request.verify()?;
        let public = self.public_identity();
        if request.account_id != public.account_id {
            return Err(AgentError::AccountMismatch);
        }
        if revision == 0 {
            return Err(AgentError::InvalidRevision);
        }
        if authorized_at < request.requested_at {
            return Err(AgentError::InvalidAuthorizationTime);
        }
        let authorization_id =
            AgentAuthorizationId::derive(&request.account_id, &request.agent_public_key);
        let mut authorization = SignedAgentAuthorization {
            version: VERSION,
            authorization_id,
            account_id: public.account_id,
            account_root_public_key: public.account_root_public_key,
            request,
            revision,
            authorized_at,
            signature: [0; SIGNATURE_BYTES],
        };
        authorization.signature = self.sign_account_root_transcript(&authorization.signing_bytes());
        Ok(authorization)
    }

    pub fn revoke_agent(
        &self,
        authorization: &SignedAgentAuthorization,
        revision: u64,
        revoked_at: u64,
    ) -> Result<SignedAgentRevocation, AgentError> {
        authorization.verify()?;
        let public = self.public_identity();
        if authorization.account_id != public.account_id
            || authorization.account_root_public_key != public.account_root_public_key
        {
            return Err(AgentError::AccountMismatch);
        }
        if revision <= authorization.revision {
            return Err(AgentError::InvalidRevision);
        }
        if revoked_at < authorization.authorized_at {
            return Err(AgentError::InvalidRevocationTime);
        }
        let mut revocation = SignedAgentRevocation {
            version: VERSION,
            authorization_id: authorization.authorization_id.clone(),
            account_id: authorization.account_id.clone(),
            account_root_public_key: authorization.account_root_public_key,
            agent_public_key: *authorization.agent_public_key(),
            authorization_hash: authorization.authorization_hash(),
            authorization_revision: authorization.revision,
            revision,
            revoked_at,
            signature: [0; SIGNATURE_BYTES],
        };
        revocation.signature = self.sign_account_root_transcript(&revocation.signing_bytes());
        Ok(revocation)
    }
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("bounded agent field length fits u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn push_hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("bounded agent field length fits u32");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn push_optional_string(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            push_bytes(output, value.as_bytes());
        }
        None => output.push(0),
    }
}

mod bytes32_hex {
    use super::{KEY_BYTES, de};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; KEY_BYTES], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; KEY_BYTES], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != KEY_BYTES * 2
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(de::Error::custom("invalid lowercase 32-byte hex value"));
        }
        hex::decode(encoded)
            .map_err(de::Error::custom)?
            .try_into()
            .map_err(|_| de::Error::custom("invalid 32-byte value length"))
    }
}

mod signature_hex {
    use super::{SIGNATURE_BYTES, de};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; SIGNATURE_BYTES], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_BYTES], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != SIGNATURE_BYTES * 2
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(de::Error::custom("invalid lowercase 64-byte hex signature"));
        }
        hex::decode(encoded)
            .map_err(de::Error::custom)?
            .try_into()
            .map_err(|_| de::Error::custom("invalid signature length"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentError {
    InvalidAuthorizationId,
    UnsupportedVersion(u16),
    InvalidAgentSecretKey,
    InvalidAgentPublicKey,
    AgentSigning,
    InvalidAgentProof,
    InvalidAccountRootPublicKey,
    InvalidAccountSignature,
    AccountMismatch,
    AuthorizationMismatch,
    InvalidRevision,
    InvalidAuthorizationTime,
    InvalidRevocationTime,
    Revoked,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuthorizationId => formatter.write_str("invalid agent authorization ID"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported agent authorization version {version}"
                )
            }
            Self::InvalidAgentSecretKey => formatter.write_str("invalid agent secret key"),
            Self::InvalidAgentPublicKey => formatter.write_str("invalid agent public key"),
            Self::AgentSigning => formatter.write_str("agent proof signing failed"),
            Self::InvalidAgentProof => formatter.write_str("invalid agent proof of key control"),
            Self::InvalidAccountRootPublicKey => {
                formatter.write_str("invalid account root public key")
            }
            Self::InvalidAccountSignature => {
                formatter.write_str("invalid account-root agent signature")
            }
            Self::AccountMismatch => formatter.write_str("agent account does not match root key"),
            Self::AuthorizationMismatch => {
                formatter.write_str("agent authorization fields do not match")
            }
            Self::InvalidRevision => formatter.write_str("invalid agent lifecycle revision"),
            Self::InvalidAuthorizationTime => {
                formatter.write_str("agent authorization predates its request")
            }
            Self::InvalidRevocationTime => {
                formatter.write_str("agent revocation predates authorization")
            }
            Self::Revoked => formatter.write_str("agent authorization is revoked"),
        }
    }
}

impl Error for AgentError {}
