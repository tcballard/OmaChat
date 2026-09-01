use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{AccountId, SignedAgentAuthorization, SignedAgentRevocation};

pub const MAX_AGENTS_PER_ACCOUNT: usize = 128;
const STATE_VERSION: u16 = 1;
const MAX_SERIALIZED_STATE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentLifecycleState {
    account_id: AccountId,
    records: BTreeMap<String, AgentLifecycleRecord>,
}

impl AgentLifecycleState {
    pub fn new(account_id: AccountId) -> Self {
        Self {
            account_id,
            records: BTreeMap::new(),
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> impl ExactSizeIterator<Item = &AgentLifecycleRecord> {
        self.records.values()
    }

    pub fn get(&self, authorization_id: &str) -> Option<&AgentLifecycleRecord> {
        self.records.get(authorization_id)
    }

    pub fn add_authorization(
        &mut self,
        authorization: SignedAgentAuthorization,
    ) -> Result<AgentLifecycleMutation, AgentLifecycleError> {
        authorization
            .verify()
            .map_err(|error| AgentLifecycleError::Cryptographic(error.to_string()))?;
        if authorization.account_id != self.account_id {
            return Err(AgentLifecycleError::AccountMismatch);
        }
        let key = authorization.authorization_id.as_str().to_owned();
        if let Some(current) = self.records.get(&key) {
            if current.authorization == authorization {
                return Ok(AgentLifecycleMutation::Unchanged);
            }
            return Err(AgentLifecycleError::ConflictingAuthorization);
        }
        if self.records.len() >= MAX_AGENTS_PER_ACCOUNT {
            return Err(AgentLifecycleError::TooManyAgents);
        }
        self.records.insert(
            key.clone(),
            AgentLifecycleRecord {
                authorization,
                revocation: None,
            },
        );
        if let Err(error) = self.ensure_serializable() {
            self.records.remove(&key);
            return Err(error);
        }
        Ok(AgentLifecycleMutation::Stored)
    }

    pub fn add_revocation(
        &mut self,
        revocation: SignedAgentRevocation,
    ) -> Result<AgentLifecycleMutation, AgentLifecycleError> {
        if revocation.account_id != self.account_id {
            return Err(AgentLifecycleError::AccountMismatch);
        }
        let key = revocation.authorization_id.as_str().to_owned();
        let record = self
            .records
            .get_mut(&key)
            .ok_or(AgentLifecycleError::UnknownAuthorization)?;
        revocation
            .verify(&record.authorization)
            .map_err(|error| AgentLifecycleError::Cryptographic(error.to_string()))?;
        if let Some(current) = &record.revocation {
            if current == &revocation {
                return Ok(AgentLifecycleMutation::Unchanged);
            }
            return Err(AgentLifecycleError::ConflictingRevocation);
        }
        record.revocation = Some(revocation);
        if let Err(error) = self.ensure_serializable() {
            self.records
                .get_mut(&key)
                .expect("validated agent record remains present")
                .revocation = None;
            return Err(error);
        }
        Ok(AgentLifecycleMutation::Stored)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, AgentLifecycleError> {
        let persisted = PersistedAgentLifecycleState {
            version: STATE_VERSION,
            account_id: self.account_id.clone(),
            records: self
                .records
                .values()
                .map(|record| PersistedAgentLifecycleRecord {
                    authorization: record.authorization.clone(),
                    revocation: record.revocation.clone(),
                })
                .collect(),
        };
        let encoded =
            serde_json::to_vec(&persisted).map_err(|_| AgentLifecycleError::InvalidEncoding)?;
        if encoded.len() > MAX_SERIALIZED_STATE_BYTES {
            return Err(AgentLifecycleError::StateTooLarge);
        }
        Ok(encoded)
    }

    pub fn from_json(encoded: &[u8]) -> Result<Self, AgentLifecycleError> {
        if encoded.len() > MAX_SERIALIZED_STATE_BYTES {
            return Err(AgentLifecycleError::StateTooLarge);
        }
        let persisted: PersistedAgentLifecycleState =
            serde_json::from_slice(encoded).map_err(|_| AgentLifecycleError::InvalidEncoding)?;
        if persisted.version != STATE_VERSION {
            return Err(AgentLifecycleError::UnsupportedVersion(persisted.version));
        }
        if persisted.records.len() > MAX_AGENTS_PER_ACCOUNT {
            return Err(AgentLifecycleError::TooManyAgents);
        }

        let mut seen = BTreeSet::new();
        let mut state = Self::new(persisted.account_id);
        for record in persisted.records {
            let key = record.authorization.authorization_id.as_str().to_owned();
            if !seen.insert(key) {
                return Err(AgentLifecycleError::InvalidEncoding);
            }
            state.add_authorization(record.authorization)?;
            if let Some(revocation) = record.revocation {
                state.add_revocation(revocation)?;
            }
        }
        Ok(state)
    }

    fn ensure_serializable(&self) -> Result<(), AgentLifecycleError> {
        self.to_json().map(|_| ())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentLifecycleRecord {
    authorization: SignedAgentAuthorization,
    revocation: Option<SignedAgentRevocation>,
}

impl AgentLifecycleRecord {
    pub fn authorization(&self) -> &SignedAgentAuthorization {
        &self.authorization
    }

    pub fn revocation(&self) -> Option<&SignedAgentRevocation> {
        self.revocation.as_ref()
    }

    pub fn status(&self) -> AgentLifecycleStatus {
        if self.revocation.is_some() {
            AgentLifecycleStatus::Revoked
        } else {
            AgentLifecycleStatus::Active
        }
    }

    pub fn verify_current(&self) -> Result<(), AgentLifecycleError> {
        self.authorization
            .verify_current(self.revocation.as_ref())
            .map_err(|error| AgentLifecycleError::Cryptographic(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentLifecycleStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentLifecycleMutation {
    Stored,
    Unchanged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentLifecycleError {
    InvalidEncoding,
    UnsupportedVersion(u16),
    StateTooLarge,
    TooManyAgents,
    AccountMismatch,
    UnknownAuthorization,
    ConflictingAuthorization,
    ConflictingRevocation,
    Cryptographic(String),
}

impl fmt::Display for AgentLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("invalid agent lifecycle encoding"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported agent lifecycle version {version}")
            }
            Self::StateTooLarge => formatter.write_str("agent lifecycle state exceeds its bound"),
            Self::TooManyAgents => formatter.write_str("too many agents for one account"),
            Self::AccountMismatch => formatter.write_str("agent belongs to another account"),
            Self::UnknownAuthorization => {
                formatter.write_str("agent revocation has no matching authorization")
            }
            Self::ConflictingAuthorization => {
                formatter.write_str("conflicting agent authorization")
            }
            Self::ConflictingRevocation => formatter.write_str("conflicting agent revocation"),
            Self::Cryptographic(error) => {
                write!(
                    formatter,
                    "agent lifecycle signature validation failed: {error}"
                )
            }
        }
    }
}

impl Error for AgentLifecycleError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedAgentLifecycleState {
    version: u16,
    account_id: AccountId,
    records: Vec<PersistedAgentLifecycleRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedAgentLifecycleRecord {
    authorization: SignedAgentAuthorization,
    revocation: Option<SignedAgentRevocation>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountSecrets, AgentAuthorizationRequest};

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
            .expect("owner authorization")
    }

    #[test]
    fn multiple_agents_and_revocation_survive_strict_restart_validation() {
        let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
        let first = authorization(&owner, &[0x31; 32]);
        let second = authorization(&owner, &[0x32; 32]);
        let revocation = owner
            .revoke_agent(&first, 2, 1_788_100_100)
            .expect("revocation");
        let mut state = AgentLifecycleState::new(owner.public_identity().account_id);
        assert_eq!(
            state.add_authorization(first.clone()),
            Ok(AgentLifecycleMutation::Stored)
        );
        assert_eq!(
            state.add_authorization(second.clone()),
            Ok(AgentLifecycleMutation::Stored)
        );
        assert_eq!(
            state.add_revocation(revocation),
            Ok(AgentLifecycleMutation::Stored)
        );

        let restarted = AgentLifecycleState::from_json(&state.to_json().expect("state JSON"))
            .expect("validated restart");
        assert_eq!(restarted, state);
        assert_eq!(restarted.len(), 2);
        let first_record = restarted
            .get(first.authorization_id.as_str())
            .expect("first agent");
        assert_eq!(first_record.status(), AgentLifecycleStatus::Revoked);
        assert!(first_record.verify_current().is_err());
        let second_record = restarted
            .get(second.authorization_id.as_str())
            .expect("second agent");
        assert_eq!(second_record.status(), AgentLifecycleStatus::Active);
        second_record.verify_current().expect("active agent");
        assert_ne!(
            first_record.authorization().agent_public_key(),
            second_record.authorization().agent_public_key()
        );
    }

    #[test]
    fn cross_account_and_conflicting_state_fail_closed() {
        let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
        let other = AccountSecrets::from_seeds([3; 32], [4; 32]);
        let first = authorization(&owner, &[0x31; 32]);
        let mut state = AgentLifecycleState::new(owner.public_identity().account_id);
        state
            .add_authorization(first.clone())
            .expect("first authorization");
        assert_eq!(
            state.add_authorization(authorization(&other, &[0x32; 32])),
            Err(AgentLifecycleError::AccountMismatch)
        );

        let mut conflicting = first;
        conflicting.request.requested_at += 1;
        assert!(matches!(
            state.add_authorization(conflicting),
            Err(AgentLifecycleError::Cryptographic(_))
        ));
    }

    #[test]
    fn signed_payload_tampering_is_rejected_on_decode() {
        let owner = AccountSecrets::from_seeds([1; 32], [2; 32]);
        let authorization = authorization(&owner, &[0x31; 32]);
        let mut state = AgentLifecycleState::new(owner.public_identity().account_id);
        state
            .add_authorization(authorization)
            .expect("authorization");
        let encoded = state.to_json().expect("state JSON");
        let tampered = String::from_utf8(encoded)
            .expect("UTF-8 JSON")
            .replace("1788100000", "1788100001");
        assert!(matches!(
            AgentLifecycleState::from_json(tampered.as_bytes()),
            Err(AgentLifecycleError::Cryptographic(_))
        ));
        assert!(
            AgentLifecycleState::from_json(br#"{"version":1,"account_id":"bad","records":[]}"#)
                .is_err()
        );
    }
}
