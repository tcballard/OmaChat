use std::error::Error;
use std::fmt;

use omachat_crypto::{AccountId, AgentLifecycleError, AgentLifecycleState};
use omachat_store::{SealedStore, StoreError};

pub const AGENT_LIFECYCLE_RECORD_NAME: &str = "agent-lifecycle-v1";

pub struct SealedAgentLifecycle<'a> {
    store: &'a SealedStore,
}

impl<'a> SealedAgentLifecycle<'a> {
    pub fn new(store: &'a SealedStore) -> Self {
        Self { store }
    }

    pub fn load(
        &self,
        expected_account_id: &AccountId,
    ) -> Result<SealedAgentLifecycleState, SealedAgentLifecycleError> {
        let encoded = match self.store.read(AGENT_LIFECYCLE_RECORD_NAME) {
            Ok(encoded) => encoded,
            Err(StoreError::RecordNotFound) => return Ok(SealedAgentLifecycleState::Missing),
            Err(error) => return Err(error.into()),
        };
        let state = AgentLifecycleState::from_json(&encoded)?;
        if state.account_id() != expected_account_id {
            return Err(SealedAgentLifecycleError::AccountMismatch);
        }
        Ok(SealedAgentLifecycleState::Loaded(state))
    }

    pub fn save(&self, state: &AgentLifecycleState) -> Result<(), SealedAgentLifecycleError> {
        let encoded = state.to_json()?;
        self.store.write(AGENT_LIFECYCLE_RECORD_NAME, &encoded)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), SealedAgentLifecycleError> {
        self.store.delete(AGENT_LIFECYCLE_RECORD_NAME)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedAgentLifecycleState {
    Missing,
    Loaded(AgentLifecycleState),
}

#[derive(Debug)]
pub enum SealedAgentLifecycleError {
    Store(StoreError),
    Lifecycle(AgentLifecycleError),
    AccountMismatch,
}

impl fmt::Display for SealedAgentLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "sealed agent storage failed: {error}"),
            Self::Lifecycle(error) => {
                write!(formatter, "agent lifecycle validation failed: {error}")
            }
            Self::AccountMismatch => {
                formatter.write_str("sealed agent lifecycle belongs to another account")
            }
        }
    }
}

impl Error for SealedAgentLifecycleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Lifecycle(error) => Some(error),
            Self::AccountMismatch => None,
        }
    }
}

impl From<StoreError> for SealedAgentLifecycleError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AgentLifecycleError> for SealedAgentLifecycleError {
    fn from(error: AgentLifecycleError) -> Self {
        Self::Lifecycle(error)
    }
}
