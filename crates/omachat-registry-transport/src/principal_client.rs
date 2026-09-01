use crate::{
    PRINCIPAL_REGISTRY_TRANSPORT_VERSION, PrincipalRegistryClaim, PrincipalRegistryOperation,
    PrincipalRegistryProtocolError, PrincipalRegistryRemoteError, PrincipalRegistryRequest,
    PrincipalRegistryResponseOutcome, RegistryTransport, VerifiedPrincipalRegistryRecord,
    decode_principal_response, encode_principal_request,
};
use omachat_crypto::{AccountId, GlobalHandle};
use omachat_registry::proof_bearing_claim::ProofBearingDeviceHandleClaim;
use std::{error::Error, fmt};

/// Verified client for the separately versioned proof-bearing registry.
pub struct PrincipalRegistryClient<T> {
    transport: T,
    pinned_registry_key: [u8; 32],
    next_request_id: u64,
}

impl<T: RegistryTransport> PrincipalRegistryClient<T> {
    #[must_use]
    pub const fn new(transport: T, pinned_registry_key: [u8; 32]) -> Self {
        Self {
            transport,
            pinned_registry_key,
            next_request_id: 1,
        }
    }

    pub async fn claim_device(
        &mut self,
        claim: &ProofBearingDeviceHandleClaim,
    ) -> Result<VerifiedPrincipalRegistryRecord, PrincipalRegistryClientError<T::Error>> {
        let outcome = self
            .request(PrincipalRegistryOperation::ClaimDevice {
                claim: Box::new(PrincipalRegistryClaim::from_claim(claim)),
            })
            .await?;
        match outcome {
            PrincipalRegistryResponseOutcome::Accepted { record } => {
                let verified = record
                    .verify(&self.pinned_registry_key)
                    .map_err(PrincipalRegistryClientError::InvalidEvidence)?;
                if verified.claim() != claim {
                    return Err(PrincipalRegistryClientError::ClaimMismatch);
                }
                Ok(verified)
            }
            PrincipalRegistryResponseOutcome::Rejected { error } => {
                Err(PrincipalRegistryClientError::Rejected(error))
            }
            PrincipalRegistryResponseOutcome::Found { .. }
            | PrincipalRegistryResponseOutcome::NotFound => {
                Err(PrincipalRegistryClientError::UnexpectedOutcome)
            }
        }
    }

    pub async fn lookup_public_key(
        &mut self,
        nostr_public_key: &[u8; 32],
    ) -> Result<Option<VerifiedPrincipalRegistryRecord>, PrincipalRegistryClientError<T::Error>>
    {
        let outcome = self
            .request(PrincipalRegistryOperation::LookupPublicKey {
                nostr_public_key: *nostr_public_key,
            })
            .await?;
        self.verify_lookup(outcome, |record| {
            record
                .claim()
                .principal_proof()
                .payload()
                .nostr_public_key()
                == *nostr_public_key
        })
    }

    pub async fn lookup_handle(
        &mut self,
        handle: &GlobalHandle,
    ) -> Result<Option<VerifiedPrincipalRegistryRecord>, PrincipalRegistryClientError<T::Error>>
    {
        let outcome = self
            .request(PrincipalRegistryOperation::LookupHandle {
                handle: handle.clone(),
            })
            .await?;
        self.verify_lookup(outcome, |record| {
            record.claim_receipt().handle.as_global_handle() == handle
        })
    }

    pub async fn lookup_account(
        &mut self,
        account_id: &AccountId,
    ) -> Result<Option<VerifiedPrincipalRegistryRecord>, PrincipalRegistryClientError<T::Error>>
    {
        let outcome = self
            .request(PrincipalRegistryOperation::LookupAccount {
                account_id: account_id.clone(),
            })
            .await?;
        self.verify_lookup(outcome, |record| {
            record.claim().claim().binding().account_id == *account_id
        })
    }

    async fn request(
        &mut self,
        operation: PrincipalRegistryOperation,
    ) -> Result<PrincipalRegistryResponseOutcome, PrincipalRegistryClientError<T::Error>> {
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(PrincipalRegistryClientError::RequestIdExhausted)?;
        let request = encode_principal_request(&PrincipalRegistryRequest {
            version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation,
        })
        .map_err(PrincipalRegistryClientError::Protocol)?;
        let encoded_response = self
            .transport
            .exchange(request)
            .await
            .map_err(PrincipalRegistryClientError::Transport)?;
        let response = decode_principal_response(&encoded_response)
            .map_err(PrincipalRegistryClientError::Protocol)?;
        if response.request_id != request_id {
            return Err(PrincipalRegistryClientError::CorrelationMismatch {
                expected: request_id,
                actual: response.request_id,
            });
        }
        Ok(response.outcome)
    }

    fn verify_lookup(
        &self,
        outcome: PrincipalRegistryResponseOutcome,
        matches_query: impl FnOnce(&VerifiedPrincipalRegistryRecord) -> bool,
    ) -> Result<Option<VerifiedPrincipalRegistryRecord>, PrincipalRegistryClientError<T::Error>>
    {
        match outcome {
            PrincipalRegistryResponseOutcome::Found { record } => {
                let verified = record
                    .verify(&self.pinned_registry_key)
                    .map_err(PrincipalRegistryClientError::InvalidEvidence)?;
                if !matches_query(&verified) {
                    return Err(PrincipalRegistryClientError::LookupMismatch);
                }
                Ok(Some(verified))
            }
            PrincipalRegistryResponseOutcome::NotFound => Ok(None),
            PrincipalRegistryResponseOutcome::Rejected { error } => {
                Err(PrincipalRegistryClientError::Rejected(error))
            }
            PrincipalRegistryResponseOutcome::Accepted { .. } => {
                Err(PrincipalRegistryClientError::UnexpectedOutcome)
            }
        }
    }

    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[derive(Debug)]
pub enum PrincipalRegistryClientError<E> {
    Transport(E),
    Protocol(PrincipalRegistryProtocolError),
    CorrelationMismatch { expected: u64, actual: u64 },
    Rejected(PrincipalRegistryRemoteError),
    InvalidEvidence(PrincipalRegistryProtocolError),
    ClaimMismatch,
    LookupMismatch,
    UnexpectedOutcome,
    RequestIdExhausted,
}

impl<E: fmt::Display> fmt::Display for PrincipalRegistryClientError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => {
                write!(formatter, "principal registry transport failed: {error}")
            }
            Self::Protocol(error) => {
                write!(formatter, "principal registry protocol failed: {error}")
            }
            Self::CorrelationMismatch { expected, actual } => write!(
                formatter,
                "principal registry response ID {actual} does not match request {expected}"
            ),
            Self::Rejected(error) => write!(
                formatter,
                "principal registry rejected claim {:?}: {}",
                error.code, error.message
            ),
            Self::InvalidEvidence(error) => {
                write!(
                    formatter,
                    "principal registry returned invalid evidence: {error}"
                )
            }
            Self::ClaimMismatch => {
                formatter.write_str("principal registry result does not match the submitted claim")
            }
            Self::LookupMismatch => {
                formatter.write_str("principal registry result does not match the lookup key")
            }
            Self::UnexpectedOutcome => {
                formatter.write_str("principal registry returned an unexpected outcome")
            }
            Self::RequestIdExhausted => {
                formatter.write_str("principal registry request IDs are exhausted")
            }
        }
    }
}

impl<E: Error + 'static> Error for PrincipalRegistryClientError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Protocol(error) | Self::InvalidEvidence(error) => Some(error),
            _ => None,
        }
    }
}
