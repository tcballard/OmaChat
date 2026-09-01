use crate::{
    PrincipalRegistryOperation, PrincipalRegistryProtocolError, PrincipalRegistryRecordWire,
    PrincipalRegistryRemoteCode, PrincipalRegistryRemoteError, PrincipalRegistryResponse,
    PrincipalRegistryResponseOutcome, RegistryRemoteCode, decode_principal_request,
    encode_principal_response,
};
use omachat_registry::{
    RegistryError,
    principal_registry::{PrincipalRegistryError, PrincipalRegistryHead, PrincipalRegistryState},
};
use omachat_store::{PrincipalRegistryVault, PrincipalRegistryVaultError, SealedStore};
use std::{error::Error, fmt};

/// Crash-safe proof-bearing registry service over one sealed authoritative state.
pub struct PrincipalRegistryService<'store> {
    store: &'store SealedStore,
    state: PrincipalRegistryState,
    head: PrincipalRegistryHead,
    unavailable: bool,
}

impl<'store> PrincipalRegistryService<'store> {
    /// Opens and independently replays persisted state.
    ///
    /// `expected_head` must come from storage with rollback guarantees
    /// independent of the sealed registry record. Callers that pass `None`
    /// retain corruption and signature checks but cannot detect rollback of an
    /// otherwise valid older sealed record.
    pub fn open(
        store: &'store SealedStore,
        registry_signing_seed: [u8; 32],
        expected_head: Option<&PrincipalRegistryHead>,
    ) -> Result<Self, PrincipalRegistryServiceError> {
        let state =
            PrincipalRegistryVault::load_or_create(store, registry_signing_seed, expected_head)
                .map_err(PrincipalRegistryServiceError::Persistence)?;
        let head = state.snapshot().head;
        Ok(Self {
            store,
            state,
            head,
            unavailable: false,
        })
    }

    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.state.verifying_key()
    }

    /// Returns the latest signed head for storage in an independent rollback
    /// anchor after a successful response.
    #[must_use]
    pub const fn head(&self) -> &PrincipalRegistryHead {
        &self.head
    }

    #[must_use]
    pub const fn is_available(&self) -> bool {
        !self.unavailable
    }

    pub fn handle(
        &mut self,
        encoded_request: &[u8],
        accepted_at: u64,
    ) -> Result<Vec<u8>, PrincipalRegistryServiceError> {
        if self.unavailable {
            return Err(PrincipalRegistryServiceError::Unavailable);
        }
        let request = decode_principal_request(encoded_request)
            .map_err(PrincipalRegistryServiceError::Protocol)?;
        let request_id = request.request_id;
        let outcome = match request.operation {
            PrincipalRegistryOperation::ClaimDevice { claim } => match claim.to_claim() {
                Ok(claim) => match self.state.apply_device(claim, accepted_at) {
                    Ok(record) => {
                        match PrincipalRegistryVault::persist(self.store, &self.state) {
                            Ok(head) => self.head = head,
                            Err(error) => {
                                self.unavailable = true;
                                return Err(PrincipalRegistryServiceError::Persistence(error));
                            }
                        }
                        PrincipalRegistryResponseOutcome::Accepted {
                            record: Box::new(PrincipalRegistryRecordWire::from_record(&record)),
                        }
                    }
                    Err(error) => PrincipalRegistryResponseOutcome::Rejected {
                        error: remote_error(&error),
                    },
                },
                Err(_) => PrincipalRegistryResponseOutcome::Rejected {
                    error: PrincipalRegistryRemoteError {
                        code: PrincipalRegistryRemoteCode::InvalidClaim,
                        message: "proof-bearing handle claim is invalid".to_owned(),
                    },
                },
            },
            PrincipalRegistryOperation::LookupPublicKey { nostr_public_key } => {
                self.state.public_key_record(&nostr_public_key).map_or(
                    PrincipalRegistryResponseOutcome::NotFound,
                    |record| PrincipalRegistryResponseOutcome::Found {
                        record: Box::new(PrincipalRegistryRecordWire::from_record(record)),
                    },
                )
            }
            PrincipalRegistryOperation::LookupAccount { account_id } => {
                self.state.account_record(account_id.as_str()).map_or(
                    PrincipalRegistryResponseOutcome::NotFound,
                    |record| PrincipalRegistryResponseOutcome::Found {
                        record: Box::new(PrincipalRegistryRecordWire::from_record(record)),
                    },
                )
            }
        };
        encode_principal_response(&PrincipalRegistryResponse {
            version: crate::PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
            request_id,
            outcome,
        })
        .map_err(PrincipalRegistryServiceError::Protocol)
    }
}

fn remote_error(error: &PrincipalRegistryError) -> PrincipalRegistryRemoteError {
    let code = match error {
        PrincipalRegistryError::InvalidProofBearingClaim(_) => {
            PrincipalRegistryRemoteCode::InvalidClaim
        }
        PrincipalRegistryError::Registry(error) => map_root_code(error),
        PrincipalRegistryError::CommandIdConflict => PrincipalRegistryRemoteCode::CommandConflict,
        PrincipalRegistryError::PublicKeyAlreadyBound { .. } => {
            PrincipalRegistryRemoteCode::PublicKeyTaken
        }
        PrincipalRegistryError::InconsistentState => PrincipalRegistryRemoteCode::InvalidState,
    };
    PrincipalRegistryRemoteError {
        code,
        message: error.to_string(),
    }
}

fn map_root_code(error: &RegistryError) -> PrincipalRegistryRemoteCode {
    match RegistryRemoteCode::from(error) {
        RegistryRemoteCode::InvalidClaim => PrincipalRegistryRemoteCode::InvalidClaim,
        RegistryRemoteCode::StaleRevision => PrincipalRegistryRemoteCode::StaleRevision,
        RegistryRemoteCode::CommandConflict => PrincipalRegistryRemoteCode::CommandConflict,
        RegistryRemoteCode::HandleTaken => PrincipalRegistryRemoteCode::HandleTaken,
        RegistryRemoteCode::PolicyDeferred => PrincipalRegistryRemoteCode::PolicyDeferred,
        RegistryRemoteCode::Exhausted => PrincipalRegistryRemoteCode::Exhausted,
        RegistryRemoteCode::InvalidState => PrincipalRegistryRemoteCode::InvalidState,
    }
}

#[derive(Debug)]
pub enum PrincipalRegistryServiceError {
    Protocol(PrincipalRegistryProtocolError),
    Persistence(PrincipalRegistryVaultError),
    Unavailable,
}

impl fmt::Display for PrincipalRegistryServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(formatter, "principal registry protocol failed: {error}")
            }
            Self::Persistence(error) => {
                write!(formatter, "principal registry persistence failed: {error}")
            }
            Self::Unavailable => formatter.write_str(
                "principal registry service is unavailable after an uncertain persistence outcome",
            ),
        }
    }
}

impl Error for PrincipalRegistryServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Persistence(error) => Some(error),
            Self::Unavailable => None,
        }
    }
}
