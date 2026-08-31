//! Bounded registry service protocol and verified client transport adapter.
//!
//! This crate deliberately provides no listener, deployment configuration, or
//! freshness cache. A hosting layer can carry these strict request/response
//! bytes, while clients accept a receipt only after verifying a separately
//! pinned registry key and the exact signed claim.

mod evidence;

pub use evidence::{RegistryEvidenceClient, RegistryEvidenceError, RegistryEvidenceResolution};

use omachat_crypto::{AccountId, GlobalHandle, SignedLocalAccountBinding};
use omachat_registry::{
    AcceptedRegistryRecord, CommandId, HandleClaim, RegistryError, RegistryReceipt, RegistryState,
};
use omachat_store::{RegistryVault, RegistryVaultError, SealedStore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{error::Error, fmt, future::Future};

pub const REGISTRY_TRANSPORT_VERSION: u16 = 2;
pub const MAX_REGISTRY_MESSAGE_BYTES: usize = 64 * 1024;
const CLAIM_WIRE_VERSION: u16 = 1;
const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryClaim {
    pub version: u16,
    pub command_id: CommandId,
    pub expected_revision: u64,
    pub binding: SignedLocalAccountBinding,
    pub proof: Vec<u8>,
}

impl RegistryClaim {
    #[must_use]
    pub fn from_claim(claim: &HandleClaim) -> Self {
        Self {
            version: CLAIM_WIRE_VERSION,
            command_id: claim.command_id(),
            expected_revision: claim.expected_revision(),
            binding: claim.binding().clone(),
            proof: claim.proof().to_vec(),
        }
    }

    pub fn to_claim(&self) -> Result<HandleClaim, RegistryError> {
        if self.version != CLAIM_WIRE_VERSION {
            return Err(RegistryError::UnsupportedClaimVersion(self.version));
        }
        let proof: [u8; SIGNATURE_BYTES] = self
            .proof
            .as_slice()
            .try_into()
            .map_err(|_| RegistryError::InvalidClaimProof)?;
        HandleClaim::from_signed_parts(
            self.command_id,
            self.expected_revision,
            self.binding.clone(),
            proof,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRequest {
    pub version: u16,
    pub request_id: u64,
    pub operation: RegistryOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegistryOperation {
    Claim { claim: Box<RegistryClaim> },
    LookupHandle { handle: GlobalHandle },
    LookupAccount { account_id: AccountId },
}

impl RegistryRequest {
    #[must_use]
    pub fn claim(request_id: u64, claim: &HandleClaim) -> Self {
        Self {
            version: REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation: RegistryOperation::Claim {
                claim: Box::new(RegistryClaim::from_claim(claim)),
            },
        }
    }

    #[must_use]
    pub fn lookup_handle(request_id: u64, handle: GlobalHandle) -> Self {
        Self {
            version: REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation: RegistryOperation::LookupHandle { handle },
        }
    }

    #[must_use]
    pub const fn lookup_account(request_id: u64, account_id: AccountId) -> Self {
        Self {
            version: REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation: RegistryOperation::LookupAccount { account_id },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRecord {
    pub claim: RegistryClaim,
    pub receipt: Box<RegistryReceipt>,
}

impl RegistryRecord {
    #[must_use]
    pub fn from_record(record: AcceptedRegistryRecord) -> Self {
        Self {
            claim: RegistryClaim::from_claim(&record.claim),
            receipt: Box::new(record.receipt),
        }
    }

    pub fn to_record(&self) -> Result<AcceptedRegistryRecord, RegistryError> {
        Ok(AcceptedRegistryRecord {
            claim: self.claim.to_claim()?,
            receipt: (*self.receipt).clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryResponse {
    pub version: u16,
    pub request_id: u64,
    pub outcome: RegistryResponseOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegistryResponseOutcome {
    Accepted { receipt: Box<RegistryReceipt> },
    Found { record: Box<RegistryRecord> },
    NotFound,
    Rejected { error: RegistryRemoteError },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRemoteError {
    pub code: RegistryRemoteCode,
    pub message: String,
}

impl RegistryRemoteError {
    fn from_registry(error: &RegistryError) -> Self {
        Self {
            code: RegistryRemoteCode::from(error),
            message: error.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryRemoteCode {
    InvalidClaim,
    StaleRevision,
    CommandConflict,
    HandleTaken,
    PolicyDeferred,
    Exhausted,
    InvalidState,
}

impl From<&RegistryError> for RegistryRemoteCode {
    fn from(error: &RegistryError) -> Self {
        match error {
            RegistryError::StaleRevision { .. } | RegistryError::StaleBindingRevision { .. } => {
                Self::StaleRevision
            }
            RegistryError::CommandIdConflict => Self::CommandConflict,
            RegistryError::HandleTaken(_) => Self::HandleTaken,
            RegistryError::HandleRenameDeferred => Self::PolicyDeferred,
            RegistryError::RevisionExhausted | RegistryError::SequenceExhausted => Self::Exhausted,
            RegistryError::UnsupportedStateVersion(_)
            | RegistryError::InvalidRegistryState
            | RegistryError::InvalidRegistryKey
            | RegistryError::InvalidReceiptSequence
            | RegistryError::InvalidReceiptSignature
            | RegistryError::InvalidReceiptChain
            | RegistryError::InvalidAccountReceiptChain
            | RegistryError::ReceiptClaimMismatch
            | RegistryError::HistoricalClaimUnavailable => Self::InvalidState,
            RegistryError::InvalidBinding(_)
            | RegistryError::MissingHandle
            | RegistryError::ClaimAccountMismatch
            | RegistryError::InvalidClaimProof
            | RegistryError::InvalidBindingRevision { .. }
            | RegistryError::UnsupportedClaimVersion(_)
            | RegistryError::UnsupportedReceiptVersion(_) => Self::InvalidClaim,
        }
    }
}

pub fn encode_request(request: &RegistryRequest) -> Result<Vec<u8>, RegistryProtocolError> {
    encode_bounded(request)
}

pub fn decode_request(bytes: &[u8]) -> Result<RegistryRequest, RegistryProtocolError> {
    let request: RegistryRequest = decode_bounded(bytes)?;
    if request.version != REGISTRY_TRANSPORT_VERSION {
        return Err(RegistryProtocolError::UnsupportedVersion(request.version));
    }
    Ok(request)
}

pub fn encode_response(response: &RegistryResponse) -> Result<Vec<u8>, RegistryProtocolError> {
    encode_bounded(response)
}

pub fn decode_response(bytes: &[u8]) -> Result<RegistryResponse, RegistryProtocolError> {
    let response: RegistryResponse = decode_bounded(bytes)?;
    if response.version != REGISTRY_TRANSPORT_VERSION {
        return Err(RegistryProtocolError::UnsupportedVersion(response.version));
    }
    Ok(response)
}

fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, RegistryProtocolError> {
    let encoded = serde_json::to_vec(value).map_err(|_| RegistryProtocolError::Encoding)?;
    if encoded.len() > MAX_REGISTRY_MESSAGE_BYTES {
        return Err(RegistryProtocolError::MessageTooLarge);
    }
    Ok(encoded)
}

fn decode_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, RegistryProtocolError> {
    if bytes.len() > MAX_REGISTRY_MESSAGE_BYTES {
        return Err(RegistryProtocolError::MessageTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| RegistryProtocolError::Malformed)
}

#[derive(Debug, Eq, PartialEq)]
pub enum RegistryProtocolError {
    MessageTooLarge,
    Malformed,
    UnsupportedVersion(u16),
    Encoding,
}

impl fmt::Display for RegistryProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge => write!(
                formatter,
                "registry message exceeds {MAX_REGISTRY_MESSAGE_BYTES} bytes"
            ),
            Self::Malformed => formatter.write_str("registry message is malformed"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported registry transport version {version}"
                )
            }
            Self::Encoding => formatter.write_str("registry message encoding failed"),
        }
    }
}

impl Error for RegistryProtocolError {}

pub trait RegistryTransport {
    type Error;
    type Exchange<'a>: Future<Output = Result<Vec<u8>, Self::Error>> + Send + 'a
    where
        Self: 'a;

    fn exchange(&mut self, request: Vec<u8>) -> Self::Exchange<'_>;
}

pub struct RegistryClient<T> {
    transport: T,
    pinned_registry_key: [u8; 32],
    next_request_id: u64,
}

impl<T: RegistryTransport> RegistryClient<T> {
    #[must_use]
    pub const fn new(transport: T, pinned_registry_key: [u8; 32]) -> Self {
        Self {
            transport,
            pinned_registry_key,
            next_request_id: 1,
        }
    }

    pub async fn claim(
        &mut self,
        claim: &HandleClaim,
    ) -> Result<RegistryReceipt, RegistryClientError<T::Error>> {
        let outcome = self
            .request(RegistryOperation::Claim {
                claim: Box::new(RegistryClaim::from_claim(claim)),
            })
            .await?;
        match outcome {
            RegistryResponseOutcome::Accepted { receipt } => {
                receipt
                    .verify_for_claim(&self.pinned_registry_key, claim)
                    .map_err(RegistryClientError::InvalidReceipt)?;
                Ok(*receipt)
            }
            RegistryResponseOutcome::Rejected { error } => {
                Err(RegistryClientError::Rejected(error))
            }
            RegistryResponseOutcome::Found { .. } | RegistryResponseOutcome::NotFound => {
                Err(RegistryClientError::UnexpectedOutcome)
            }
        }
    }

    pub async fn lookup_handle(
        &mut self,
        handle: &GlobalHandle,
    ) -> Result<Option<AcceptedRegistryRecord>, RegistryClientError<T::Error>> {
        let outcome = self
            .request(RegistryOperation::LookupHandle {
                handle: handle.clone(),
            })
            .await?;
        self.verify_lookup(outcome, |record| {
            record.receipt.handle.as_global_handle() == handle
        })
    }

    pub async fn lookup_account(
        &mut self,
        account_id: &AccountId,
    ) -> Result<Option<AcceptedRegistryRecord>, RegistryClientError<T::Error>> {
        let outcome = self
            .request(RegistryOperation::LookupAccount {
                account_id: account_id.clone(),
            })
            .await?;
        self.verify_lookup(outcome, |record| record.receipt.account_id == *account_id)
    }

    async fn request(
        &mut self,
        operation: RegistryOperation,
    ) -> Result<RegistryResponseOutcome, RegistryClientError<T::Error>> {
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(RegistryClientError::RequestIdExhausted)?;
        let request = encode_request(&RegistryRequest {
            version: REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation,
        })
        .map_err(RegistryClientError::Protocol)?;
        let encoded_response = self
            .transport
            .exchange(request)
            .await
            .map_err(RegistryClientError::Transport)?;
        let response = decode_response(&encoded_response).map_err(RegistryClientError::Protocol)?;
        if response.request_id != request_id {
            return Err(RegistryClientError::CorrelationMismatch {
                expected: request_id,
                actual: response.request_id,
            });
        }
        Ok(response.outcome)
    }

    fn verify_lookup(
        &self,
        outcome: RegistryResponseOutcome,
        matches_query: impl FnOnce(&AcceptedRegistryRecord) -> bool,
    ) -> Result<Option<AcceptedRegistryRecord>, RegistryClientError<T::Error>> {
        match outcome {
            RegistryResponseOutcome::Found { record } => {
                let record = record
                    .to_record()
                    .map_err(RegistryClientError::InvalidReceipt)?;
                record
                    .verify(&self.pinned_registry_key)
                    .map_err(RegistryClientError::InvalidReceipt)?;
                if !matches_query(&record) {
                    return Err(RegistryClientError::LookupMismatch);
                }
                Ok(Some(record))
            }
            RegistryResponseOutcome::NotFound => Ok(None),
            RegistryResponseOutcome::Rejected { error } => {
                Err(RegistryClientError::Rejected(error))
            }
            RegistryResponseOutcome::Accepted { .. } => Err(RegistryClientError::UnexpectedOutcome),
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[derive(Debug)]
pub enum RegistryClientError<E> {
    Transport(E),
    Protocol(RegistryProtocolError),
    CorrelationMismatch { expected: u64, actual: u64 },
    Rejected(RegistryRemoteError),
    InvalidReceipt(RegistryError),
    LookupMismatch,
    UnexpectedOutcome,
    RequestIdExhausted,
}

impl<E: fmt::Display> fmt::Display for RegistryClientError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "registry transport failed: {error}"),
            Self::Protocol(error) => write!(formatter, "registry protocol failed: {error}"),
            Self::CorrelationMismatch { expected, actual } => write!(
                formatter,
                "registry response ID {actual} does not match request {expected}"
            ),
            Self::Rejected(error) => {
                write!(
                    formatter,
                    "registry rejected claim {:?}: {}",
                    error.code, error.message
                )
            }
            Self::InvalidReceipt(error) => {
                write!(formatter, "registry returned an invalid receipt: {error}")
            }
            Self::LookupMismatch => {
                formatter.write_str("registry lookup result does not match the query")
            }
            Self::UnexpectedOutcome => {
                formatter.write_str("registry returned an unexpected outcome")
            }
            Self::RequestIdExhausted => formatter.write_str("registry request IDs are exhausted"),
        }
    }
}

impl<E: Error + 'static> Error for RegistryClientError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidReceipt(error) => Some(error),
            _ => None,
        }
    }
}

pub struct RegistryService<'store> {
    store: &'store SealedStore,
    state: RegistryState,
    unavailable: bool,
}

impl<'store> RegistryService<'store> {
    pub fn open(
        store: &'store SealedStore,
        registry_signing_seed: [u8; 32],
    ) -> Result<Self, RegistryServiceError> {
        let state = RegistryVault::load_or_create(store, registry_signing_seed)
            .map_err(RegistryServiceError::Persistence)?;
        Ok(Self {
            store,
            state,
            unavailable: false,
        })
    }

    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.state.verifying_key()
    }

    #[must_use]
    pub const fn is_available(&self) -> bool {
        !self.unavailable
    }

    pub fn handle(
        &mut self,
        encoded_request: &[u8],
        accepted_at: u64,
    ) -> Result<Vec<u8>, RegistryServiceError> {
        if self.unavailable {
            return Err(RegistryServiceError::Unavailable);
        }
        let request = decode_request(encoded_request).map_err(RegistryServiceError::Protocol)?;
        let request_id = request.request_id;
        let outcome = match request.operation {
            RegistryOperation::Claim { claim } => match claim.to_claim() {
                Ok(claim) => match self.state.apply(claim, accepted_at) {
                    Ok(receipt) => {
                        if let Err(error) = RegistryVault::persist(self.store, &self.state) {
                            self.unavailable = true;
                            return Err(RegistryServiceError::Persistence(error));
                        }
                        RegistryResponseOutcome::Accepted {
                            receipt: Box::new(receipt),
                        }
                    }
                    Err(error) => RegistryResponseOutcome::Rejected {
                        error: RegistryRemoteError::from_registry(&error),
                    },
                },
                Err(error) => RegistryResponseOutcome::Rejected {
                    error: RegistryRemoteError::from_registry(&error),
                },
            },
            RegistryOperation::LookupHandle { handle } => match self.state.handle_record(&handle) {
                Ok(Some(record)) => RegistryResponseOutcome::Found {
                    record: Box::new(RegistryRecord::from_record(record)),
                },
                Ok(None) => RegistryResponseOutcome::NotFound,
                Err(error) => RegistryResponseOutcome::Rejected {
                    error: RegistryRemoteError::from_registry(&error),
                },
            },
            RegistryOperation::LookupAccount { account_id } => {
                match self.state.account_record(&account_id) {
                    Ok(Some(record)) => RegistryResponseOutcome::Found {
                        record: Box::new(RegistryRecord::from_record(record)),
                    },
                    Ok(None) => RegistryResponseOutcome::NotFound,
                    Err(error) => RegistryResponseOutcome::Rejected {
                        error: RegistryRemoteError::from_registry(&error),
                    },
                }
            }
        };
        encode_response(&RegistryResponse {
            version: REGISTRY_TRANSPORT_VERSION,
            request_id,
            outcome,
        })
        .map_err(RegistryServiceError::Protocol)
    }
}

#[derive(Debug)]
pub enum RegistryServiceError {
    Protocol(RegistryProtocolError),
    Persistence(RegistryVaultError),
    Unavailable,
}

impl fmt::Display for RegistryServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "registry protocol failed: {error}"),
            Self::Persistence(error) => write!(formatter, "registry persistence failed: {error}"),
            Self::Unavailable => formatter.write_str(
                "registry service is unavailable after an uncertain persistence outcome",
            ),
        }
    }
}

impl Error for RegistryServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Persistence(error) => Some(error),
            Self::Unavailable => None,
        }
    }
}
