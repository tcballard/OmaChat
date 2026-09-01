//! Strict transport codec for proof-bearing registry operations.
//!
//! This protocol is separately versioned from the deployed v2 root-claim
//! protocol. Defining its bytes does not make the legacy registry host accept
//! principal proofs; host and persistence integration remain explicit later
//! boundaries.

use crate::{MAX_REGISTRY_MESSAGE_BYTES, RegistryClaim};
use omachat_crypto::AccountId;
use omachat_registry::{
    RegistryReceipt, principal_proof::NostrPrincipalControlProof,
    principal_receipt::PrincipalProofReceipt, principal_registry::PrincipalRegistryRecord,
    proof_bearing_claim::ProofBearingDeviceHandleClaim,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{error::Error, fmt};

pub const PRINCIPAL_REGISTRY_TRANSPORT_VERSION: u16 = 1;
pub const MAX_PRINCIPAL_REGISTRY_MESSAGE_BYTES: usize = MAX_REGISTRY_MESSAGE_BYTES;
const PRINCIPAL_CLAIM_WIRE_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistryClaim {
    pub version: u16,
    pub root_claim: RegistryClaim,
    pub principal_proof: Vec<u8>,
}

impl PrincipalRegistryClaim {
    #[must_use]
    pub fn from_claim(claim: &ProofBearingDeviceHandleClaim) -> Self {
        Self {
            version: PRINCIPAL_CLAIM_WIRE_VERSION,
            root_claim: RegistryClaim::from_claim(claim.claim()),
            principal_proof: claim.principal_proof().to_bytes(),
        }
    }

    pub fn to_claim(
        &self,
    ) -> Result<ProofBearingDeviceHandleClaim, PrincipalRegistryProtocolError> {
        if self.version != PRINCIPAL_CLAIM_WIRE_VERSION {
            return Err(PrincipalRegistryProtocolError::UnsupportedClaimVersion(
                self.version,
            ));
        }
        let root_claim = self
            .root_claim
            .to_claim()
            .map_err(|_| PrincipalRegistryProtocolError::InvalidClaim)?;
        let principal_proof = NostrPrincipalControlProof::from_bytes(&self.principal_proof)
            .map_err(|_| PrincipalRegistryProtocolError::InvalidClaim)?;
        ProofBearingDeviceHandleClaim::new(root_claim, principal_proof)
            .map_err(|_| PrincipalRegistryProtocolError::InvalidClaim)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistryRequest {
    pub version: u16,
    pub request_id: u64,
    pub operation: PrincipalRegistryOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrincipalRegistryOperation {
    ClaimDevice { claim: Box<PrincipalRegistryClaim> },
    LookupPublicKey { nostr_public_key: [u8; 32] },
    LookupAccount { account_id: AccountId },
}

impl PrincipalRegistryRequest {
    #[must_use]
    pub fn claim_device(request_id: u64, claim: &ProofBearingDeviceHandleClaim) -> Self {
        Self {
            version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation: PrincipalRegistryOperation::ClaimDevice {
                claim: Box::new(PrincipalRegistryClaim::from_claim(claim)),
            },
        }
    }

    #[must_use]
    pub const fn lookup_public_key(request_id: u64, nostr_public_key: [u8; 32]) -> Self {
        Self {
            version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation: PrincipalRegistryOperation::LookupPublicKey { nostr_public_key },
        }
    }

    #[must_use]
    pub const fn lookup_account(request_id: u64, account_id: AccountId) -> Self {
        Self {
            version: PRINCIPAL_REGISTRY_TRANSPORT_VERSION,
            request_id,
            operation: PrincipalRegistryOperation::LookupAccount { account_id },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistryRecordWire {
    pub claim: PrincipalRegistryClaim,
    pub claim_receipt: Box<RegistryReceipt>,
    pub principal_receipt: Vec<u8>,
}

impl PrincipalRegistryRecordWire {
    #[must_use]
    pub fn from_record(record: &PrincipalRegistryRecord) -> Self {
        Self {
            claim: PrincipalRegistryClaim {
                version: PRINCIPAL_CLAIM_WIRE_VERSION,
                root_claim: RegistryClaim::from_claim(record.claim()),
                principal_proof: record.principal_proof().to_bytes(),
            },
            claim_receipt: Box::new(record.claim_receipt().clone()),
            principal_receipt: record.principal_receipt().to_bytes(),
        }
    }

    pub fn verify(
        &self,
        pinned_registry_key: &[u8; 32],
    ) -> Result<VerifiedPrincipalRegistryRecord, PrincipalRegistryProtocolError> {
        let claim = self.claim.to_claim()?;
        self.claim_receipt
            .verify_for_claim(pinned_registry_key, claim.claim())
            .map_err(|_| PrincipalRegistryProtocolError::InvalidEvidence)?;
        let principal_receipt = PrincipalProofReceipt::from_bytes_for_claim_receipt(
            &self.principal_receipt,
            &self.claim_receipt,
            pinned_registry_key,
        )
        .map_err(|_| PrincipalRegistryProtocolError::InvalidEvidence)?;
        principal_receipt
            .verify_for(pinned_registry_key, &claim, &self.claim_receipt)
            .map_err(|_| PrincipalRegistryProtocolError::InvalidEvidence)?;
        Ok(VerifiedPrincipalRegistryRecord {
            claim,
            claim_receipt: (*self.claim_receipt).clone(),
            principal_receipt,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPrincipalRegistryRecord {
    claim: ProofBearingDeviceHandleClaim,
    claim_receipt: RegistryReceipt,
    principal_receipt: PrincipalProofReceipt,
}

impl VerifiedPrincipalRegistryRecord {
    #[must_use]
    pub const fn claim(&self) -> &ProofBearingDeviceHandleClaim {
        &self.claim
    }

    #[must_use]
    pub const fn claim_receipt(&self) -> &RegistryReceipt {
        &self.claim_receipt
    }

    #[must_use]
    pub const fn principal_receipt(&self) -> &PrincipalProofReceipt {
        &self.principal_receipt
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistryResponse {
    pub version: u16,
    pub request_id: u64,
    pub outcome: PrincipalRegistryResponseOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrincipalRegistryResponseOutcome {
    Accepted {
        record: Box<PrincipalRegistryRecordWire>,
    },
    Found {
        record: Box<PrincipalRegistryRecordWire>,
    },
    NotFound,
    Rejected {
        error: PrincipalRegistryRemoteError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRegistryRemoteError {
    pub code: PrincipalRegistryRemoteCode,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalRegistryRemoteCode {
    InvalidClaim,
    StaleRevision,
    CommandConflict,
    HandleTaken,
    PublicKeyTaken,
    PolicyDeferred,
    Exhausted,
    InvalidState,
}

pub fn encode_principal_request(
    request: &PrincipalRegistryRequest,
) -> Result<Vec<u8>, PrincipalRegistryProtocolError> {
    encode_bounded(request)
}

pub fn decode_principal_request(
    bytes: &[u8],
) -> Result<PrincipalRegistryRequest, PrincipalRegistryProtocolError> {
    let request: PrincipalRegistryRequest = decode_bounded(bytes)?;
    if request.version != PRINCIPAL_REGISTRY_TRANSPORT_VERSION {
        return Err(PrincipalRegistryProtocolError::UnsupportedVersion(
            request.version,
        ));
    }
    if let PrincipalRegistryOperation::ClaimDevice { claim } = &request.operation {
        claim.to_claim()?;
    }
    Ok(request)
}

pub fn encode_principal_response(
    response: &PrincipalRegistryResponse,
) -> Result<Vec<u8>, PrincipalRegistryProtocolError> {
    encode_bounded(response)
}

pub fn decode_principal_response(
    bytes: &[u8],
) -> Result<PrincipalRegistryResponse, PrincipalRegistryProtocolError> {
    let response: PrincipalRegistryResponse = decode_bounded(bytes)?;
    if response.version != PRINCIPAL_REGISTRY_TRANSPORT_VERSION {
        return Err(PrincipalRegistryProtocolError::UnsupportedVersion(
            response.version,
        ));
    }
    Ok(response)
}

fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, PrincipalRegistryProtocolError> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| PrincipalRegistryProtocolError::Encoding)?;
    if encoded.len() > MAX_PRINCIPAL_REGISTRY_MESSAGE_BYTES {
        return Err(PrincipalRegistryProtocolError::MessageTooLarge);
    }
    Ok(encoded)
}

fn decode_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, PrincipalRegistryProtocolError> {
    if bytes.len() > MAX_PRINCIPAL_REGISTRY_MESSAGE_BYTES {
        return Err(PrincipalRegistryProtocolError::MessageTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| PrincipalRegistryProtocolError::Malformed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalRegistryProtocolError {
    MessageTooLarge,
    Malformed,
    UnsupportedVersion(u16),
    UnsupportedClaimVersion(u16),
    InvalidClaim,
    InvalidEvidence,
    Encoding,
}

impl fmt::Display for PrincipalRegistryProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge => write!(
                formatter,
                "principal registry message exceeds {MAX_PRINCIPAL_REGISTRY_MESSAGE_BYTES} bytes"
            ),
            Self::Malformed => formatter.write_str("principal registry message is malformed"),
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported principal registry transport version {version}"
            ),
            Self::UnsupportedClaimVersion(version) => {
                write!(
                    formatter,
                    "unsupported principal registry claim version {version}"
                )
            }
            Self::InvalidClaim => formatter.write_str("principal registry claim is invalid"),
            Self::InvalidEvidence => {
                formatter.write_str("principal registry receipt evidence is invalid")
            }
            Self::Encoding => formatter.write_str("principal registry message encoding failed"),
        }
    }
}

impl Error for PrincipalRegistryProtocolError {}
