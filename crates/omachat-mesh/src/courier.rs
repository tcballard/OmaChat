//! Courier day tags, strict TLV envelopes, Noise-X seals, and one-time prekeys.

use crate::noise::{NoiseError, open_x, seal_x};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

const TAG_CONTEXT: &[u8] = b"bitchat-courier-tag-v1";
const STATIC_PROLOGUE: &[u8] = b"bitchat-courier-v1";
const PREKEY_PROLOGUE: &[u8] = b"bitchat-prekey-v1";
pub const MAX_COURIER_CIPHERTEXT: usize = 16 * 1024;
pub const MAX_COPIES: u8 = 8;
pub const PREKEY_GRACE_MS: u64 = 48 * 60 * 60 * 1_000;

#[must_use]
pub fn day_tag(recipient_static_public: &[u8; 32], epoch_day: u32) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(recipient_static_public).expect("HMAC key");
    mac.update(TAG_CONTEXT);
    mac.update(&epoch_day.to_be_bytes());
    mac.finalize().into_bytes()[..16]
        .try_into()
        .expect("fixed day tag")
}

#[must_use]
pub fn candidate_day_tags(recipient_static_public: &[u8; 32], epoch_day: u32) -> [[u8; 16]; 3] {
    [
        day_tag(recipient_static_public, epoch_day.saturating_sub(1)),
        day_tag(recipient_static_public, epoch_day),
        day_tag(recipient_static_public, epoch_day.saturating_add(1)),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CourierEnvelope {
    pub recipient_tag: [u8; 16],
    pub expiry_ms: u64,
    pub ciphertext: Vec<u8>,
    pub copies: u8,
    pub prekey_id: Option<u32>,
}

impl CourierEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, CourierError> {
        self.validate()?;
        let mut output = Vec::new();
        push_tlv(&mut output, 1, &self.recipient_tag)?;
        push_tlv(&mut output, 2, &self.expiry_ms.to_be_bytes())?;
        push_tlv(&mut output, 3, &self.ciphertext)?;
        if self.copies != 1 {
            push_tlv(&mut output, 4, &[self.copies])?;
        }
        if let Some(prekey_id) = self.prekey_id {
            push_tlv(&mut output, 5, &prekey_id.to_be_bytes())?;
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CourierError> {
        if bytes.len() > MAX_COURIER_CIPHERTEXT + 64 {
            return Err(CourierError::TooLarge);
        }
        let mut values: [Option<&[u8]>; 5] = [None; 5];
        let mut offset = 0;
        while offset < bytes.len() {
            if bytes.len() - offset < 3 {
                return Err(CourierError::Truncated);
            }
            let kind = usize::from(bytes[offset]);
            let length = usize::from(u16::from_be_bytes(
                bytes[offset + 1..offset + 3].try_into().expect("fixed TLV"),
            ));
            offset += 3;
            let end = offset.checked_add(length).ok_or(CourierError::Truncated)?;
            let value = bytes.get(offset..end).ok_or(CourierError::Truncated)?;
            offset = end;
            if (1..=5).contains(&kind) && values[kind - 1].replace(value).is_some() {
                return Err(CourierError::DuplicateTlv);
            }
        }
        let envelope = Self {
            recipient_tag: exact(values[0], 16)?.try_into().expect("fixed tag"),
            expiry_ms: u64::from_be_bytes(exact(values[1], 8)?.try_into().expect("fixed expiry")),
            ciphertext: values[2].ok_or(CourierError::MissingTlv)?.to_vec(),
            copies: values[3].map_or(Ok(1), |value| exact(Some(value), 1).map(|v| v[0]))?,
            prekey_id: values[4]
                .map(|value| {
                    exact(Some(value), 4)
                        .map(|v| u32::from_be_bytes(v.try_into().expect("fixed prekey")))
                })
                .transpose()?,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<(), CourierError> {
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_COURIER_CIPHERTEXT {
            return Err(CourierError::TooLarge);
        }
        if self.copies == 0 || self.copies > MAX_COPIES {
            return Err(CourierError::Copies);
        }
        if self.prekey_id.is_none() && self.copies != 1 {
            return Err(CourierError::Copies);
        }
        Ok(())
    }
}

pub struct SealCourier<'a> {
    pub sender_static_secret: &'a [u8; 32],
    pub recipient_identity_public: &'a [u8; 32],
    pub recipient_seal_public: &'a [u8; 32],
    pub ephemeral_secret: &'a [u8; 32],
    pub epoch_day: u32,
    pub expiry_ms: u64,
    pub prekey_id: Option<u32>,
    pub copies: u8,
}

pub fn seal(input: &SealCourier<'_>, payload: &[u8]) -> Result<CourierEnvelope, CourierError> {
    let prologue = prologue(input.prekey_id);
    Ok(CourierEnvelope {
        recipient_tag: day_tag(input.recipient_identity_public, input.epoch_day),
        expiry_ms: input.expiry_ms,
        ciphertext: seal_x(
            input.sender_static_secret,
            input.recipient_seal_public,
            input.ephemeral_secret,
            &prologue,
            payload,
        )?,
        copies: input.copies,
        prekey_id: input.prekey_id,
    })
}

pub fn open(
    envelope: &CourierEnvelope,
    recipient_secret: &[u8; 32],
    now_ms: u64,
) -> Result<(Vec<u8>, [u8; 32]), CourierError> {
    if now_ms > envelope.expiry_ms {
        return Err(CourierError::Expired);
    }
    Ok(open_x(
        recipient_secret,
        &prologue(envelope.prekey_id),
        &envelope.ciphertext,
    )?)
}

fn prologue(prekey_id: Option<u32>) -> Vec<u8> {
    if let Some(id) = prekey_id {
        let mut value = PREKEY_PROLOGUE.to_vec();
        value.extend_from_slice(&id.to_be_bytes());
        value
    } else {
        STATIC_PROLOGUE.to_vec()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPrekey {
    pub id: u32,
    pub public_key: [u8; 32],
    pub created_at_ms: u64,
    pub signature: [u8; 64],
}

impl SignedPrekey {
    pub fn create(id: u32, secret: &[u8; 32], created_at_ms: u64, signing: &SigningKey) -> Self {
        let public_key = x25519(*secret, X25519_BASEPOINT_BYTES);
        let signature = signing
            .sign(&prekey_signing_bytes(id, &public_key, created_at_ms))
            .to_bytes();
        Self {
            id,
            public_key,
            created_at_ms,
            signature,
        }
    }
    pub fn verify(
        &self,
        key: &VerifyingKey,
        now_ms: u64,
        maximum_age_ms: u64,
    ) -> Result<(), CourierError> {
        if now_ms.saturating_sub(self.created_at_ms) > maximum_age_ms {
            return Err(CourierError::Expired);
        }
        key.verify(
            &prekey_signing_bytes(self.id, &self.public_key, self.created_at_ms),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| CourierError::Signature)
    }
}

fn prekey_signing_bytes(id: u32, public: &[u8; 32], created: u64) -> Vec<u8> {
    let mut bytes = b"bitchat-prekey-bundle-v1".to_vec();
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(public);
    bytes.extend_from_slice(&created.to_be_bytes());
    bytes
}

struct LocalPrekey {
    secret: Zeroizing<[u8; 32]>,
    consumed_at_ms: Option<u64>,
}
#[derive(Default)]
pub struct LocalPrekeys {
    keys: HashMap<u32, LocalPrekey>,
}

impl LocalPrekeys {
    pub fn insert(&mut self, id: u32, secret: [u8; 32]) -> Result<(), CourierError> {
        if self.keys.contains_key(&id) {
            return Err(CourierError::DuplicatePrekey);
        }
        self.keys.insert(
            id,
            LocalPrekey {
                secret: Zeroizing::new(secret),
                consumed_at_ms: None,
            },
        );
        Ok(())
    }
    pub fn open(
        &mut self,
        envelope: &CourierEnvelope,
        now_ms: u64,
    ) -> Result<(Vec<u8>, [u8; 32], bool), CourierError> {
        let id = envelope.prekey_id.ok_or(CourierError::MissingPrekey)?;
        let key = self.keys.get_mut(&id).ok_or(CourierError::MissingPrekey)?;
        if key
            .consumed_at_ms
            .is_some_and(|consumed| now_ms.saturating_sub(consumed) > PREKEY_GRACE_MS)
        {
            self.keys.remove(&id);
            return Err(CourierError::MissingPrekey);
        }
        let first = key.consumed_at_ms.is_none();
        let opened = open(envelope, &key.secret, now_ms)?;
        if first {
            key.consumed_at_ms = Some(now_ms);
        }
        Ok((opened.0, opened.1, first))
    }
    pub fn purge(&mut self, now_ms: u64) {
        self.keys.retain(|_, key| {
            !key.consumed_at_ms
                .is_some_and(|at| now_ms.saturating_sub(at) > PREKEY_GRACE_MS)
        });
    }
}

#[derive(Default)]
pub struct CourierDedup {
    ids: HashSet<[u8; 16]>,
}
impl CourierDedup {
    pub fn accept(&mut self, id: [u8; 16]) -> bool {
        self.ids.insert(id)
    }
}

fn push_tlv(output: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), CourierError> {
    output.push(kind);
    output.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| CourierError::TooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}
fn exact(value: Option<&[u8]>, length: usize) -> Result<&[u8], CourierError> {
    value
        .filter(|v| v.len() == length)
        .ok_or(CourierError::MissingTlv)
}

#[derive(Debug)]
pub enum CourierError {
    Noise(NoiseError),
    TooLarge,
    Truncated,
    DuplicateTlv,
    MissingTlv,
    Copies,
    Expired,
    Signature,
    DuplicatePrekey,
    MissingPrekey,
}
impl From<NoiseError> for CourierError {
    fn from(value: NoiseError) -> Self {
        Self::Noise(value)
    }
}
impl fmt::Display for CourierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "courier error: {self:?}")
    }
}
impl Error for CourierError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Noise(e) => Some(e),
            _ => None,
        }
    }
}
