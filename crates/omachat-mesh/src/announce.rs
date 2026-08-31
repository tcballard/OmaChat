//! Announcement and Noise-authenticated peer-state TLV codecs.

use crate::packet::ID_BYTES;
use std::{collections::HashSet, error::Error, fmt};

const NICKNAME: u8 = 0x01;
const NOISE_KEY: u8 = 0x02;
const SIGNING_KEY: u8 = 0x03;
const NEIGHBORS: u8 = 0x04;
const CAPABILITIES: u8 = 0x05;
const BRIDGE_GEOHASH: u8 = 0x06;
const MAX_NICKNAME_BYTES: usize = 64;
const MAX_NEIGHBORS: usize = 16;
const MAX_ANNOUNCE_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Announcement {
    pub nickname: String,
    pub noise_public_key: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub neighbors: Vec<[u8; ID_BYTES]>,
    pub capabilities: u64,
    pub bridge_geohash: Option<String>,
}

impl Announcement {
    pub fn encode(&self) -> Result<Vec<u8>, AnnounceError> {
        validate(self)?;
        let mut output = Vec::new();
        push_tlv(&mut output, NICKNAME, self.nickname.as_bytes())?;
        push_tlv(&mut output, NOISE_KEY, &self.noise_public_key)?;
        push_tlv(&mut output, SIGNING_KEY, &self.signing_public_key)?;
        if !self.neighbors.is_empty() {
            let values = self.neighbors.iter().flatten().copied().collect::<Vec<_>>();
            push_tlv(&mut output, NEIGHBORS, &values)?;
        }
        let mut capabilities = self.capabilities.to_le_bytes().to_vec();
        while capabilities.len() > 1 && capabilities.last() == Some(&0) {
            capabilities.pop();
        }
        push_tlv(&mut output, CAPABILITIES, &capabilities)?;
        if let Some(geohash) = &self.bridge_geohash {
            push_tlv(&mut output, BRIDGE_GEOHASH, geohash.as_bytes())?;
        }
        if output.len() > MAX_ANNOUNCE_BYTES {
            return Err(AnnounceError::TooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AnnounceError> {
        if bytes.len() > MAX_ANNOUNCE_BYTES {
            return Err(AnnounceError::TooLarge);
        }
        let mut offset = 0;
        let mut seen = HashSet::new();
        let mut nickname = None;
        let mut noise = None;
        let mut signing = None;
        let mut neighbors = Vec::new();
        let mut capabilities = None;
        let mut bridge = None;
        while offset < bytes.len() {
            let kind = *bytes.get(offset).ok_or(AnnounceError::Truncated)?;
            let length = usize::from(*bytes.get(offset + 1).ok_or(AnnounceError::Truncated)?);
            offset += 2;
            let end = offset.checked_add(length).ok_or(AnnounceError::Truncated)?;
            let value = bytes.get(offset..end).ok_or(AnnounceError::Truncated)?;
            offset = end;
            if matches!(
                kind,
                NICKNAME | NOISE_KEY | SIGNING_KEY | NEIGHBORS | CAPABILITIES | BRIDGE_GEOHASH
            ) && !seen.insert(kind)
            {
                return Err(AnnounceError::Duplicate(kind));
            }
            match kind {
                NICKNAME => {
                    nickname =
                        Some(String::from_utf8(value.to_vec()).map_err(|_| AnnounceError::Utf8)?)
                }
                NOISE_KEY => noise = Some(value.try_into().map_err(|_| AnnounceError::KeyLength)?),
                SIGNING_KEY => {
                    signing = Some(value.try_into().map_err(|_| AnnounceError::KeyLength)?)
                }
                NEIGHBORS => {
                    if value.len() % ID_BYTES != 0 || value.len() / ID_BYTES > MAX_NEIGHBORS {
                        return Err(AnnounceError::Neighbors);
                    }
                    neighbors = value.as_chunks::<ID_BYTES>().0.to_vec();
                }
                CAPABILITIES => {
                    if value.is_empty()
                        || value.len() > 8
                        || (value.len() > 1 && value.last() == Some(&0))
                    {
                        return Err(AnnounceError::Capabilities);
                    }
                    let mut little = [0_u8; 8];
                    little[..value.len()].copy_from_slice(value);
                    capabilities = Some(u64::from_le_bytes(little));
                }
                BRIDGE_GEOHASH => {
                    bridge =
                        Some(String::from_utf8(value.to_vec()).map_err(|_| AnnounceError::Utf8)?)
                }
                _ => {}
            }
        }
        let announcement = Self {
            nickname: nickname.ok_or(AnnounceError::Missing(NICKNAME))?,
            noise_public_key: noise.ok_or(AnnounceError::Missing(NOISE_KEY))?,
            signing_public_key: signing.ok_or(AnnounceError::Missing(SIGNING_KEY))?,
            neighbors,
            capabilities: capabilities.ok_or(AnnounceError::Missing(CAPABILITIES))?,
            bridge_geohash: bridge,
        };
        validate(&announcement)?;
        Ok(announcement)
    }
}

/// Only this Noise-encrypted record may promote signing/capability pins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeerState {
    pub noise_public_key: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub capabilities: u64,
}

impl AuthenticatedPeerState {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = b"OAPS\x01".to_vec();
        output.extend_from_slice(&self.noise_public_key);
        output.extend_from_slice(&self.signing_public_key);
        output.extend_from_slice(&self.capabilities.to_le_bytes());
        output
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AnnounceError> {
        if bytes.len() != 77 || &bytes[..5] != b"OAPS\x01" {
            return Err(AnnounceError::AuthenticatedState);
        }
        Ok(Self {
            noise_public_key: bytes[5..37].try_into().expect("fixed noise key"),
            signing_public_key: bytes[37..69].try_into().expect("fixed signing key"),
            capabilities: u64::from_le_bytes(bytes[69..77].try_into().expect("fixed capabilities")),
        })
    }
}

fn push_tlv(output: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), AnnounceError> {
    output.push(kind);
    output.push(u8::try_from(value.len()).map_err(|_| AnnounceError::TooLarge)?);
    output.extend_from_slice(value);
    Ok(())
}

fn validate(value: &Announcement) -> Result<(), AnnounceError> {
    if value.nickname.len() > MAX_NICKNAME_BYTES || value.neighbors.len() > MAX_NEIGHBORS {
        return Err(AnnounceError::TooLarge);
    }
    if let Some(geohash) = &value.bridge_geohash {
        omachat_proto::geohash::Geohash::parse(geohash)
            .map_err(|_| AnnounceError::BridgeGeohash)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnounceError {
    TooLarge,
    Truncated,
    Utf8,
    KeyLength,
    Neighbors,
    Capabilities,
    Duplicate(u8),
    Missing(u8),
    BridgeGeohash,
    AuthenticatedState,
}

impl fmt::Display for AnnounceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid announcement: {self:?}")
    }
}

impl Error for AnnounceError {}
