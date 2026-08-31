//! Strict v1/v2 outer packet codec derived from the pinned Swift wire format.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use std::{error::Error, fmt, io::Read, io::Write};

pub const ID_BYTES: usize = 8;
pub const SIGNATURE_BYTES: usize = 64;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ROUTE_HOPS: usize = 32;
const COMPRESSION_THRESHOLD: usize = 256;
const MAX_COMPRESSION_RATIO: usize = 50_000;
const KNOWN_FLAGS: u8 = 0x1f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    Announce = 0x01,
    Message = 0x02,
    Leave = 0x03,
    CourierEnvelope = 0x04,
    NoiseHandshake = 0x10,
    NoiseEncrypted = 0x11,
    Fragment = 0x20,
    RequestSync = 0x21,
    File = 0x22,
    Board = 0x23,
    PrekeyBundle = 0x24,
    Group = 0x25,
    Ping = 0x26,
    Pong = 0x27,
    NostrCarrier = 0x28,
    Voice = 0x29,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Announce),
            0x02 => Ok(Self::Message),
            0x03 => Ok(Self::Leave),
            0x04 => Ok(Self::CourierEnvelope),
            0x10 => Ok(Self::NoiseHandshake),
            0x11 => Ok(Self::NoiseEncrypted),
            0x20 => Ok(Self::Fragment),
            0x21 => Ok(Self::RequestSync),
            0x22 => Ok(Self::File),
            0x23 => Ok(Self::Board),
            0x24 => Ok(Self::PrekeyBundle),
            0x25 => Ok(Self::Group),
            0x26 => Ok(Self::Ping),
            0x27 => Ok(Self::Pong),
            0x28 => Ok(Self::NostrCarrier),
            0x29 => Ok(Self::Voice),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    Known(MessageType),
    Unknown(u8),
}

impl PacketType {
    #[must_use]
    pub fn byte(self) -> u8 {
        match self {
            Self::Known(value) => value as u8,
            Self::Unknown(value) => value,
        }
    }
    #[must_use]
    pub fn relay_safe(self) -> bool {
        matches!(self, Self::Known(_))
    }
}

impl From<MessageType> for PacketType {
    fn from(value: MessageType) -> Self {
        Self::Known(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub version: u8,
    pub message_type: PacketType,
    pub ttl: u8,
    pub timestamp_ms: u64,
    pub sender: [u8; ID_BYTES],
    pub recipient: Option<[u8; ID_BYTES]>,
    pub route: Vec<[u8; ID_BYTES]>,
    pub payload: Vec<u8>,
    pub signature: Option<[u8; SIGNATURE_BYTES]>,
    pub is_rsr: bool,
}

impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        self.encode_inner(true)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let version = *bytes.first().ok_or(PacketError::Truncated)?;
        let header_bytes = header_size(version)?;
        if bytes.len() < header_bytes + ID_BYTES {
            return Err(PacketError::Truncated);
        }
        let message_type = MessageType::try_from(bytes[1])
            .map(PacketType::Known)
            .unwrap_or(PacketType::Unknown(bytes[1]));
        let ttl = bytes[2];
        let timestamp_ms = u64::from_be_bytes(bytes[3..11].try_into().expect("fixed timestamp"));
        let flags = bytes[11];
        if flags & !KNOWN_FLAGS != 0 || (version == 1 && flags & 0x08 != 0) {
            return Err(PacketError::UnknownFlags(flags));
        }
        let payload_length = if version == 1 {
            usize::from(u16::from_be_bytes(
                bytes[12..14].try_into().expect("fixed v1 length"),
            ))
        } else {
            usize::try_from(u32::from_be_bytes(
                bytes[12..16].try_into().expect("fixed v2 length"),
            ))
            .map_err(|_| PacketError::PayloadTooLarge)?
        };
        if payload_length > MAX_PAYLOAD_BYTES + 4 {
            return Err(PacketError::PayloadTooLarge);
        }
        let mut offset = header_bytes;
        let sender = take_array::<ID_BYTES>(bytes, &mut offset)?;
        let recipient = if flags & 0x01 != 0 {
            Some(take_array::<ID_BYTES>(bytes, &mut offset)?)
        } else {
            None
        };
        let route = if flags & 0x08 != 0 {
            let count = usize::from(*bytes.get(offset).ok_or(PacketError::Truncated)?);
            offset += 1;
            if count > MAX_ROUTE_HOPS {
                return Err(PacketError::RouteTooLong);
            }
            (0..count)
                .map(|_| take_array::<ID_BYTES>(bytes, &mut offset))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let payload_end = offset
            .checked_add(payload_length)
            .ok_or(PacketError::PayloadTooLarge)?;
        let encoded_payload = bytes
            .get(offset..payload_end)
            .ok_or(PacketError::Truncated)?;
        offset = payload_end;
        let payload = if flags & 0x04 != 0 {
            let length_bytes = if version == 1 { 2 } else { 4 };
            if encoded_payload.len() <= length_bytes {
                return Err(PacketError::InvalidCompression);
            }
            let original_size = if version == 1 {
                usize::from(u16::from_be_bytes(
                    encoded_payload[..2].try_into().expect("fixed v1 size"),
                ))
            } else {
                usize::try_from(u32::from_be_bytes(
                    encoded_payload[..4].try_into().expect("fixed v2 size"),
                ))
                .map_err(|_| PacketError::PayloadTooLarge)?
            };
            if original_size > MAX_PAYLOAD_BYTES
                || original_size / encoded_payload[length_bytes..].len().max(1)
                    > MAX_COMPRESSION_RATIO
            {
                return Err(PacketError::PayloadTooLarge);
            }
            decompress_exact(&encoded_payload[length_bytes..], original_size)?
        } else {
            encoded_payload.to_vec()
        };
        let signature = if flags & 0x02 != 0 {
            Some(take_array::<SIGNATURE_BYTES>(bytes, &mut offset)?)
        } else {
            None
        };
        Ok(Self {
            version,
            message_type,
            ttl,
            timestamp_ms,
            sender,
            recipient,
            route,
            payload,
            signature,
            is_rsr: flags & 0x10 != 0,
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, PacketError> {
        let mut canonical = self.clone();
        canonical.ttl = 0;
        canonical.signature = None;
        canonical.is_rsr = false;
        canonical.encode_inner(true)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), PacketError> {
        self.signature = Some(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), PacketError> {
        let signature = self.signature.ok_or(PacketError::MissingSignature)?;
        key.verify(&self.signing_bytes()?, &Signature::from_bytes(&signature))
            .map_err(|_| PacketError::InvalidSignature)
    }

    fn encode_inner(&self, allow_compression: bool) -> Result<Vec<u8>, PacketError> {
        let header_bytes = header_size(self.version)?;
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(PacketError::PayloadTooLarge);
        }
        if self.version == 1 && !self.route.is_empty() {
            return Err(PacketError::RouteRequiresV2);
        }
        if self.route.len() > MAX_ROUTE_HOPS {
            return Err(PacketError::RouteTooLong);
        }
        let compressed = if allow_compression && should_compress(&self.payload) {
            compress_beneficial(&self.payload)?
        } else {
            None
        };
        let mut encoded_payload = Vec::new();
        if let Some(compressed) = &compressed {
            if self.version == 1 {
                encoded_payload.extend_from_slice(
                    &u16::try_from(self.payload.len())
                        .map_err(|_| PacketError::PayloadTooLarge)?
                        .to_be_bytes(),
                );
            } else {
                encoded_payload.extend_from_slice(
                    &u32::try_from(self.payload.len())
                        .map_err(|_| PacketError::PayloadTooLarge)?
                        .to_be_bytes(),
                );
            }
            encoded_payload.extend_from_slice(compressed);
        } else {
            encoded_payload.extend_from_slice(&self.payload);
        }
        let payload_length = encoded_payload.len();
        let flags = u8::from(self.recipient.is_some())
            | (u8::from(self.signature.is_some()) << 1)
            | (u8::from(compressed.is_some()) << 2)
            | (u8::from(!self.route.is_empty()) << 3)
            | (u8::from(self.is_rsr) << 4);
        let mut output = Vec::with_capacity(
            header_bytes
                + ID_BYTES
                + self.route.len() * ID_BYTES
                + payload_length
                + SIGNATURE_BYTES,
        );
        output.extend_from_slice(&[self.version, self.message_type.byte(), self.ttl]);
        output.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        output.push(flags);
        if self.version == 1 {
            output.extend_from_slice(
                &u16::try_from(payload_length)
                    .map_err(|_| PacketError::PayloadTooLarge)?
                    .to_be_bytes(),
            );
        } else {
            output.extend_from_slice(
                &u32::try_from(payload_length)
                    .map_err(|_| PacketError::PayloadTooLarge)?
                    .to_be_bytes(),
            );
        }
        output.extend_from_slice(&self.sender);
        if let Some(recipient) = self.recipient {
            output.extend_from_slice(&recipient);
        }
        if !self.route.is_empty() {
            output.push(u8::try_from(self.route.len()).expect("route cap fits u8"));
            for hop in &self.route {
                output.extend_from_slice(hop);
            }
        }
        output.extend_from_slice(&encoded_payload);
        if let Some(signature) = self.signature {
            output.extend_from_slice(&signature);
        }
        Ok(output)
    }
}

fn header_size(version: u8) -> Result<usize, PacketError> {
    match version {
        1 => Ok(14),
        2 => Ok(16),
        value => Err(PacketError::UnsupportedVersion(value)),
    }
}

fn take_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], PacketError> {
    let end = offset.checked_add(N).ok_or(PacketError::Truncated)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(PacketError::Truncated)?
        .try_into()
        .expect("fixed checked slice");
    *offset = end;
    Ok(value)
}

fn should_compress(payload: &[u8]) -> bool {
    if payload.len() < COMPRESSION_THRESHOLD {
        return false;
    }
    let mut seen = [false; 256];
    for byte in payload {
        seen[usize::from(*byte)] = true;
    }
    let unique = seen.into_iter().filter(|value| *value).count();
    unique * 10 < payload.len().min(256) * 9
}

fn compress_beneficial(payload: &[u8]) -> Result<Option<Vec<u8>>, PacketError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .map_err(PacketError::Compression)?;
    let compressed = encoder.finish().map_err(PacketError::Compression)?;
    Ok((compressed.len() < payload.len()).then_some(compressed))
}

fn decompress_exact(compressed: &[u8], expected: usize) -> Result<Vec<u8>, PacketError> {
    let mut output = Vec::with_capacity(expected.min(MAX_PAYLOAD_BYTES));
    ZlibDecoder::new(compressed)
        .take(
            u64::try_from(expected)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut output)
        .map_err(PacketError::Compression)?;
    if output.len() != expected {
        return Err(PacketError::InvalidCompression);
    }
    Ok(output)
}

#[derive(Debug)]
pub enum PacketError {
    Truncated,
    UnsupportedVersion(u8),
    UnknownFlags(u8),
    PayloadTooLarge,
    RouteRequiresV2,
    RouteTooLong,
    InvalidCompression,
    Compression(std::io::Error),
    MissingSignature,
    InvalidSignature,
}

impl fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("mesh packet is truncated"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported mesh version {version}")
            }
            Self::UnknownFlags(flags) => {
                write!(formatter, "mesh packet has unknown flags 0x{flags:02x}")
            }
            Self::PayloadTooLarge => formatter.write_str("mesh payload exceeds its resource limit"),
            Self::RouteRequiresV2 => formatter.write_str("source routes require packet version 2"),
            Self::RouteTooLong => formatter.write_str("source route exceeds its hop limit"),
            Self::InvalidCompression => formatter.write_str("compressed mesh payload is invalid"),
            Self::Compression(error) => write!(formatter, "mesh compression failed: {error}"),
            Self::MissingSignature => formatter.write_str("mesh packet has no signature"),
            Self::InvalidSignature => formatter.write_str("mesh packet signature is invalid"),
        }
    }
}

impl Error for PacketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Compression(error) => Some(error),
            _ => None,
        }
    }
}
