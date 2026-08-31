//! Packet IDs, Golomb-coded sets, request TLVs, and RSR response windows.

use crate::packet::{ID_BYTES, Packet};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, error::Error, fmt};

pub const FILTER_P: u8 = 7;
pub const FILTER_MAX_BYTES: usize = 400;
pub const RESPONSE_WINDOW_MS: u64 = 30_000;
pub const MAX_SYNC_RESPONSES: usize = 64;
const MAX_FRAGMENT_IDS: usize = 32;

#[must_use]
pub fn packet_id(packet: &Packet) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update([packet.message_type.byte()]);
    hasher.update(packet.sender);
    hasher.update(packet.timestamp_ms.to_be_bytes());
    hasher.update(&packet.payload);
    hasher.finalize()[..16].try_into().expect("fixed packet ID")
}

#[must_use]
pub fn map_id(id: &[u8; 16], modulus: u64) -> u64 {
    if modulus == 0 {
        return 1;
    }
    let digest = Sha256::digest(id);
    let mut high = u64::from_be_bytes(digest[..8].try_into().expect("fixed map word"));
    high &= i64::MAX as u64;
    let mapped = high % modulus;
    if mapped == 0 { 1 } else { mapped }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcsFilter {
    pub p: u8,
    pub modulus: u64,
    pub bytes: Vec<u8>,
}

impl GcsFilter {
    pub fn build(ids: &[[u8; 16]], p: u8, modulus: u64) -> Result<Self, SyncError> {
        if p > 31 || modulus == 0 {
            return Err(SyncError::Parameters);
        }
        let mut mapped = ids.iter().map(|id| map_id(id, modulus)).collect::<Vec<_>>();
        mapped.sort_unstable();
        mapped.dedup();
        let mut writer = BitWriter::default();
        let mut previous = 0_u64;
        for value in mapped {
            let difference = value.saturating_sub(previous);
            let quotient = difference >> p;
            if quotient > u64::from(FILTER_MAX_BYTES as u32) * 8 {
                return Err(SyncError::FilterTooLarge);
            }
            for _ in 0..quotient {
                writer.push(true)?;
            }
            writer.push(false)?;
            writer.push_value(difference & ((1_u64 << p) - 1), p)?;
            previous = value;
        }
        let bytes = writer.finish();
        if bytes.len() > FILTER_MAX_BYTES {
            return Err(SyncError::FilterTooLarge);
        }
        Ok(Self { p, modulus, bytes })
    }

    pub fn values(&self) -> Result<Vec<u64>, SyncError> {
        if self.p > 31 || self.modulus == 0 || self.bytes.len() > FILTER_MAX_BYTES {
            return Err(SyncError::Parameters);
        }
        let mut reader = BitReader::new(&self.bytes);
        let mut values = Vec::new();
        let mut previous = 0_u64;
        while reader.remaining() > usize::from(self.p) {
            let mut quotient = 0_u64;
            while reader.read()? {
                quotient += 1;
                if quotient > u64::from(FILTER_MAX_BYTES as u32) * 8 {
                    return Err(SyncError::MalformedUnary);
                }
            }
            let remainder = reader.read_value(self.p)?;
            let difference = (quotient << self.p) | remainder;
            if difference == 0 {
                break;
            }
            previous = previous
                .checked_add(difference)
                .ok_or(SyncError::MalformedFilter)?;
            if previous > self.modulus {
                return Err(SyncError::MalformedFilter);
            }
            values.push(previous);
        }
        Ok(values)
    }

    pub fn contains(&self, id: &[u8; 16]) -> Result<bool, SyncError> {
        Ok(self
            .values()?
            .binary_search(&map_id(id, self.modulus))
            .is_ok())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestSync {
    pub p: u8,
    pub modulus: u64,
    pub filter: Vec<u8>,
    pub types: Vec<u8>,
    pub since_ms: u64,
    pub fragment_ids: Vec<[u8; 8]>,
}

impl RequestSync {
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        self.validate()?;
        let mut output = Vec::new();
        push_tlv(&mut output, 1, &[self.p])?;
        push_tlv(&mut output, 2, &self.modulus.to_be_bytes())?;
        push_tlv(&mut output, 3, &self.filter)?;
        push_tlv(&mut output, 4, &self.types)?;
        push_tlv(&mut output, 5, &self.since_ms.to_be_bytes())?;
        let fragments = self
            .fragment_ids
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        if !fragments.is_empty() {
            push_tlv(&mut output, 6, &fragments)?;
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() > 1024 {
            return Err(SyncError::RequestTooLarge);
        }
        let mut fields: [Option<&[u8]>; 6] = [None; 6];
        let mut offset = 0;
        while offset < bytes.len() {
            let kind = usize::from(*bytes.get(offset).ok_or(SyncError::Truncated)?);
            let length = usize::from(u16::from_be_bytes(
                bytes
                    .get(offset + 1..offset + 3)
                    .ok_or(SyncError::Truncated)?
                    .try_into()
                    .expect("fixed TLV length"),
            ));
            offset += 3;
            let end = offset.checked_add(length).ok_or(SyncError::Truncated)?;
            let value = bytes.get(offset..end).ok_or(SyncError::Truncated)?;
            offset = end;
            if (1..=6).contains(&kind) && fields[kind - 1].replace(value).is_some() {
                return Err(SyncError::DuplicateTlv);
            }
        }
        let p = *exact(fields[0], 1)?.first().expect("exact one");
        let modulus = u64::from_be_bytes(exact(fields[1], 8)?.try_into().expect("fixed modulus"));
        let filter = fields[2].ok_or(SyncError::MissingTlv)?.to_vec();
        let types = fields[3].ok_or(SyncError::MissingTlv)?.to_vec();
        let since_ms = u64::from_be_bytes(exact(fields[4], 8)?.try_into().expect("fixed since"));
        let fragment_bytes = fields[5].unwrap_or_default();
        if !fragment_bytes.len().is_multiple_of(8) {
            return Err(SyncError::FragmentIds);
        }
        let fragment_ids = fragment_bytes.as_chunks::<8>().0.to_vec();
        let request = Self {
            p,
            modulus,
            filter,
            types,
            since_ms,
            fragment_ids,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), SyncError> {
        if self.p > 31
            || self.modulus == 0
            || self.filter.len() > FILTER_MAX_BYTES
            || self.types.len() > 32
            || self.fragment_ids.len() > MAX_FRAGMENT_IDS
        {
            return Err(SyncError::Parameters);
        }
        GcsFilter {
            p: self.p,
            modulus: self.modulus,
            bytes: self.filter.clone(),
        }
        .values()?;
        Ok(())
    }
}

fn push_tlv(output: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), SyncError> {
    output.push(kind);
    output.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| SyncError::RequestTooLarge)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn exact(value: Option<&[u8]>, length: usize) -> Result<&[u8], SyncError> {
    value
        .filter(|bytes| bytes.len() == length)
        .ok_or(SyncError::MissingTlv)
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    bits: u8,
}
impl BitWriter {
    fn push(&mut self, value: bool) -> Result<(), SyncError> {
        if self.bytes.len() >= FILTER_MAX_BYTES {
            return Err(SyncError::FilterTooLarge);
        }
        self.current = (self.current << 1) | u8::from(value);
        self.bits += 1;
        if self.bits == 8 {
            self.bytes.push(self.current);
            self.current = 0;
            self.bits = 0;
        }
        Ok(())
    }
    fn push_value(&mut self, value: u64, bits: u8) -> Result<(), SyncError> {
        for shift in (0..bits).rev() {
            self.push((value >> shift) & 1 == 1)?;
        }
        Ok(())
    }
    fn finish(mut self) -> Vec<u8> {
        if self.bits != 0 {
            self.current <<= 8 - self.bits;
            self.bytes.push(self.current);
        }
        self.bytes
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bit: usize,
}
impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() * 8 - self.bit
    }
    fn read(&mut self) -> Result<bool, SyncError> {
        if self.bit >= self.bytes.len() * 8 {
            return Err(SyncError::Truncated);
        }
        let value = self.bytes[self.bit / 8] & (1 << (7 - self.bit % 8)) != 0;
        self.bit += 1;
        Ok(value)
    }
    fn read_value(&mut self, bits: u8) -> Result<u64, SyncError> {
        let mut value = 0;
        for _ in 0..bits {
            value = (value << 1) | u64::from(self.read()?);
        }
        Ok(value)
    }
}

#[derive(Default)]
pub struct ResponseWindows {
    windows: HashMap<([u8; ID_BYTES], [u8; 8]), u64>,
}

impl ResponseWindows {
    pub fn register(&mut self, peer: [u8; ID_BYTES], token: [u8; 8], now_ms: u64) {
        self.windows
            .insert((peer, token), now_ms.saturating_add(RESPONSE_WINDOW_MS));
    }
    pub fn accepts(
        &mut self,
        peer: [u8; ID_BYTES],
        token: [u8; 8],
        ttl: u8,
        is_rsr: bool,
        now_ms: u64,
    ) -> bool {
        self.expire(now_ms);
        ttl == 0 && is_rsr && self.windows.contains_key(&(peer, token))
    }
    pub fn expire(&mut self, now_ms: u64) {
        self.windows.retain(|_, expiry| *expiry > now_ms);
    }
}

/// Select bounded public packets absent from the requester's GCS. Responses
/// are canonical RSR packets: TTL zero and never eligible for reflooding.
pub fn select_missing(request: &RequestSync, archive: &[Packet]) -> Result<Vec<Packet>, SyncError> {
    let filter = GcsFilter {
        p: request.p,
        modulus: request.modulus,
        bytes: request.filter.clone(),
    };
    filter.values()?;
    let mut candidates = archive
        .iter()
        .filter(|packet| {
            packet.timestamp_ms >= request.since_ms
                && request.types.contains(&packet.message_type.byte())
                && !filter.contains(&packet_id(packet)).unwrap_or(false)
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|packet| packet.timestamp_ms);
    Ok(candidates
        .into_iter()
        .take(MAX_SYNC_RESPONSES)
        .map(|packet| {
            let mut response = packet.clone();
            response.ttl = 0;
            response.is_rsr = true;
            response
        })
        .collect())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    Parameters,
    FilterTooLarge,
    MalformedUnary,
    MalformedFilter,
    RequestTooLarge,
    Truncated,
    DuplicateTlv,
    MissingTlv,
    FragmentIds,
}
impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sync codec error: {self:?}")
    }
}
impl Error for SyncError {}
