//! Bounded mesh/Nostr carrier wire format and loop suppression.

use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    fmt,
};

pub const MAX_CARRIER_BYTES: usize = 16 * 1024;
const DIRECTION: u8 = 0x01;
const GEOHASH: u8 = 0x02;
const EVENT_JSON: u8 = 0x03;
const MESH_ID: u8 = 0x04;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CarrierDirection {
    MeshToNostr = 0,
    NostrToMesh = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NostrCarrier {
    pub direction: CarrierDirection,
    pub geohash: String,
    pub event_json: Vec<u8>,
    pub mesh_id: Option<[u8; 8]>,
}

impl NostrCarrier {
    pub fn encode(&self) -> Result<Vec<u8>, CarrierError> {
        validate_geohash(&self.geohash)?;
        if self.event_json.is_empty() {
            return Err(CarrierError::InvalidEvent);
        }
        let mut output = Vec::new();
        push_tlv(&mut output, DIRECTION, &[self.direction as u8])?;
        push_tlv(&mut output, GEOHASH, self.geohash.as_bytes())?;
        push_tlv(&mut output, EVENT_JSON, &self.event_json)?;
        if let Some(mesh_id) = self.mesh_id {
            push_tlv(&mut output, MESH_ID, &mesh_id)?;
        }
        if output.len() > MAX_CARRIER_BYTES {
            return Err(CarrierError::TooLarge);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CarrierError> {
        if bytes.is_empty() || bytes.len() > MAX_CARRIER_BYTES {
            return Err(CarrierError::TooLarge);
        }
        let mut offset = 0;
        let mut seen = HashSet::new();
        let mut direction = None;
        let mut geohash = None;
        let mut event_json = None;
        let mut mesh_id = None;
        while offset < bytes.len() {
            let kind = *bytes.get(offset).ok_or(CarrierError::Truncated)?;
            let length = u16::from_be_bytes(
                bytes
                    .get(offset + 1..offset + 3)
                    .ok_or(CarrierError::Truncated)?
                    .try_into()
                    .expect("fixed TLV length"),
            ) as usize;
            offset += 3;
            let end = offset.checked_add(length).ok_or(CarrierError::TooLarge)?;
            let value = bytes.get(offset..end).ok_or(CarrierError::Truncated)?;
            offset = end;
            if matches!(kind, DIRECTION | GEOHASH | EVENT_JSON | MESH_ID) && !seen.insert(kind) {
                return Err(CarrierError::Duplicate(kind));
            }
            match kind {
                DIRECTION if value == [0] => direction = Some(CarrierDirection::MeshToNostr),
                DIRECTION if value == [1] => direction = Some(CarrierDirection::NostrToMesh),
                DIRECTION => return Err(CarrierError::Direction),
                GEOHASH => {
                    geohash =
                        Some(String::from_utf8(value.to_vec()).map_err(|_| CarrierError::Geohash)?)
                }
                EVENT_JSON if !value.is_empty() => event_json = Some(value.to_vec()),
                EVENT_JSON => return Err(CarrierError::InvalidEvent),
                MESH_ID => mesh_id = Some(value.try_into().map_err(|_| CarrierError::MeshId)?),
                _ => {}
            }
        }
        let carrier = Self {
            direction: direction.ok_or(CarrierError::Missing(DIRECTION))?,
            geohash: geohash.ok_or(CarrierError::Missing(GEOHASH))?,
            event_json: event_json.ok_or(CarrierError::Missing(EVENT_JSON))?,
            mesh_id,
        };
        validate_geohash(&carrier.geohash)?;
        Ok(carrier)
    }
}

fn push_tlv(output: &mut Vec<u8>, kind: u8, value: &[u8]) -> Result<(), CarrierError> {
    let length = u16::try_from(value.len()).map_err(|_| CarrierError::TooLarge)?;
    output.push(kind);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn validate_geohash(value: &str) -> Result<(), CarrierError> {
    omachat_proto::geohash::Geohash::parse(value)
        .map(|_| ())
        .map_err(|_| CarrierError::Geohash)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BridgeMetrics {
    pub mesh_to_nostr: u64,
    pub nostr_to_mesh: u64,
    pub loop_drops: u64,
    pub malformed_drops: u64,
}

/// One bounded identity set is shared across both directions, so reflected
/// events cannot traverse the bridge a second time.
pub struct BridgeLoopGuard {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
    metrics: BridgeMetrics,
}

impl BridgeLoopGuard {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity,
            metrics: BridgeMetrics::default(),
        }
    }

    pub fn accept(&mut self, identity: &str, direction: CarrierDirection) -> bool {
        if self.capacity == 0 || identity.is_empty() || !self.seen.insert(identity.to_owned()) {
            self.metrics.loop_drops = self.metrics.loop_drops.saturating_add(1);
            return false;
        }
        self.order.push_back(identity.to_owned());
        if self.order.len() > self.capacity
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        match direction {
            CarrierDirection::MeshToNostr => {
                self.metrics.mesh_to_nostr = self.metrics.mesh_to_nostr.saturating_add(1)
            }
            CarrierDirection::NostrToMesh => {
                self.metrics.nostr_to_mesh = self.metrics.nostr_to_mesh.saturating_add(1)
            }
        }
        true
    }

    pub fn record_malformed(&mut self) {
        self.metrics.malformed_drops = self.metrics.malformed_drops.saturating_add(1);
    }

    #[must_use]
    pub fn metrics(&self) -> BridgeMetrics {
        self.metrics
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierError {
    TooLarge,
    Truncated,
    Duplicate(u8),
    Missing(u8),
    Direction,
    Geohash,
    InvalidEvent,
    MeshId,
}
impl fmt::Display for CarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Nostr carrier: {self:?}")
    }
}
impl Error for CarrierError {}
