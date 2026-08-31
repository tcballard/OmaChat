//! Dynamic fragmentation and globally bounded reassembly.

use crate::packet::ID_BYTES;
use std::{collections::HashMap, error::Error, fmt};

pub const FRAGMENT_HEADER_BYTES: usize = 13;
pub const MAX_ASSEMBLY_BYTES: usize = 1024 * 1024;
pub const MAX_ASSEMBLIES: usize = 128;
pub const GLOBAL_MEMORY_BYTES: usize = 8 * 1024 * 1024;
pub const EXPIRY_MILLISECONDS: u64 = 30_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub id: [u8; 8],
    pub index: u16,
    pub total: u16,
    pub original_type: u8,
    pub data: Vec<u8>,
}

impl Fragment {
    pub fn encode(&self) -> Result<Vec<u8>, FragmentError> {
        if self.total == 0 || self.index >= self.total || self.data.is_empty() {
            return Err(FragmentError::Invalid);
        }
        let mut output = Vec::with_capacity(FRAGMENT_HEADER_BYTES + self.data.len());
        output.extend_from_slice(&self.id);
        output.extend_from_slice(&self.index.to_be_bytes());
        output.extend_from_slice(&self.total.to_be_bytes());
        output.push(self.original_type);
        output.extend_from_slice(&self.data);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FragmentError> {
        if bytes.len() <= FRAGMENT_HEADER_BYTES {
            return Err(FragmentError::Truncated);
        }
        let fragment = Self {
            id: bytes[..8].try_into().expect("fixed fragment id"),
            index: u16::from_be_bytes(bytes[8..10].try_into().expect("fixed index")),
            total: u16::from_be_bytes(bytes[10..12].try_into().expect("fixed total")),
            original_type: bytes[12],
            data: bytes[13..].to_vec(),
        };
        if fragment.total == 0 || fragment.index >= fragment.total {
            return Err(FragmentError::Invalid);
        }
        Ok(fragment)
    }
}

pub fn plan(
    id: [u8; 8],
    original_type: u8,
    payload: &[u8],
    link_budget: usize,
) -> Result<Vec<Fragment>, FragmentError> {
    let chunk = link_budget
        .checked_sub(FRAGMENT_HEADER_BYTES)
        .filter(|value| *value > 0)
        .ok_or(FragmentError::LinkBudget)?;
    if payload.is_empty() || payload.len() > MAX_ASSEMBLY_BYTES {
        return Err(FragmentError::TooLarge);
    }
    let total = payload.len().div_ceil(chunk);
    let total = u16::try_from(total).map_err(|_| FragmentError::TooLarge)?;
    Ok(payload
        .chunks(chunk)
        .enumerate()
        .map(|(index, data)| Fragment {
            id,
            index: u16::try_from(index).expect("total fits u16"),
            total,
            original_type,
            data: data.to_vec(),
        })
        .collect())
}

struct Assembly {
    created_at: u64,
    original_type: u8,
    total: u16,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Reassembled {
    pub original_type: u8,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct ReassemblyManager {
    assemblies: HashMap<([u8; ID_BYTES], [u8; 8]), Assembly>,
    memory_bytes: usize,
}

impl ReassemblyManager {
    pub fn insert(
        &mut self,
        sender: [u8; ID_BYTES],
        fragment: Fragment,
        now_ms: u64,
    ) -> Result<Option<Reassembled>, FragmentError> {
        self.expire(now_ms);
        let key = (sender, fragment.id);
        if !self.assemblies.contains_key(&key) {
            if self.assemblies.len() >= MAX_ASSEMBLIES {
                return Err(FragmentError::AssemblyLimit);
            }
            self.assemblies.insert(
                key,
                Assembly {
                    created_at: now_ms,
                    original_type: fragment.original_type,
                    total: fragment.total,
                    parts: (0..fragment.total).map(|_| None).collect(),
                    bytes: 0,
                },
            );
        }
        let assembly = self.assemblies.get_mut(&key).expect("assembly inserted");
        if assembly.total != fragment.total || assembly.original_type != fragment.original_type {
            self.remove(&key);
            return Err(FragmentError::Conflict);
        }
        let slot = &mut assembly.parts[usize::from(fragment.index)];
        if let Some(existing) = slot {
            if existing == &fragment.data {
                return Ok(None);
            }
            self.remove(&key);
            return Err(FragmentError::Conflict);
        }
        if assembly.bytes.saturating_add(fragment.data.len()) > MAX_ASSEMBLY_BYTES
            || self.memory_bytes.saturating_add(fragment.data.len()) > GLOBAL_MEMORY_BYTES
        {
            self.remove(&key);
            return Err(FragmentError::TooLarge);
        }
        assembly.bytes += fragment.data.len();
        self.memory_bytes += fragment.data.len();
        *slot = Some(fragment.data);
        if assembly.parts.iter().all(Option::is_some) {
            let assembly = self.assemblies.remove(&key).expect("complete assembly");
            self.memory_bytes -= assembly.bytes;
            let payload = assembly.parts.into_iter().flatten().flatten().collect();
            return Ok(Some(Reassembled {
                original_type: assembly.original_type,
                payload,
            }));
        }
        Ok(None)
    }

    pub fn expire(&mut self, now_ms: u64) {
        let expired = self
            .assemblies
            .iter()
            .filter(|(_, assembly)| {
                now_ms.saturating_sub(assembly.created_at) >= EXPIRY_MILLISECONDS
            })
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in expired {
            self.remove(&key);
        }
    }

    fn remove(&mut self, key: &([u8; ID_BYTES], [u8; 8])) {
        if let Some(assembly) = self.assemblies.remove(key) {
            self.memory_bytes -= assembly.bytes;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentError {
    Truncated,
    Invalid,
    LinkBudget,
    TooLarge,
    AssemblyLimit,
    Conflict,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fragment error: {self:?}")
    }
}
impl Error for FragmentError {}
