//! Deterministic presence, flooding, fanout, and fresh bidirectional routes.

use crate::packet::{ID_BYTES, MAX_ROUTE_HOPS, MessageType, Packet, PacketType};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

pub const REACHABILITY_MS: u64 = 60_000;
pub const DEDUP_MS: u64 = 5 * 60_000;
pub const DEDUP_CAPACITY: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPresence {
    pub peer_id: [u8; ID_BYTES],
    pub neighbors: Vec<[u8; ID_BYTES]>,
    pub last_seen_ms: u64,
    pub authenticated: bool,
}

#[derive(Default)]
pub struct PresenceDirectory {
    peers: HashMap<[u8; ID_BYTES], PeerPresence>,
}

impl PresenceDirectory {
    pub fn observe(&mut self, presence: PeerPresence) {
        self.peers.insert(presence.peer_id, presence);
    }

    pub fn leave(&mut self, peer: &[u8; ID_BYTES]) -> bool {
        self.peers.remove(peer).is_some()
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.peers
            .retain(|_, peer| now_ms.saturating_sub(peer.last_seen_ms) < REACHABILITY_MS);
    }

    #[must_use]
    pub fn reachable(&self, now_ms: u64) -> Vec<&PeerPresence> {
        let mut peers = self
            .peers
            .values()
            .filter(|peer| now_ms.saturating_sub(peer.last_seen_ms) < REACHABILITY_MS)
            .collect::<Vec<_>>();
        peers.sort_by_key(|peer| peer.peer_id);
        peers
    }
}

#[must_use]
pub fn announce_delay_ms(reachable_peers: usize, isolated_attempt: u8) -> u64 {
    if reachable_peers == 0 {
        2_000_u64
            .saturating_mul(1_u64 << isolated_attempt.min(4))
            .min(30_000)
    } else {
        30_000
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupResult {
    New,
    Duplicate,
}

#[derive(Default)]
pub struct DedupCache {
    seen: HashMap<[u8; 16], u64>,
    order: VecDeque<([u8; 16], u64)>,
}

impl DedupCache {
    pub fn observe(&mut self, id: [u8; 16], now_ms: u64) -> DedupResult {
        self.expire(now_ms);
        if self.seen.contains_key(&id) {
            return DedupResult::Duplicate;
        }
        while self.order.len() >= DEDUP_CAPACITY {
            if let Some((old, timestamp)) = self.order.pop_front()
                && self.seen.get(&old) == Some(&timestamp)
            {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(id, now_ms);
        self.order.push_back((id, now_ms));
        DedupResult::New
    }

    fn expire(&mut self, now_ms: u64) {
        while self
            .order
            .front()
            .is_some_and(|(_, timestamp)| now_ms.saturating_sub(*timestamp) >= DEDUP_MS)
        {
            let (id, timestamp) = self.order.pop_front().expect("front exists");
            if self.seen.get(&id) == Some(&timestamp) {
                self.seen.remove(&id);
            }
        }
    }
}

#[must_use]
pub fn origin_ttl(reachable_peers: usize) -> u8 {
    match reachable_peers {
        0..=2 => 3,
        3..=7 => 5,
        _ => 7,
    }
}

#[must_use]
pub fn relay_jitter_ms(id: &[u8; 16], directed: bool) -> u64 {
    let digest = Sha256::digest(id);
    let value = u16::from_be_bytes([digest[0], digest[1]]);
    if directed {
        5 + u64::from(value % 21)
    } else {
        20 + u64::from(value % 101)
    }
}

#[must_use]
pub fn should_relay(packet: &Packet) -> bool {
    packet.ttl > 0
        && packet.message_type.relay_safe()
        && packet.message_type != PacketType::Known(MessageType::RequestSync)
}

#[must_use]
pub fn select_fanout(
    message_id: &[u8; 16],
    local_links: &[[u8; 16]],
    ingress: Option<[u8; 16]>,
    full_fanout: bool,
) -> Vec<[u8; 16]> {
    let mut candidates = local_links
        .iter()
        .copied()
        .filter(|link| Some(*link) != ingress)
        .collect::<Vec<_>>();
    candidates.sort_by_key(|link| {
        let mut hasher = Sha256::new();
        hasher.update(message_id);
        hasher.update(b"::");
        hasher.update(link);
        <[u8; 32]>::from(hasher.finalize())
    });
    if full_fanout || candidates.len() <= 2 {
        return candidates;
    }
    let count = candidates.len().div_ceil(2).max(2);
    candidates.truncate(count);
    candidates
}

#[derive(Default)]
pub struct Topology {
    claims: HashMap<[u8; ID_BYTES], (u64, HashSet<[u8; ID_BYTES]>)>,
}

impl Topology {
    pub fn update(
        &mut self,
        peer: [u8; ID_BYTES],
        neighbors: impl IntoIterator<Item = [u8; ID_BYTES]>,
        now_ms: u64,
    ) {
        self.claims
            .insert(peer, (now_ms, neighbors.into_iter().collect()));
    }

    pub fn route(
        &self,
        source: [u8; ID_BYTES],
        destination: [u8; ID_BYTES],
        now_ms: u64,
    ) -> Option<Vec<[u8; ID_BYTES]>> {
        if source == destination {
            return Some(Vec::new());
        }
        let mut queue = VecDeque::from([source]);
        let mut previous = HashMap::new();
        let mut visited = HashSet::from([source]);
        while let Some(current) = queue.pop_front() {
            for neighbor in self.fresh_bidirectional_neighbors(current, now_ms) {
                if !visited.insert(neighbor) {
                    continue;
                }
                previous.insert(neighbor, current);
                if neighbor == destination {
                    let mut route = vec![destination];
                    let mut cursor = destination;
                    while let Some(parent) = previous.get(&cursor).copied() {
                        if parent == source {
                            break;
                        }
                        route.push(parent);
                        cursor = parent;
                    }
                    route.reverse();
                    return (route.len() <= MAX_ROUTE_HOPS).then_some(route);
                }
                queue.push_back(neighbor);
            }
        }
        None
    }

    fn fresh_bidirectional_neighbors(
        &self,
        peer: [u8; ID_BYTES],
        now_ms: u64,
    ) -> Vec<[u8; ID_BYTES]> {
        let Some((seen, neighbors)) = self.claims.get(&peer) else {
            return Vec::new();
        };
        if now_ms.saturating_sub(*seen) >= REACHABILITY_MS {
            return Vec::new();
        }
        let mut valid = neighbors
            .iter()
            .copied()
            .filter(|neighbor| {
                self.claims
                    .get(neighbor)
                    .is_some_and(|(other_seen, other_neighbors)| {
                        now_ms.saturating_sub(*other_seen) < REACHABILITY_MS
                            && other_neighbors.contains(&peer)
                    })
            })
            .collect::<Vec<_>>();
        valid.sort_unstable();
        valid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardPlan {
    SourceRoute([u8; ID_BYTES]),
    Flood,
    DeliverLocal,
    DropLoop,
}

#[must_use]
pub fn forward_source_route(local: [u8; ID_BYTES], route: &[[u8; ID_BYTES]]) -> ForwardPlan {
    if route.is_empty() {
        return ForwardPlan::DeliverLocal;
    }
    if route.iter().filter(|hop| **hop == local).count() > 1 {
        return ForwardPlan::DropLoop;
    }
    match route.iter().position(|hop| *hop == local) {
        Some(index) if index + 1 < route.len() => ForwardPlan::SourceRoute(route[index + 1]),
        Some(_) => ForwardPlan::DeliverLocal,
        None => ForwardPlan::Flood,
    }
}
