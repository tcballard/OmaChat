//! Pinned, cross-client geohash relay selection policy.

use crate::relay::RelayHealth;
use omachat_proto::geohash::Geohash;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, error::Error, fmt};
use url::Url;

pub const COMPATIBILITY_PROFILE_ID: &str = "bitchat-swift-v1.7.1";
pub const SWIFT_SNAPSHOT_SHA256: &str =
    "811523100064820b024714eaf3bbe0a9ba99a3c257e453e01bc1bc0f3bf8401a";
pub const ANDROID_SNAPSHOT_SHA256: &str =
    "1cb6f457f790ecf45bd4285769168f289066426fa8152f01f3ecdccabaa91aa5";
pub const RELAYS_PER_SNAPSHOT: usize = 5;
pub const MAXIMUM_GEO_RELAYS: usize = 10;

const SWIFT_SNAPSHOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/georelays/snapshots/811523100064820b024714eaf3bbe0a9ba99a3c257e453e01bc1bc0f3bf8401a/online_relays_gps.csv"
));
const ANDROID_SNAPSHOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/georelays/snapshots/1cb6f457f790ecf45bd4285769168f289066426fa8152f01f3ecdccabaa91aa5/nostr_relays.csv"
));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeoRelayOverrideMode {
    /// User relays take priority and the pinned set fills the remaining bound.
    Supplement,
    /// Only user relays are selected. The pinned set remains reported but unused.
    Replace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoRelayOverrides {
    pub mode: GeoRelayOverrideMode,
    pub urls: Vec<String>,
}

impl Default for GeoRelayOverrides {
    fn default() -> Self {
        Self {
            mode: GeoRelayOverrideMode::Supplement,
            urls: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GeoRelaySource {
    UserOverride,
    SwiftSnapshot,
    AndroidSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedGeoRelay {
    pub url: String,
    pub sources: Vec<GeoRelaySource>,
    pub observed_health: Option<RelayHealth>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoRelaySelectionStatus {
    pub compatibility_profile: &'static str,
    pub swift_snapshot_sha256: &'static str,
    pub android_snapshot_sha256: &'static str,
    pub geohash: String,
    pub override_mode: GeoRelayOverrideMode,
    pub selected: Vec<SelectedGeoRelay>,
    pub skipped_unhealthy: Vec<String>,
}

impl GeoRelaySelectionStatus {
    #[must_use]
    pub fn urls(&self) -> Vec<&str> {
        self.selected
            .iter()
            .map(|relay| relay.url.as_str())
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct GeoRelaySelector {
    swift: Vec<RelayEntry>,
    android: Vec<RelayEntry>,
}

impl GeoRelaySelector {
    /// Load and authenticate both release-pinned relay directories embedded in
    /// the binary. No runtime directory fetch is performed.
    pub fn pinned() -> Result<Self, GeoRelayError> {
        Ok(Self {
            swift: parse_snapshot(SWIFT_SNAPSHOT, SWIFT_SNAPSHOT_SHA256, 441)?,
            android: parse_snapshot(ANDROID_SNAPSHOT, ANDROID_SNAPSHOT_SHA256, 413)?,
        })
    }

    /// Select a bounded relay set. Unknown and connecting relays remain
    /// candidates; only relays observed as disconnected or stopped are skipped,
    /// allowing the next-nearest entry in that snapshot to take its place.
    pub fn select(
        &self,
        geohash: &Geohash,
        overrides: &GeoRelayOverrides,
        health: &HashMap<String, RelayHealth>,
    ) -> Result<GeoRelaySelectionStatus, GeoRelayError> {
        let center = geohash.center();
        let normalized_health = health
            .iter()
            .map(|(url, state)| Ok((normalize_endpoint(url)?, *state)))
            .collect::<Result<HashMap<_, _>, GeoRelayError>>()?;
        let mut skipped_unhealthy = Vec::new();
        let mut compatibility = Vec::new();

        for (source, entries, swift_ties) in [
            (GeoRelaySource::SwiftSnapshot, self.swift.as_slice(), true),
            (
                GeoRelaySource::AndroidSnapshot,
                self.android.as_slice(),
                false,
            ),
        ] {
            for url in nearest_healthy(
                entries,
                center.latitude,
                center.longitude,
                RELAYS_PER_SNAPSHOT,
                swift_ties,
                &normalized_health,
                &mut skipped_unhealthy,
            ) {
                push_candidate(&mut compatibility, url, source);
            }
        }

        let mut overrides_normalized = Vec::new();
        for value in &overrides.urls {
            let url = normalize_endpoint(value)?;
            if is_unhealthy(normalized_health.get(&url).copied()) {
                push_unique(&mut skipped_unhealthy, url);
            } else {
                push_candidate(&mut overrides_normalized, url, GeoRelaySource::UserOverride);
            }
        }

        let compatibility = if overrides.mode == GeoRelayOverrideMode::Supplement {
            compatibility
        } else {
            Vec::new()
        };
        let mut selected: Vec<Candidate> = Vec::new();
        for relay in overrides_normalized.into_iter().chain(compatibility) {
            if let Some(existing) = selected
                .iter_mut()
                .find(|candidate| candidate.url == relay.url)
            {
                for source in relay.sources {
                    if !existing.sources.contains(&source) {
                        existing.sources.push(source);
                    }
                }
            } else if selected.len() < MAXIMUM_GEO_RELAYS {
                selected.push(relay);
            }
        }

        Ok(GeoRelaySelectionStatus {
            compatibility_profile: COMPATIBILITY_PROFILE_ID,
            swift_snapshot_sha256: SWIFT_SNAPSHOT_SHA256,
            android_snapshot_sha256: ANDROID_SNAPSHOT_SHA256,
            geohash: geohash.as_str().to_owned(),
            override_mode: overrides.mode,
            selected: selected
                .into_iter()
                .map(|relay| SelectedGeoRelay {
                    observed_health: normalized_health.get(&relay.url).copied(),
                    url: relay.url,
                    sources: relay.sources,
                })
                .collect(),
            skipped_unhealthy,
        })
    }
}

#[derive(Clone, Debug)]
struct RelayEntry {
    url: String,
    latitude: f64,
    longitude: f64,
}

#[derive(Clone, Debug)]
struct Candidate {
    url: String,
    sources: Vec<GeoRelaySource>,
}

fn parse_snapshot(
    bytes: &[u8],
    expected_sha256: &'static str,
    expected_entries: usize,
) -> Result<Vec<RelayEntry>, GeoRelayError> {
    let actual_sha256 = hex::encode(Sha256::digest(bytes));
    if actual_sha256 != expected_sha256 {
        return Err(GeoRelayError::SnapshotHash {
            expected: expected_sha256,
            actual: actual_sha256,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| GeoRelayError::SnapshotUtf8)?;
    let mut lines = text.lines();
    if lines.next() != Some("Relay URL,Latitude,Longitude") {
        return Err(GeoRelayError::SnapshotHeader);
    }
    let mut entries = Vec::new();
    for (index, line) in lines.filter(|line| !line.trim().is_empty()).enumerate() {
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(GeoRelayError::SnapshotRow(index + 2));
        }
        let latitude = fields[1]
            .parse::<f64>()
            .map_err(|_| GeoRelayError::SnapshotRow(index + 2))?;
        let longitude = fields[2]
            .parse::<f64>()
            .map_err(|_| GeoRelayError::SnapshotRow(index + 2))?;
        if !latitude.is_finite()
            || !longitude.is_finite()
            || !(-90.0..=90.0).contains(&latitude)
            || !(-180.0..=180.0).contains(&longitude)
        {
            return Err(GeoRelayError::SnapshotRow(index + 2));
        }
        entries.push(RelayEntry {
            url: normalize_endpoint(fields[0])?,
            latitude,
            longitude,
        });
    }
    if entries.len() != expected_entries {
        return Err(GeoRelayError::SnapshotCount {
            expected: expected_entries,
            actual: entries.len(),
        });
    }
    Ok(entries)
}

fn nearest_healthy(
    entries: &[RelayEntry],
    latitude: f64,
    longitude: f64,
    count: usize,
    swift_ties: bool,
    health: &HashMap<String, RelayHealth>,
    skipped: &mut Vec<String>,
) -> Vec<String> {
    let mut ranked = entries
        .iter()
        .map(|relay| (distance(latitude, longitude, relay), relay))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let ordering = left.0.total_cmp(&right.0);
        if swift_ties && ordering.is_eq() {
            left.1.url.cmp(&right.1.url)
        } else {
            ordering
        }
    });
    let mut selected = Vec::new();
    for (_, relay) in ranked {
        if is_unhealthy(health.get(&relay.url).copied()) {
            push_unique(skipped, relay.url.clone());
        } else {
            selected.push(relay.url.clone());
            if selected.len() == count {
                break;
            }
        }
    }
    selected
}

fn distance(latitude: f64, longitude: f64, relay: &RelayEntry) -> f64 {
    let delta_latitude = (relay.latitude - latitude).to_radians();
    let delta_longitude = (relay.longitude - longitude).to_radians();
    let a = (delta_latitude / 2.0).sin().powi(2)
        + latitude.to_radians().cos()
            * relay.latitude.to_radians().cos()
            * (delta_longitude / 2.0).sin().powi(2);
    6_371.0 * 2.0 * a.sqrt().atan2((1.0 - a).sqrt())
}

fn normalize_endpoint(value: &str) -> Result<String, GeoRelayError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(GeoRelayError::RelayUrl(value.to_owned()));
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("wss://{trimmed}")
    };
    let parsed = Url::parse(&candidate).map_err(|_| GeoRelayError::RelayUrl(value.to_owned()))?;
    if !matches!(parsed.scheme(), "ws" | "wss")
        || parsed.host_str().is_none()
        || parsed.port_or_known_default().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(GeoRelayError::RelayUrl(value.to_owned()));
    }
    let scheme_end = candidate
        .find("://")
        .expect("candidate always contains a scheme");
    let rest = &candidate[scheme_end + 3..];
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = rest[..authority_end].to_ascii_lowercase();
    let path = &rest[authority_end..];
    let path = if path == "/" { "" } else { path };
    Ok(format!("{}://{authority}{path}", parsed.scheme()))
}

fn is_unhealthy(health: Option<RelayHealth>) -> bool {
    matches!(
        health,
        Some(RelayHealth::Disconnected | RelayHealth::Stopped)
    )
}

fn push_candidate(candidates: &mut Vec<Candidate>, url: String, source: GeoRelaySource) {
    if let Some(existing) = candidates.iter_mut().find(|candidate| candidate.url == url) {
        if !existing.sources.contains(&source) {
            existing.sources.push(source);
        }
    } else {
        candidates.push(Candidate {
            url,
            sources: vec![source],
        });
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeoRelayError {
    SnapshotHash {
        expected: &'static str,
        actual: String,
    },
    SnapshotUtf8,
    SnapshotHeader,
    SnapshotRow(usize),
    SnapshotCount {
        expected: usize,
        actual: usize,
    },
    RelayUrl(String),
}

impl fmt::Display for GeoRelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotHash { expected, actual } => {
                write!(
                    formatter,
                    "relay snapshot hash {actual} does not match {expected}"
                )
            }
            Self::SnapshotUtf8 => formatter.write_str("relay snapshot is not UTF-8"),
            Self::SnapshotHeader => formatter.write_str("relay snapshot header is invalid"),
            Self::SnapshotRow(line) => write!(formatter, "relay snapshot row {line} is invalid"),
            Self::SnapshotCount { expected, actual } => write!(
                formatter,
                "relay snapshot contains {actual} entries; expected {expected}"
            ),
            Self::RelayUrl(url) => write!(formatter, "invalid relay WebSocket URL: {url}"),
        }
    }
}

impl Error for GeoRelayError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_tie_breaks_stay_distinct() {
        let entries = vec![
            RelayEntry {
                url: "wss://tie-z.example".into(),
                latitude: 0.0,
                longitude: 1.0,
            },
            RelayEntry {
                url: "wss://tie-a.example".into(),
                latitude: 0.0,
                longitude: -1.0,
            },
            RelayEntry {
                url: "wss://near.example".into(),
                latitude: 0.1,
                longitude: 0.0,
            },
        ];
        let mut skipped = Vec::new();
        let swift = nearest_healthy(&entries, 0.0, 0.0, 3, true, &HashMap::new(), &mut skipped);
        let android = nearest_healthy(&entries, 0.0, 0.0, 3, false, &HashMap::new(), &mut skipped);
        assert_eq!(
            swift,
            [
                "wss://near.example",
                "wss://tie-a.example",
                "wss://tie-z.example"
            ]
        );
        assert_eq!(
            android,
            [
                "wss://near.example",
                "wss://tie-z.example",
                "wss://tie-a.example"
            ]
        );
    }

    #[test]
    fn endpoint_normalization_preserves_explicit_default_ports() {
        assert_eq!(
            normalize_endpoint("NOSTR.EXAMPLE:443/").unwrap(),
            "wss://nostr.example:443"
        );
        assert_eq!(
            normalize_endpoint("wss://nostr.example").unwrap(),
            "wss://nostr.example"
        );
    }
}
