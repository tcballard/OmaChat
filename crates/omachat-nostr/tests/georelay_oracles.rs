use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, path::PathBuf};

const GEOHASH_ALPHABET: &str = "0123456789bcdefghjkmnpqrstuvwxyz";

#[derive(Deserialize)]
struct Manifest {
    schema_version: u32,
    policy: Policy,
    snapshots: Vec<Snapshot>,
}

#[derive(Deserialize)]
struct Policy {
    selection_per_snapshot: usize,
    maximum_simultaneous_geo_relays: usize,
    combination: String,
    runtime_directory_updates: bool,
    review_cadence: String,
}

#[derive(Deserialize)]
struct Snapshot {
    implementation: String,
    release: String,
    commit: String,
    source_path: String,
    artifact_path: String,
    bytes: u64,
    sha256: String,
    entries: usize,
    selection_oracle: String,
}

#[derive(Deserialize)]
struct Cases {
    schema_version: u32,
    geohash_cases: Vec<GeohashCase>,
    tie_cases: Vec<TieCase>,
}

#[derive(Deserialize)]
struct GeohashCase {
    id: String,
    geohash: String,
    expected_swift: Vec<String>,
    expected_android: Vec<String>,
    expected_omachat: Vec<String>,
}

#[derive(Deserialize)]
struct TieCase {
    id: String,
    latitude: f64,
    longitude: f64,
    count: usize,
    entries: Vec<Relay>,
    expected_swift: Vec<String>,
    expected_android: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct Relay {
    endpoint: String,
    latitude: f64,
    longitude: f64,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate must be in workspace/crates")
        .to_owned()
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &str) -> T {
    let bytes = fs::read(workspace_root().join(path)).expect("JSON fixture must exist");
    serde_json::from_slice(&bytes).expect("JSON fixture must parse")
}

fn load_snapshot(snapshot: &Snapshot) -> Vec<Relay> {
    let bytes = fs::read(workspace_root().join(&snapshot.artifact_path))
        .expect("relay snapshot must exist");
    assert_eq!(bytes.len() as u64, snapshot.bytes);
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(digest, snapshot.sha256);
    let text = String::from_utf8(bytes).expect("snapshot must be UTF-8");
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("Relay URL,Latitude,Longitude"));
    let relays = lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<_> = line.split(',').map(str::trim).collect();
            assert_eq!(fields.len(), 3);
            Relay {
                endpoint: fields[0].to_owned(),
                latitude: fields[1].parse().expect("numeric latitude"),
                longitude: fields[2].parse().expect("numeric longitude"),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(relays.len(), snapshot.entries);
    relays
}

fn geohash_center(geohash: &str) -> (f64, f64) {
    let mut latitude = [-90.0, 90.0];
    let mut longitude = [-180.0, 180.0];
    let mut even = true;
    for character in geohash.chars() {
        let value = GEOHASH_ALPHABET
            .find(character.to_ascii_lowercase())
            .expect("valid geohash character");
        for mask in [16, 8, 4, 2, 1] {
            let range = if even { &mut longitude } else { &mut latitude };
            let midpoint = (range[0] + range[1]) / 2.0;
            if value & mask == 0 {
                range[1] = midpoint;
            } else {
                range[0] = midpoint;
            }
            even = !even;
        }
    }
    (
        (latitude[0] + latitude[1]) / 2.0,
        (longitude[0] + longitude[1]) / 2.0,
    )
}

fn distance(latitude: f64, longitude: f64, relay: &Relay) -> f64 {
    let delta_latitude = (relay.latitude - latitude).to_radians();
    let delta_longitude = (relay.longitude - longitude).to_radians();
    let a = (delta_latitude / 2.0).sin().powi(2)
        + latitude.to_radians().cos()
            * relay.latitude.to_radians().cos()
            * (delta_longitude / 2.0).sin().powi(2);
    6_371.0 * 2.0 * a.sqrt().atan2((1.0 - a).sqrt())
}

fn endpoint(value: &str) -> String {
    if value.contains("://") {
        value.to_owned()
    } else {
        format!("wss://{value}")
    }
}

fn swift_nearest(relays: &[Relay], latitude: f64, longitude: f64, count: usize) -> Vec<String> {
    let mut ranked: Vec<_> = relays
        .iter()
        .map(|relay| (distance(latitude, longitude, relay), relay))
        .collect();
    ranked.sort_by(|left, right| {
        left.0
            .total_cmp(&right.0)
            .then_with(|| left.1.endpoint.cmp(&right.1.endpoint))
    });
    ranked
        .into_iter()
        .take(count)
        .map(|(_, relay)| endpoint(&relay.endpoint))
        .collect()
}

fn android_nearest(relays: &[Relay], latitude: f64, longitude: f64, count: usize) -> Vec<String> {
    let mut ranked: Vec<_> = relays
        .iter()
        .map(|relay| (distance(latitude, longitude, relay), relay))
        .collect();
    ranked.sort_by(|left, right| left.0.total_cmp(&right.0));
    ranked
        .into_iter()
        .take(count)
        .map(|(_, relay)| endpoint(&relay.endpoint))
        .collect()
}

fn bounded_union(swift: &[String], android: &[String], maximum: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    swift
        .iter()
        .chain(android)
        .filter(|value| seen.insert(value.as_str()))
        .take(maximum)
        .cloned()
        .collect()
}

#[test]
fn pinned_snapshots_and_nearest_five_outputs_do_not_drift() {
    let manifest: Manifest = load_json("conformance/georelays/manifest.json");
    let cases: Cases = load_json("conformance/georelays/cases.json");
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(cases.schema_version, 1);
    assert_eq!(manifest.policy.selection_per_snapshot, 5);
    assert_eq!(manifest.policy.maximum_simultaneous_geo_relays, 10);
    assert_eq!(manifest.policy.combination, "swift-first-bounded-union");
    assert!(!manifest.policy.runtime_directory_updates);
    assert_eq!(
        manifest.policy.review_cadence,
        "monthly-and-on-upstream-security-release"
    );
    let swift = manifest
        .snapshots
        .iter()
        .find(|snapshot| snapshot.implementation == "swift")
        .expect("Swift snapshot");
    let android = manifest
        .snapshots
        .iter()
        .find(|snapshot| snapshot.implementation == "android")
        .expect("Android snapshot");
    assert_eq!(swift.release, "v1.7.1");
    assert_eq!(swift.commit, "9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa");
    assert_eq!(swift.source_path, "relays/online_relays_gps.csv");
    assert_eq!(
        swift.selection_oracle,
        "haversine distance ascending, then relay host ascending"
    );
    assert_eq!(android.release, "v2.0.1");
    assert_eq!(android.commit, "93e9594bad3e537b4ec6fd096c0fde7533f22e74");
    assert_eq!(android.source_path, "app/src/main/assets/nostr_relays.csv");
    assert_eq!(
        android.selection_oracle,
        "haversine distance ascending with stable input-order ties"
    );
    let swift_relays = load_snapshot(swift);
    let android_relays = load_snapshot(android);
    assert!(cases.geohash_cases.len() >= 2);
    for case in cases.geohash_cases {
        let (latitude, longitude) = geohash_center(&case.geohash);
        let selected_swift = swift_nearest(&swift_relays, latitude, longitude, 5);
        let selected_android = android_nearest(&android_relays, latitude, longitude, 5);
        assert_eq!(selected_swift, case.expected_swift, "{} Swift", case.id);
        assert_eq!(
            selected_android, case.expected_android,
            "{} Android",
            case.id
        );
        assert_eq!(
            bounded_union(&selected_swift, &selected_android, 10),
            case.expected_omachat,
            "{} union",
            case.id
        );
    }
}

#[test]
fn released_tie_break_behaviors_are_recorded() {
    let cases: Cases = load_json("conformance/georelays/cases.json");
    assert!(!cases.tie_cases.is_empty());
    for case in cases.tie_cases {
        assert_eq!(
            swift_nearest(&case.entries, case.latitude, case.longitude, case.count),
            case.expected_swift,
            "{} Swift tie",
            case.id
        );
        assert_eq!(
            android_nearest(&case.entries, case.latitude, case.longitude, case.count),
            case.expected_android,
            "{} Android tie",
            case.id
        );
    }
}
