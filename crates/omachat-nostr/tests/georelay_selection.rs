use omachat_nostr::{
    georelay::{
        ANDROID_SNAPSHOT_SHA256, COMPATIBILITY_PROFILE_ID, GeoRelayOverrideMode, GeoRelayOverrides,
        GeoRelaySelector, SWIFT_SNAPSHOT_SHA256,
    },
    relay::RelayHealth,
};
use omachat_proto::geohash::Geohash;
use serde::Deserialize;
use std::{collections::HashMap, fs, path::PathBuf};

#[derive(Deserialize)]
struct Cases {
    geohash_cases: Vec<GeohashCase>,
}

#[derive(Deserialize)]
struct GeohashCase {
    geohash: String,
    expected_omachat: Vec<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate must be in workspace/crates")
        .to_owned()
}

#[test]
fn production_selector_matches_every_frozen_cell() {
    let cases: Cases = serde_json::from_slice(
        &fs::read(workspace_root().join("conformance/georelays/cases.json")).unwrap(),
    )
    .unwrap();
    let selector = GeoRelaySelector::pinned().unwrap();
    for case in cases.geohash_cases {
        let geohash = Geohash::parse(&case.geohash).unwrap();
        let status = selector
            .select(&geohash, &GeoRelayOverrides::default(), &HashMap::new())
            .unwrap();
        assert_eq!(status.urls(), case.expected_omachat);
        assert_eq!(status.compatibility_profile, COMPATIBILITY_PROFILE_ID);
        assert_eq!(status.swift_snapshot_sha256, SWIFT_SNAPSHOT_SHA256);
        assert_eq!(status.android_snapshot_sha256, ANDROID_SNAPSHOT_SHA256);
    }
}

#[test]
fn health_fallback_uses_the_next_nearest_relays() {
    let selector = GeoRelaySelector::pinned().unwrap();
    let geohash = Geohash::parse("gcpvj").unwrap();
    let initial = selector
        .select(&geohash, &GeoRelayOverrides::default(), &HashMap::new())
        .unwrap();
    let unhealthy = initial.selected[0].url.clone();
    let health = HashMap::from([(unhealthy.clone(), RelayHealth::Disconnected)]);
    let fallback = selector
        .select(&geohash, &GeoRelayOverrides::default(), &health)
        .unwrap();

    assert!(!fallback.urls().contains(&unhealthy.as_str()));
    assert!(fallback.skipped_unhealthy.contains(&unhealthy));
    assert_eq!(fallback.selected.len(), initial.selected.len());
}

#[test]
fn overrides_have_explicit_bounded_supplement_and_replace_semantics() {
    let selector = GeoRelaySelector::pinned().unwrap();
    let geohash = Geohash::parse("r3gx2").unwrap();
    let overrides = GeoRelayOverrides {
        mode: GeoRelayOverrideMode::Supplement,
        urls: vec![
            "WSS://CUSTOM.EXAMPLE/".into(),
            "wss://custom.example".into(),
        ],
    };
    let supplemented = selector
        .select(&geohash, &overrides, &HashMap::new())
        .unwrap();
    assert_eq!(supplemented.urls()[0], "wss://custom.example");
    assert!(supplemented.selected.len() <= 10);

    let replaced = selector
        .select(
            &geohash,
            &GeoRelayOverrides {
                mode: GeoRelayOverrideMode::Replace,
                urls: vec!["custom.example".into()],
            },
            &HashMap::new(),
        )
        .unwrap();
    assert_eq!(replaced.urls(), ["wss://custom.example"]);
}
