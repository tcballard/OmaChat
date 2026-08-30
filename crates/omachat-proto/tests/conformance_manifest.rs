#[path = "../../../conformance/loader.rs"]
mod loader;

use loader::{Disclosure, ExpectedProfile, load_artifact, load_manifest, parse_and_validate};
use omachat_proto::{ANDROID_REVISION, COMPATIBILITY_PROFILE, OMARCHY_REVISION, SWIFT_REVISION};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn expected_profile() -> ExpectedProfile<'static> {
    ExpectedProfile {
        id: COMPATIBILITY_PROFILE,
        swift_revision: SWIFT_REVISION,
        android_revision: ANDROID_REVISION,
        omarchy_revision: OMARCHY_REVISION,
    }
}

#[test]
fn harmless_sample_fixture_passes_schema_and_artifact_validation() {
    let manifest = load_manifest(&workspace_root(), expected_profile())
        .expect("the committed conformance manifest must validate");

    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.fixtures.len(), 1);
    let fixture = &manifest.fixtures[0];
    assert_eq!(fixture.id, "schema-smoke-v1");
    assert!(
        fixture
            .artifacts
            .iter()
            .all(|artifact| artifact.disclosure == Disclosure::PublicCommitted)
    );

    let input = load_artifact(&workspace_root(), fixture, "input-text")
        .expect("the sample input must load after validation");
    let output = load_artifact(&workspace_root(), fixture, "output-json")
        .expect("the sample output must load after validation");
    let output: serde_json::Value =
        serde_json::from_slice(&output).expect("the validated output is JSON");
    assert_eq!(
        output["echo"].as_str(),
        std::str::from_utf8(&input).ok().map(str::trim_end)
    );
}

#[test]
fn unknown_schema_fields_are_rejected() {
    let manifest = include_bytes!("../../../conformance/manifest.json");
    let invalid = String::from_utf8(manifest.to_vec())
        .expect("the committed manifest is UTF-8")
        .replacen("{", "{\n  \"unexpected\": true,", 1);

    let error = parse_and_validate(&workspace_root(), invalid.as_bytes(), expected_profile())
        .expect_err("unknown schema fields must fail validation");
    assert!(error.contains("unknown field"), "unexpected error: {error}");
}

#[test]
fn disclosure_schema_distinguishes_test_only_private_material() {
    let manifest = include_bytes!("../../../conformance/manifest.json");
    let private_input = String::from_utf8(manifest.to_vec())
        .expect("the committed manifest is UTF-8")
        .replacen("public-committed", "test-only-private", 1);

    let validated = parse_and_validate(
        &workspace_root(),
        private_input.as_bytes(),
        expected_profile(),
    )
    .expect("synthetic test-only private inputs are a valid disclosure class");
    assert_eq!(
        validated.fixtures[0].artifacts[0].disclosure,
        Disclosure::TestOnlyPrivate
    );
}

#[test]
fn captured_upstream_fixture_requires_source_metadata() {
    let manifest = include_bytes!("../../../conformance/manifest.json");
    let invalid = String::from_utf8(manifest.to_vec())
        .expect("the committed manifest is UTF-8")
        .replacen(
            "\"kind\": \"synthetic\"",
            "\"kind\": \"captured-upstream\"",
            1,
        );

    let error = parse_and_validate(&workspace_root(), invalid.as_bytes(), expected_profile())
        .expect_err("captured upstream fixtures must identify their source");
    assert!(
        error.contains("producer repository is required"),
        "unexpected error: {error}"
    );
}
