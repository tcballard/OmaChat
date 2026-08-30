#[path = "../../../conformance/loader.rs"]
mod loader;

use loader::{
    ArtifactRole, Disclosure, ExpectedProfile, ProducerKind, load_artifact, load_manifest,
    parse_and_validate,
};
use omachat_proto::{ANDROID_REVISION, COMPATIBILITY_PROFILE, OMARCHY_REVISION, SWIFT_REVISION};
use std::{
    fs,
    path::{Path, PathBuf},
};

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
    let fixture = manifest
        .fixtures
        .iter()
        .find(|fixture| fixture.id == "schema-smoke-v1")
        .expect("the harmless sample fixture must remain in the manifest");
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
fn release_critical_crypto_vectors_have_upstream_provenance() {
    const FIXTURE_IDS: [&str; 10] = [
        "android-nostr-supported-shapes-v1",
        "swift-courier-day-tags-v1",
        "swift-courier-prekey-v2",
        "swift-courier-static-v1",
        "swift-geohash-identity-v1",
        "swift-nip13-policy-v1",
        "swift-noise-xx-transcript-v1",
        "swift-nostr-private-envelope-android-shape-v1",
        "swift-nostr-private-envelope-key-schedule-v1",
        "swift-nostr-private-envelope-tagless-v1",
    ];

    let manifest = load_manifest(&workspace_root(), expected_profile())
        .expect("the committed conformance manifest must validate");
    let mut captured_ids = manifest
        .fixtures
        .iter()
        .filter(|fixture| fixture.id != "schema-smoke-v1")
        .map(|fixture| fixture.id.as_str())
        .collect::<Vec<_>>();
    captured_ids.sort_unstable();
    assert_eq!(captured_ids, FIXTURE_IDS);

    let mut saw_public = false;
    let mut saw_test_only_private = false;
    for fixture_id in FIXTURE_IDS {
        let fixture = manifest
            .fixtures
            .iter()
            .find(|fixture| fixture.id == fixture_id)
            .expect("every release-critical fixture must be present");
        assert_eq!(fixture.producer.kind, ProducerKind::CapturedUpstream);

        let (repository, release, commit) = if fixture_id.starts_with("swift-") {
            (
                "https://github.com/permissionlesstech/bitchat",
                "v1.7.1",
                SWIFT_REVISION,
            )
        } else {
            (
                "https://github.com/permissionlesstech/bitchat-android",
                "v2.0.1",
                ANDROID_REVISION,
            )
        };
        assert_eq!(fixture.producer.repository.as_deref(), Some(repository));
        assert_eq!(fixture.producer.release.as_deref(), Some(release));
        assert_eq!(fixture.producer.commit.as_deref(), Some(commit));

        assert!(
            fixture
                .artifacts
                .iter()
                .any(|artifact| artifact.role == ArtifactRole::Input)
        );
        assert!(
            fixture
                .artifacts
                .iter()
                .any(|artifact| artifact.role == ArtifactRole::Output)
        );
        if fixture_id.starts_with("swift-") {
            assert!(
                fixture
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.role == ArtifactRole::Intermediate)
            );
        }

        for artifact in &fixture.artifacts {
            load_artifact(&workspace_root(), fixture, &artifact.id)
                .expect("every captured artifact must load after validation");
            saw_public |= artifact.disclosure == Disclosure::PublicCommitted;
            saw_test_only_private |= artifact.disclosure == Disclosure::TestOnlyPrivate;
        }

        let fixture_directory = workspace_root()
            .join("conformance/fixtures")
            .join(fixture_id);
        let mut files_on_disk = fs::read_dir(&fixture_directory)
            .expect("the captured fixture directory must exist")
            .map(|entry| {
                entry
                    .expect("fixture directory entries must be readable")
                    .file_name()
                    .into_string()
                    .expect("fixture artifact names must be UTF-8")
            })
            .collect::<Vec<_>>();
        files_on_disk.sort_unstable();
        let mut declared_files = fixture
            .artifacts
            .iter()
            .map(|artifact| {
                Path::new(&artifact.path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("manifest artifact paths must end in a UTF-8 file name")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        declared_files.sort_unstable();
        assert_eq!(
            files_on_disk, declared_files,
            "fixture {fixture_id} must not contain unmanifested files"
        );
    }

    assert!(
        saw_public,
        "captured public wire evidence must be classified"
    );
    assert!(
        saw_test_only_private,
        "synthetic test-only private material must be classified"
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
