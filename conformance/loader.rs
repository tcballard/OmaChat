//! Test-only loader for versioned conformance manifests.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Component, Path},
};

const SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub compatibility_profile: CompatibilityProfile,
    pub fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityProfile {
    pub id: String,
    pub swift_revision: String,
    pub android_revision: String,
    pub omarchy_revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub id: String,
    pub protocol_area: String,
    pub description: String,
    pub producer: Producer,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Producer {
    pub kind: ProducerKind,
    pub implementation: String,
    pub repository: Option<String>,
    pub release: Option<String>,
    pub commit: Option<String>,
    pub captured_at_utc: String,
    pub build: BuildMetadata,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProducerKind {
    Synthetic,
    CapturedUpstream,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildMetadata {
    pub toolchain: String,
    pub host: String,
    pub target: String,
    pub configuration: String,
    pub command: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub id: String,
    pub role: ArtifactRole,
    pub disclosure: Disclosure,
    pub encoding: Encoding,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRole {
    Input,
    Intermediate,
    Output,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Disclosure {
    PublicCommitted,
    TestOnlyPrivate,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    #[serde(rename = "utf-8")]
    Utf8,
    Json,
    Binary,
}

#[derive(Clone, Copy)]
pub struct ExpectedProfile<'a> {
    pub id: &'a str,
    pub swift_revision: &'a str,
    pub android_revision: &'a str,
    pub omarchy_revision: &'a str,
}

pub fn load_manifest(
    workspace_root: &Path,
    expected_profile: ExpectedProfile<'_>,
) -> Result<Manifest, String> {
    let manifest_path = workspace_root.join("conformance/manifest.json");
    let bytes = fs::read(&manifest_path)
        .map_err(|error| format!("failed to read {}: {error}", manifest_path.display()))?;
    parse_and_validate(workspace_root, &bytes, expected_profile)
}

pub fn parse_and_validate(
    workspace_root: &Path,
    manifest_bytes: &[u8],
    expected_profile: ExpectedProfile<'_>,
) -> Result<Manifest, String> {
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("manifest schema error: {error}"))?;
    validate_manifest(workspace_root, &manifest, expected_profile)?;
    Ok(manifest)
}

pub fn load_artifact(
    workspace_root: &Path,
    fixture: &Fixture,
    artifact_id: &str,
) -> Result<Vec<u8>, String> {
    let artifact = fixture
        .artifacts
        .iter()
        .find(|artifact| artifact.id == artifact_id)
        .ok_or_else(|| {
            format!(
                "fixture {} does not contain artifact {artifact_id}",
                fixture.id
            )
        })?;
    validate_artifact(workspace_root, fixture, artifact)?;

    let artifact_path = workspace_root.join("conformance").join(&artifact.path);
    fs::read(&artifact_path)
        .map_err(|error| format!("failed to read {}: {error}", artifact_path.display()))
}

fn validate_manifest(
    workspace_root: &Path,
    manifest: &Manifest,
    expected_profile: ExpectedProfile<'_>,
) -> Result<(), String> {
    if manifest.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema version {}; expected {SUPPORTED_SCHEMA_VERSION}",
            manifest.schema_version
        ));
    }

    validate_profile(&manifest.compatibility_profile, expected_profile)?;

    if manifest.fixtures.is_empty() {
        return Err("manifest must contain at least one fixture".to_owned());
    }

    let mut fixture_ids = HashSet::new();
    for fixture in &manifest.fixtures {
        validate_identifier("fixture", &fixture.id)?;
        if !fixture_ids.insert(fixture.id.as_str()) {
            return Err(format!("duplicate fixture id {}", fixture.id));
        }
        validate_fixture(workspace_root, fixture)?;
    }

    Ok(())
}

fn validate_profile(
    profile: &CompatibilityProfile,
    expected: ExpectedProfile<'_>,
) -> Result<(), String> {
    let actual = [
        ("id", profile.id.as_str(), expected.id),
        (
            "swift_revision",
            profile.swift_revision.as_str(),
            expected.swift_revision,
        ),
        (
            "android_revision",
            profile.android_revision.as_str(),
            expected.android_revision,
        ),
        (
            "omarchy_revision",
            profile.omarchy_revision.as_str(),
            expected.omarchy_revision,
        ),
    ];

    for (name, value, expected_value) in actual {
        if value != expected_value {
            return Err(format!(
                "compatibility profile {name} is {value}; expected {expected_value}"
            ));
        }
    }
    Ok(())
}

fn validate_fixture(workspace_root: &Path, fixture: &Fixture) -> Result<(), String> {
    require_nonempty("protocol_area", &fixture.protocol_area)?;
    require_nonempty("description", &fixture.description)?;
    validate_producer(&fixture.producer)?;

    if fixture.artifacts.is_empty() {
        return Err(format!("fixture {} has no artifacts", fixture.id));
    }

    let mut artifact_ids = HashSet::new();
    let mut artifact_paths = HashSet::new();
    let mut has_input = false;
    let mut has_output = false;
    for artifact in &fixture.artifacts {
        validate_identifier("artifact", &artifact.id)?;
        if !artifact_ids.insert(artifact.id.as_str()) {
            return Err(format!(
                "fixture {} has duplicate artifact id {}",
                fixture.id, artifact.id
            ));
        }
        if !artifact_paths.insert(artifact.path.as_str()) {
            return Err(format!(
                "fixture {} has duplicate artifact path {}",
                fixture.id, artifact.path
            ));
        }
        has_input |= artifact.role == ArtifactRole::Input;
        has_output |= artifact.role == ArtifactRole::Output;
        validate_artifact(workspace_root, fixture, artifact)?;
    }

    if !has_input || !has_output {
        return Err(format!(
            "fixture {} must contain at least one input and one output",
            fixture.id
        ));
    }
    Ok(())
}

fn validate_producer(producer: &Producer) -> Result<(), String> {
    require_nonempty("producer implementation", &producer.implementation)?;
    require_nonempty("captured_at_utc", &producer.captured_at_utc)?;
    if !is_utc_timestamp(&producer.captured_at_utc) {
        return Err("captured_at_utc must use YYYY-MM-DDTHH:MM:SSZ".to_owned());
    }

    match producer.kind {
        ProducerKind::Synthetic => {
            if producer.repository.is_some()
                || producer.release.is_some()
                || producer.commit.is_some()
            {
                return Err(
                    "synthetic producer must not claim repository, release, or commit metadata"
                        .to_owned(),
                );
            }
        }
        ProducerKind::CapturedUpstream => {
            require_optional("producer repository", producer.repository.as_deref())?;
            require_optional("producer release", producer.release.as_deref())?;
            let commit = require_optional("producer commit", producer.commit.as_deref())?;
            if !is_lower_hex(commit, 40) {
                return Err(
                    "producer commit must be a full lowercase 40-character hex id".to_owned(),
                );
            }
        }
    }

    require_nonempty("build toolchain", &producer.build.toolchain)?;
    require_nonempty("build host", &producer.build.host)?;
    require_nonempty("build target", &producer.build.target)?;
    require_nonempty("build configuration", &producer.build.configuration)?;
    if producer.build.command.is_empty()
        || producer.build.command.iter().any(|part| part.is_empty())
    {
        return Err("build command must contain non-empty argument-vector entries".to_owned());
    }
    Ok(())
}

fn validate_artifact(
    workspace_root: &Path,
    fixture: &Fixture,
    artifact: &Artifact,
) -> Result<(), String> {
    let relative_path = Path::new(&artifact.path);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(format!("artifact {} has an unsafe path", artifact.id));
    }

    let required_prefix = Path::new("fixtures").join(&fixture.id);
    if !relative_path.starts_with(&required_prefix) {
        return Err(format!(
            "artifact {} must be below {}",
            artifact.id,
            required_prefix.display()
        ));
    }
    if !is_lower_hex(&artifact.sha256, 64) {
        return Err(format!(
            "artifact {} sha256 must be 64 lowercase hex characters",
            artifact.id
        ));
    }

    let conformance_root = workspace_root.join("conformance");
    let artifact_path = conformance_root.join(relative_path);
    let canonical_root = fs::canonicalize(&conformance_root).map_err(|error| {
        format!(
            "failed to resolve conformance root {}: {error}",
            conformance_root.display()
        )
    })?;
    let canonical_artifact = fs::canonicalize(&artifact_path)
        .map_err(|error| format!("failed to resolve {}: {error}", artifact_path.display()))?;
    if !canonical_artifact.starts_with(&canonical_root) {
        return Err(format!(
            "artifact {} resolves outside conformance",
            artifact.id
        ));
    }
    let metadata = fs::symlink_metadata(&artifact_path)
        .map_err(|error| format!("failed to inspect {}: {error}", artifact_path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{} is not a regular file", artifact_path.display()));
    }
    if metadata.len() != artifact.bytes {
        return Err(format!(
            "artifact {} byte length is {}; manifest records {}",
            artifact.id,
            metadata.len(),
            artifact.bytes
        ));
    }

    let bytes = fs::read(&artifact_path)
        .map_err(|error| format!("failed to read {}: {error}", artifact_path.display()))?;
    let digest = lowercase_hex(&Sha256::digest(&bytes));
    if digest != artifact.sha256 {
        return Err(format!("artifact {} sha256 mismatch", artifact.id));
    }

    match artifact.encoding {
        Encoding::Utf8 => {
            std::str::from_utf8(&bytes)
                .map_err(|error| format!("artifact {} is not UTF-8: {error}", artifact.id))?;
        }
        Encoding::Json => {
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|error| format!("artifact {} is not valid JSON: {error}", artifact.id))?;
        }
        Encoding::Binary => {}
    }

    Ok(())
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), String> {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return Err(format!("{kind} id must not be empty"));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(format!(
            "{kind} id must start with lowercase ASCII or a digit"
        ));
    }
    if characters.any(|character| {
        !character.is_ascii_lowercase() && !character.is_ascii_digit() && character != '-'
    }) {
        return Err(format!(
            "{kind} id may contain only lowercase ASCII, digits, and hyphens"
        ));
    }
    Ok(())
}

fn require_nonempty(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_optional<'a>(name: &str, value: Option<&'a str>) -> Result<&'a str, String> {
    let value = value.ok_or_else(|| format!("{name} is required"))?;
    require_nonempty(name, value)?;
    Ok(value)
}

fn is_lower_hex(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}
