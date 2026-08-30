# Conformance fixture contract

Tracks: [OC-003](https://github.com/tcballard/OmaChat/issues/4),
[OC-004](https://github.com/tcballard/OmaChat/issues/5), and
[OC-005](https://github.com/tcballard/OmaChat/issues/6)

This directory is the provenance boundary for every byte OmaChat calls a
cross-implementation fixture. A fixture is trusted only when `manifest.json`
identifies where it came from, how its producer was built and invoked, which
compatibility profile it targets, and the size and SHA-256 digest of every
artifact.

OC-003 defines the contract and includes one harmless schema smoke fixture.
OC-004 adds captured release-critical vectors from the immutable Swift v1.7.1
and Android v2.0.1 compatibility pins. The capture-only harnesses remain test
adapters and are never linked into an OmaChat binary.

OC-005 adds exact content-addressed geo-relay snapshots under `georelays/`.
Those public data files have a separate manifest because they are frozen
compatibility-profile inputs rather than generated protocol vectors. Rust
oracle tests verify their provenance, hashes, entry counts, selection behavior,
and bounded union policy.

## Layout

```text
conformance/
├── README.md
├── georelays/
│   ├── cases.json
│   ├── manifest.json
│   └── snapshots/<sha256>/
├── harnesses/
│   ├── README.md
│   ├── android/
│   └── swift/
├── loader.rs
├── manifest.json
└── fixtures/
    ├── schema-smoke-v1/
    └── <captured-fixture-id>/
        ├── inputs.json
        ├── intermediates.json
        └── outputs.json
```

`loader.rs` is test-only Rust support. The `omachat-proto` integration test
compiles it directly, so schema and artifact verification run under the normal
workspace test command without adding fixture machinery to production code.
Tests call `load_manifest` before using `load_artifact`, so profile, provenance,
path, size, digest, and encoding checks precede interpretation of fixture bytes.

## Manifest schema version 1

The Rust types in `loader.rs` are the executable schema. Deserialization denies
unknown fields. Semantic validation additionally enforces:

- schema version `1` and exact compatibility-profile identifiers;
- unique, lowercase fixture and artifact identifiers;
- at least one input and one output per fixture;
- full 40-character lowercase source commits for captured upstream builds;
- non-empty toolchain, host, target, configuration, and command metadata;
- relative artifact paths confined to `conformance/fixtures/<fixture-id>/`;
- regular files only, with exact byte length and lowercase SHA-256 digest;
- valid UTF-8 or JSON whenever the declared encoding requires it.

Producer kind `captured-upstream` requires repository, release, and immutable
commit metadata. Producer kind `synthetic` must leave those fields null so a
hand-authored sample cannot masquerade as upstream evidence.

## Inputs and secrets

Every artifact has one of two disclosure values:

- `public-committed` — ordinary public input, output, or intermediate data.
- `test-only-private` — mathematically private material, such as a synthetic
  test key, created solely for a fixture and intentionally committed publicly.

`test-only-private` is a provenance warning, not a confidentiality mechanism.
Anyone can read it. Never use a real identity key, production credential,
device export, relay token, user message, or derived value from any of those.
Real secrets have no valid manifest representation and must not enter the
repository, its Git history, CI artifacts, issue attachments, or test logs.

Before committing a future fixture, inspect every artifact and confirm that all
secret-shaped values are synthetic. If that cannot be proven, discard the
capture and regenerate it with newly created test-only keys.

## Regenerating fixtures

1. Check out the exact source commit recorded by the active compatibility
   profile in a clean upstream worktree.
2. Create a disposable staging directory with `mktemp -d`; generate fresh
   synthetic keys there when the vector needs private material.
3. Record the producer repository, release, full commit, toolchain, host,
   target, build configuration, and the argument-vector form of the capture
   command. Never record secrets in the command.
4. Run the capture twice from identical declared inputs and require identical
   artifacts. A nondeterministic field must be supplied explicitly and recorded
   as an input.
5. Inspect and classify every artifact, copy only approved files below
   `conformance/fixtures/<fixture-id>/`, then record byte sizes and SHA-256
   digests in `manifest.json`.
6. Run `cargo test -p omachat-proto --test conformance_manifest --locked`, then
   the full workspace checks from `docs/development.md`.
7. Delete the disposable staging directory. Treat deletion as cleanup, not as
   proof that a real secret was safe to process.

Fixture changes require review like protocol code. Replacing bytes without
updating their provenance and digest is a test failure, not an accepted update.

## OC-004 capture normalization

The Swift capture uses fixed synthetic keys, timestamps, nonces, messages, and
a sentinel geohash. Swift's `JSONEncoder` does not guarantee object-member
order, so the capture adapter sorts only the nested rumor and seal JSON keys
before encryption. JSON member order has no protocol meaning. Both pinned
production decryptors must still accept the normalized envelopes, and CI runs
each capture twice before comparing the output trees byte for byte.

Android is an acceptance peer only. Its fixture records which deployed Nostr
inner-event shapes the pinned Android build opens; no Android implementation
code or constants are copied into OmaChat production code. Each Android
replica forces an uncached Gradle test execution so a successful comparison
cannot be satisfied by an `UP-TO-DATE` task with no newly written output.
