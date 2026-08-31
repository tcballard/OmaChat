# Crypto-vector capture and reference harnesses

## OmaChat account/registry v1

`generate-account-registry-vector.py` is a same-project, independent Python
reference calculation for OmaChat's account and registry transcripts. It uses
fixed, plainly synthetic Ed25519, X25519, and secp256k1 test keys and fixed
times. It neither imports nor executes OmaChat's Rust implementation.

This vector is not captured upstream evidence, deployed-service evidence, or
proof of interoperability with the pinned Swift and Android clients. Its value
is narrower: two implementations calculate the new OmaChat-specific protocol
bytes independently, and Rust tests must match the committed Python result.

Use CPython 3.12.13. The exact Python packages used for the committed fixture
are pinned in `requirements-account-registry.txt`. Every seed in `inputs.json`
is public, test-only private material and must never be replaced with a real
account, device, registry, or recovery secret. Generate into a new directory:

```sh
python3 -m venv <venv-directory>
<venv-directory>/bin/python -m pip install \
  -r conformance/harnesses/requirements-account-registry.txt
<venv-directory>/bin/python \
  conformance/harnesses/generate-account-registry-vector.py \
  --output-dir <output-directory>
```

The generator sorts JSON keys, emits a final newline, and refuses to overwrite
an existing output directory. The committed vector interleaves Alice's first
and second transitions around Bob's first transition, distinguishing the
registry-wide receipt predecessor from Alice's per-account predecessor.

## OC-004 upstream captures

These capture-only tests are copied into clean checkouts of the exact upstream
revisions named by the compatibility profile. They are never linked into an
OmaChat binary.

The workflow runs every capture twice and byte-compares the two output trees.
The Swift harness uses fixed, plainly synthetic keys, timestamps, nonces,
messages, and a sentinel geohash. It exercises upstream event types, secp256k1,
XChaCha20-Poly1305, Noise state machines, courier encoding, day-tag derivation,
and production decrypt/validation paths. The Android harness consumes the two
deterministic Swift envelopes and records which historically deployed inner
tag shapes the pinned Android build accepts.

Swift's `JSONEncoder` does not promise object-member order and emits different
orders in separate processes. The capture adapter therefore sorts the nested
rumor and seal object keys before encryption. JSON member order has no protocol
meaning; the normalization is recorded in each envelope fixture, and the
pinned production decryptors must still accept the resulting bytes.

The Android source is treated as a black-box compatibility peer. Its capture
test records observable inputs and outputs; it is not a source for OmaChat's
Rust implementation.

The Android wrapper disables the build cache and forces task execution. This
is required because each replica starts with an empty capture directory;
Gradle's ordinary `UP-TO-DATE` result would otherwise skip the second test and
leave no independently produced bytes to compare.

Run the scripts only against clean upstream checkouts at the revisions embedded
in the scripts. Each script refuses a different `HEAD`.
