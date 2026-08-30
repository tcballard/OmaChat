# OC-004 crypto-vector capture harnesses

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
