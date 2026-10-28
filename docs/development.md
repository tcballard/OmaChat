# Development contract

Rust 1.98.0, edition 2024. Six crates: proto, crypto, store, server, daemon
and CLI. Dependencies remain pinned; review Cargo.lock changes.
All implementation changes use pull requests; merging requires explicit owner approval.

Run the CI checks locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
cargo build --workspace --bins --locked
scripts/check-version-contract.sh
cargo build --workspace --bins --release --locked
scripts/check-release-size.sh
sh scripts/check-packaging.sh
```

Fuzzing exercises the bounded IPC parser.
The client release set (`omachatd`, `omachat-ctl`) must stay under 10 MiB.
Server binaries are separate from the installed client set.

[ADR 0010](adr/0010-nostr-identity.md) archives the hosted chat product on
branch `hosted-archive` at `825cf07123` and makes Nostr identity the direction
on `main`. Historical evidence documents describe earlier builds, not current
interoperability claims.
