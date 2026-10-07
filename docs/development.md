# Development contract

Rust 1.98.0, edition 2024. Seven crates: proto, crypto, store, server, daemon,
CLI and TUI. Dependencies remain pinned; review Cargo.lock changes.
All implementation changes use pull requests; merging requires explicit owner approval.

Run the CI checks locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
cargo build --workspace --bins --locked
python3 scripts/test-hosted-desktop.py
scripts/check-version-contract.sh
cargo build --workspace --bins --release --locked
python3 scripts/test-tui-pty.py
scripts/check-release-size.sh
sh scripts/check-packaging.sh
```

See desktop/README.md for JS/Qt checks. Fuzzing exercises the bounded IPC parser.
The client release set (omachatd, omachat, omachat-ctl) must stay under 10 MiB.
Server binaries are separate from the installed client set.

Nostr, mesh, registry and upstream conformance workflows are retired under ADR 0008.
Historical evidence documents describe earlier builds, not current interoperability claims.
