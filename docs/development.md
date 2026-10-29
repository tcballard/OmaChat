# Development contract

Rust 1.98.0, edition 2024. Crates: proto, crypto, nostr, store, server,
daemon, terminal, and CLI. Dependencies remain pinned; review Cargo.lock changes.
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
The client release set (`omachatd`, `omachat`, `omachat-ctl`) must stay under
10 MiB. Server binaries are separate from the installed client set.
Desktop checks are `python3 -m unittest discover -s desktop/tests -p 'test_*.py'`,
`node desktop/tests/test_contact.js`, and `node desktop/tests/test_state.js`.

[ADR 0010](adr/0010-nostr-identity.md) archives the hosted chat product on
branch `hosted-archive` at `825cf07123`. [ADR 0011](adr/0011-nostr-messaging.md)
restores Nostr DMs and the two clients on the sealed secp256k1 key.
Run the [Nostr acceptance gate](nostr-e2e.md) after changing messaging, clients
or handle deployment. Omacon is optional; a public community relay is not a
prerequisite for this gate.

Historical evidence documents describe earlier builds, not current
interoperability claims.
