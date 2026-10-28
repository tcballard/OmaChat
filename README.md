# OmaChat

<a href="https://github.com/tcballard/omarchy-badges"><img src="https://raw.githubusercontent.com/tcballard/omarchy-badges/75975e5b5bf75e7ede3764bcd2950046f7abfe2c/badges/v1/omarchy-app.svg" alt="Omarchy App" height="20"></a>

OmaChat is returning to Nostr as its primary direction. [ADR 0010](docs/adr/0010-nostr-identity.md)
archives the hosted Slack/Discord-style product and scopes the next work to
optional Nostr identity, handle binding and NIP-05.

The chat product (workspaces, channels, direct messages, the desktop and the
terminal client) remains on branch `hosted-archive` at commit `825cf07123`.
It is not developed on `main`.

**Development preview; no release is deployed.** `main` keeps a local daemon,
a control CLI and a loopback handle server. The server authenticates an
Ed25519 device key and stores one `@handle` per account. It does not store
chat. A schema-version-1 chat database is refused.

Build with Rust 1.98.0: `cargo build --workspace --bins`. Configure one server
URL and its independently obtained public key in `omachatd`'s `hosted` settings
when the daemon should claim or resolve handles.
See [server operations](ops/server/README.md).

The workspace contains protocol, crypto, sealed store, handle server, daemon
and CLI crates. The installed client binaries (`omachatd`, `omachat-ctl`) retain
a 10 MiB aggregate release size ceiling. IPC v4 rejects older clients; update
the CLI and daemon together. Existing device signing credentials remain valid.

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
and `cargo test --workspace --locked` after building.
Deployment, security review, account recovery and multi-device support remain outstanding.
Nostr direct messages, an Omacon relay and BLE mesh are future phases and are
not in this tree. See [ADR 0010](docs/adr/0010-nostr-identity.md).

All implementation changes use pull requests. Pull requests are not merged without explicit owner approval.

See [security and privacy](SECURITY.md). Licensed under [Zero-Clause BSD](LICENSE).
The project name remains provisional pending a separate adoption-grade clearance review.

For the archived chat product, check out `hosted-archive` rather than pointing
this binary at a chat database. Server data and secrets must survive uninstall;
see [server operations](ops/server/README.md).
