# OmaChat

<a href="https://github.com/tcballard/omarchy-badges"><img src="https://raw.githubusercontent.com/tcballard/omarchy-badges/75975e5b5bf75e7ede3764bcd2950046f7abfe2c/badges/v1/omarchy-app.svg" alt="Omarchy App" height="20"></a>

OmaChat aims to replace everyday Slack and Discord workflows with a self-hostable
service and native Omarchy client. See the [replacement roadmap](docs/slack-discord-roadmap.md).

Today it is a hosted text collaboration development preview for Arch Linux and Omarchy,
with workspaces, channels, direct messages, history, and delivered/read receipts.
The Quickshell desktop and terminal client connect through a local Rust daemon.

**Development preview; no release or hosted instance is deployed.** The server
operator can read messages. Storage is sealed at rest; messaging is not end-to-end encrypted.
Nostr, relay rooms, geohash chat and the standalone registry are retired by
[ADR 0008](docs/adr/0008-hosted-only.md).

Build with Rust 1.98.0: `cargo build --workspace --bins`. Configure one server
URL and its independently obtained public key in `omachatd`'s `hosted` settings.
See [desktop setup](desktop/README.md), [server operations](ops/server/README.md),
and [the delivery plan](docs/hosted-server-plan.md).

The workspace contains protocol, crypto, sealed store, hosted server, daemon,
CLI and TUI crates. The installed client binaries retain a 10 MiB aggregate
release size ceiling. IPC v3 rejects pre-retirement clients; update clients
and daemon together. Existing hosted device signing credentials remain valid.
Desktop setup replaces retired configuration fields after making a private backup.

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and `python3 scripts/test-hosted-desktop.py` after building.
Desktop tests and limits are described in its README. Deployment, security review,
account recovery and multi-device support remain outstanding.

All implementation changes use pull requests. Pull requests are not merged without explicit owner approval.

See [security and privacy](SECURITY.md). Licensed under [Zero-Clause BSD](LICENSE).
The project name remains provisional pending a separate adoption-grade clearance review.

For source-run rollback, stop the preview and return to a compatible checkout;
preserve daemon configuration, keys, sealed history and drafts. Closing the
desktop leaves the daemon running. Server data and secrets must survive
uninstall; see [server operations](ops/server/README.md). No physical Omarchy
version was validated by the October transport-hardening work.
