# OmaChat

OmaChat is a planned always-on, bitchat-compatible mesh node and terminal client for Arch Linux and Omarchy.

The current development version is **0.0.1**. The complete existing backlog, OC-001 through OC-064, forms this initial release; there are no intermediate version bumps or releases between its gates. Protocol behavior is pinned to named upstream releases and must pass cross-implementation fixtures or live-peer tests before it is trusted.

## Planning

- [Upstream validation](docs/upstream-validation.md)
- [0.0.1 compatibility profile](docs/compatibility-profile.md)
- [Build backlog](docs/build-backlog.md)
- [Development contract](docs/development.md)

## Development

The repository is an eight-crate Rust workspace pinned to Rust 1.98.0. At this
stage the three binaries implement only the frozen `--version` contract; mesh,
Nostr, cryptographic, storage, daemon, and TUI behavior will arrive through the
tracked 0.0.1 backlog. See the development contract for the workspace map and
local verification commands.

All implementation changes use pull requests. Pull requests are not merged without explicit owner approval.

OmaChat is licensed under the [Zero-Clause BSD license](LICENSE). The project name remains provisional pending a separate adoption-grade clearance review.
