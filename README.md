# OmaChat

OmaChat is a tiny, work-in-progress text-collaboration client for Arch Linux and
Omarchy. Its direction is persistent user accounts, workspaces, channels, and
direct messages: a central identity/control plane supplies globally unique
handles and membership, while Nostr relays carry end-to-end encrypted content.
The repository also retains bounded bitchat-compatible geohash and Bluetooth
work, but Bluetooth/mesh is substantially deferred from the critical path.

**No release is available yet.** Version 0.0.1 remains under development. The
client now has a sealed, restart-stable local account foundation, but no central
registry is deployed and a configured handle is only a local candidate—not a
claim of global uniqueness. Do not treat this branch as an unconditional
interoperability, availability, or security claim.

Compatibility is pinned to bitchat Swift v1.7.1. Android v2.0.1 is supported
only feature by feature: its release has no courier/prekey/current-bridge
surface. Proprietary private envelopes are not standard Nostr DMs. Bridge
advertising must remain disabled until its live health gate succeeds.

## Planning

- [Upstream validation](docs/upstream-validation.md)
- [0.0.1 compatibility profile](docs/compatibility-profile.md)
- [Build backlog](docs/build-backlog.md)
- [Account registry and text-collaboration ADR](docs/adr/0002-account-registry-and-text-collaboration.md)
- [Current implementation/evidence status](docs/implementation-status.md)
- [Development contract](docs/development.md)
- [Conformance fixture contract](conformance/README.md)
- [Security and privacy](SECURITY.md)
- [Installation and service lifecycle](docs/installation.md)

## Development

The repository is a nine-crate Rust workspace pinned to Rust 1.98.0. It now
contains bounded protocol codecs, distinct device/account/recovery keys, sealed
persistence, daemon IPC, CLI/TUI surfaces, and pre-release
packaging assets. Size-optimized release builds of the three installed binaries
are held to a 10 MiB aggregate CI ceiling. The central registry, workspace
surface, target-host validation, and live conformance evidence remain gated;
see the development contract and build backlog for the exact boundary.

All implementation changes use pull requests. Pull requests are not merged without explicit owner approval.

OmaChat is licensed under the [Zero-Clause BSD license](LICENSE). The project name remains provisional pending a separate adoption-grade clearance review.
