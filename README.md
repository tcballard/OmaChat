# OmaChat

OmaChat is a work-in-progress, per-user bitchat-compatible node, daemon, command
client, and terminal UI for Arch Linux and Omarchy. It combines bounded Nostr
and mesh protocol implementations with sealed local state. It can serve only
while its host is powered and awake with the required radio/network available.

**No release is available yet.** Version 0.0.1 remains under development until
all OC-001–OC-064 gates close. Hermetic Rust and captured Swift fixtures cover
substantial protocol behavior, but the hardware, live-peer, packaged-host, and
72-hour release gates remain authoritative. Do not treat this branch as an
unconditional interoperability, availability, or security claim.

Compatibility is pinned to bitchat Swift v1.7.1. Android v2.0.1 is supported
only feature by feature: its release has no courier/prekey/current-bridge
surface. Proprietary private envelopes are not standard Nostr DMs. Bridge
advertising must remain disabled until its live health gate succeeds.

## Planning

- [Upstream validation](docs/upstream-validation.md)
- [0.0.1 compatibility profile](docs/compatibility-profile.md)
- [Build backlog](docs/build-backlog.md)
- [Current implementation/evidence status](docs/implementation-status.md)
- [Development contract](docs/development.md)
- [Conformance fixture contract](conformance/README.md)
- [Security and privacy](SECURITY.md)
- [Installation and service lifecycle](docs/installation.md)

## Development

The repository is an eight-crate Rust workspace pinned to Rust 1.98.0. It now
contains bounded protocol codecs, cryptographic identities/envelopes, sealed
persistence, daemon IPC, CLI/TUI surfaces, and pre-release packaging assets.
Radio integration and all live conformance evidence remain gated; see the
development contract and build backlog for the exact boundary.

All implementation changes use pull requests. Pull requests are not merged without explicit owner approval.

OmaChat is licensed under the [Zero-Clause BSD license](LICENSE). The project name remains provisional pending a separate adoption-grade clearance review.
