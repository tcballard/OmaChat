# Hosted-only retirement evidence

Branch: `feat/hosted-only`, based on `feat/hosted-desktop`.
Decision: [ADR 0008](adr/0008-hosted-only.md), owner-directed retirement of Nostr.

Removed Nostr/mesh/standalone registry crates, daemon relay services, public-key
contact links, relay-room UI, relay infrastructure, upstream compatibility fixtures
and their CI jobs. The desktop configures one pinned hosted server and opens DMs
by server handle. Local IPC is v3; pre-retirement clients must be updated together.

The existing Ed25519 signing seed still authenticates the same hosted account.
Tests load a pre-retirement identity record and compare its public key and challenge
signature. Hosted drafts/history retain their record names; retired conversation IDs
are excluded. Old transport configuration fails closed. Desktop setup makes a private
backup before replacing it with the hosted schema. Unrelated sealed records are not
silently deleted; panic erasure still removes the entire local store when confirmed.

Validation on 2026-10-01:

- Full Rust workspace: 107 tests passed. The final hosted-only startup fence was
  subsequently checked by all four hosted transport integration tests.
- Formatting, Clippy with warnings denied, and rustdoc with warnings denied passed.
- All 31 desktop Python/Qt tests and three JS suites passed.
- Real hosted server, two daemons and production adapters passed with debug and
  release binaries: handles, permissions, workspaces, channels, DMs, paging, receipts
  and sealed drafts.
- Hosted panic erasure stops the connection, removes local credentials and rejects
  subsequent commands or transport startup. Process lifecycle and terminal tests
  cover restart/reattach, detach, SIGINT/SIGTERM and terminal restoration.
- Release client binaries total 4,153,912 bytes (10 MiB ceiling). Packaging and version
  contracts passed. Desktop source checksums were regenerated.

[Server setup screenshot](images/desktop-headless/hosted-only-setup.png) is an offscreen
Qt fixture, not a live server screenshot. It uses the actual ChatView/ServerSetup components.
The adapter integration uses real binaries; this retirement was not separately exercised
on a physical Omarchy desktop or against a publicly deployed TLS endpoint.
Deployment and independent security review remain outstanding. Hosted messages are
not end-to-end encrypted; the server operator can read them.
