# ADR 0002: Separate the account control plane from encrypted collaboration

Status: accepted

Date: 2026-08-31

## Context

OmaChat's original backlog is organized around compatibility with the pinned
mobile geohash, Bluetooth mesh, and courier protocols. That work remains useful,
but the immediate product is now persistent text collaboration between Omarchy
hosts: users need durable accounts and globally recognizable handles before
later workspaces and channels can provide a credible Slack or Teams alternative.

A Nostr signing key alone is not an account system. It does not allocate a
globally unique human-readable handle, bind and revoke multiple devices, express
recovery authority, or let a client detect a registry that has rolled an account
back or shown inconsistent key state. Conversely, a central account service must
not become able to read collaboration content or recover an account by itself.

## Decision

OmaChat will separate two planes:

1. A central identity and control plane owns globally unique handle allocation
   and returns signed, versioned registry receipts. An immutable cryptographic
   account ID remains distinct from mutable profile data. A separate recovery
   authority and signed device bindings prevent the registry alone from taking
   over an account. Receipt chains and a key-transparency mechanism must make
   rollback or equivocation detectable.
2. Nostr relays form the collaboration data plane. Messages and future files
   remain end-to-end encrypted for their intended recipients; the registry and
   relays are not given plaintext content or account private keys.

Clients may use a previously verified registry record while offline, but must
label it as cached rather than fresh. A locally normalized handle is only a
candidate handle. OmaChat will not claim global uniqueness until an authoritative
registry state machine or adapter has returned and the client has verified its
signed receipt.

The first implementation slice is deliberately local and hermetic: create the
cryptographically distinct account and recovery roots, stable identifiers, a
signed device/profile binding, sealed account state, and truthful daemon status.
Both roots are provisionally co-resident in that sealed state; off-device
recovery custody is not implemented. The slice does not claim a live registry,
registry cache, globally unique handles, hosted relays, or completed account
recovery.

Workspaces, membership, permissions, channels, threads, reactions, search,
files, and notifications follow the account foundation; they are not silently
folded into the existing geohash issues.

Bluetooth gates G2 through G4 are substantially deferred from the critical
path. Existing compatibility code, fixtures, and issue history are retained and
must not be described as removed or as live acceptance. They can resume without
changing the account/data-plane separation.

[OC-065](https://github.com/tcballard/OmaChat/issues/73) is the authoritative
implementation scope for the account and registry foundation. If this ADR's
summary and that issue ever differ, the issue body controls implementation and
acceptance until the documents are reconciled.

## Consequences

- A central registry introduces availability, abuse, dispute, privacy, and
  operational responsibilities, but it does not become a message custodian.
- Account identity survives handle and profile changes, while device compromise
  can be addressed without silently replacing the account root.
- Offline continuity is possible without turning stale cache state into a false
  freshness or uniqueness claim.
- Existing Nostr relay, mailbox, outbox, daemon, IPC, and TUI work remains useful
  to the text-collaboration path.
- Geohash and Bluetooth interoperability become optional compatibility layers
  rather than prerequisites for the first persistent-account slice.

## Current evidence

The repository contains reusable sealed-storage, identity, Nostr, IPC, and
daemon foundations plus the first local account slice: independent account and
recovery roots (currently co-resident), stable account/device IDs, strict
candidate handles, signed device/profile bindings, sealed persistence, and
truthful daemon status. A hermetic authoritative state machine enforces handle
uniqueness, revision CAS, idempotency, and registry-signed global and
per-account hash-chained receipts. Handle rename and reuse remain deferred
until service policy is specified; the state machine does not silently choose
permanent tombstones. Crash-safe sealed persistence and a bounded, versioned
service/client transport adapter preserve those invariants and complete
accepted-claim evidence across restart. Verified handle/account lookups return
the exact claim-bound receipt against a pinned registry key; historical state
without that evidence fails lookup closed. Registry hosting/deployment, daemon
integration, the verified freshness cache, key
transparency, and the workspace/channel product surface are not completed or
live.
