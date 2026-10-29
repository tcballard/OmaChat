# ADR 0011: Restore Nostr direct messages and the two clients

- Status: Accepted by owner instruction, 2026-10-28
- Builds on: [ADR 0010](0010-nostr-identity.md)
- Supersedes the "phase 2 is not in this change" limit in ADR 0010 for messaging only

## Context

ADR 0010 put a sealed secp256k1 key (`nostr-identity-v1`) back on `main`:
generate, import, export, `npub` display, and `@handle` binding with NIP-05.
It left direct messages, the `omachat` terminal, and the Quickshell desktop
removed.

The pre-ADR-0008 tree at `c35a85516da47a6aa6db3a3d236a7230e9e5da69` has the
Nostr transport, NIP-44, the terminal client, and the Quickshell window. That
tree derived its Nostr key from the device Ed25519 secret and also carried
hosted workspaces, NIP-29 rooms, geo-relays, and BLE mesh.

## Decision

Phase 2 restores messaging and the two user interfaces, wired only to the
Phase 1 key:

- `omachat-nostr` is back for NIP-01 events, NIP-44 (in `omachat-crypto`),
  NIP-17/NIP-59 gift wraps, NIP-65 and NIP-17 relay lists, profiles, and the
  relay pool. NIP-29 group modules, geo-chat, the private mobile envelope, and
  `omachat-mesh` stay out.
- `omachatd` loads `NostrSecret` from `nostr-identity-v1`. It does not derive
  a key from Ed25519. Opening `omachat` or the Quickshell window calls
  `chat-prepare`, which generates and seals a key when none is stored.
  `omachat-ctl identity show` still does not create one. `identity generate`
  and `identity import` still refuse to replace a stored key.
- Contacts are `npub`, a 64-character public key, or `name@domain`. NIP-05
  fetches `https://<domain>/.well-known/nostr.json?name=<name>` and does not
  follow redirects. Tests may point that fetch at numeric-loopback HTTP.
- `dm_relays` in the daemon config is the initial read/write set (`wss://`, or
  numeric-loopback `ws://`). The UI's relay editor stores a sealed list that
  replaces the config list on later starts. At most four relays. The first
  three `wss://` URLs are published as a kind-10050 inbox list. Two people
  need a relay in common for delivery. Relay acceptance is not proof the
  recipient read the message.
- The `omachat` terminal and `desktop/` Quickshell window are the clients.
  They cover the npub, handle claim/bind, contacts, relays, and DMs. They do
  not export an nsec, open workspaces, or join NIP-29 rooms.
- IPC stays version 4 and gains the chat commands. Older chat commands stay
  rejected.

BLE mesh and running an Omacon NIP-29 relay remain later phases.

## Consequences

- Launch the terminal with `omachat` and the window with
  `sh desktop/omachat-desktop`, after `omachatd` is running. See the README.
- A key created by opening a client is a real Nostr identity. Export it before
  discarding the sealed store.
- The installed client set is `omachatd`, `omachat`, and `omachat-ctl`, still
  under the 10 MiB release ceiling.
- The handle server is unchanged: it stores the binding and serves NIP-05. It
  does not store message bodies and it is not a community relay.
