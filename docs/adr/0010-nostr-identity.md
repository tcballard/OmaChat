# ADR 0010: Archive the hosted chat product and return to Nostr

- Status: Accepted by owner instruction, 2026-10-28
- Supersedes: [ADR 0008](0008-hosted-only.md) and the product direction in [ADR 0009](0009-slack-discord-replacement.md)
- Related: ADR 0005 (principal-control proof), ADR 0007 (the archived data plane)

## Context

ADR 0008 made hosted messaging the only transport and removed Nostr. ADR 0009
then aimed that hosted server at replacing Slack and Discord: workspaces,
channels, administration, invite codes, a desktop client and a terminal client.

That product is intact on branch `hosted-archive` at commit
`825cf07123dd5bf98061d6b0c9fa61f179ebe5c3`, which is the same commit as `main`
when this decision was taken. It is not deleted from history. It is not the
line of development on `main`.

The owner wants Nostr identity to be the primary direction again, starting
with a small identity layer rather than restoring relays, rooms or mesh.

## Decision

`main` no longer contains the hosted chat product. Workspaces, channels,
direct messages, history, receipts, invite codes, registration modes, the
Quickshell desktop and the `omachat` terminal client are removed. Shared
pieces the identity work needs stay: Ed25519 device credentials, the sealed
store, local IPC, and a loopback server process.

`omachat-serverd` on `main` is a thin handle server. It authenticates a device
with the existing Ed25519 challenge, creates an account on first use, and lets
that account claim one `@handle`. It refuses a schema-version-1 chat database
instead of opening it. The websocket session and event queue stay so the
process can later grow into the Omacon relay. That growth is a direction, not
work in this change.

Nostr is the primary direction again, in phases. Only phase 1 is in scope for
the change that follows this archive:

1. **Phase 1.** Optional secp256k1 Nostr identity on the client (`nsec` import
   and export, `npub` display), sealed like the device secret. Bind an `npub`
   to an `@handle` on `omachat-serverd` with both the existing Ed25519 device
   authentication and a BIP-340 Schnorr proof of the Nostr key, including a
   fresh nonce and timestamp so a transcript cannot be replayed. One `npub`
   cannot be bound to two handles. Serve NIP-05 at
   `GET /.well-known/nostr.json?name=<handle>` with
   `Access-Control-Allow-Origin: *`. Everything keeps working when no Nostr
   key is present.
2. **Phase 2.** Nostr direct messages and profile portability with Damus,
   Primal and Amethyst. Not in this change.
3. **Phase 3.** An Omacon community relay. Not in this change. The thin server
   is only shaped so that relay has a place to grow.
4. **Phase 4.** BLE mesh (`omachat-mesh`). Not in this change.

Phases 2–4 wait for review. This ADR does not restore `omachat-nostr`, NIP-29
rooms, the old registry, or the mesh crate.

Phase 1 is implemented on top of the archive cut: `omachat-ctl identity`
generates, imports, exports and shows a sealed Nostr key; `identity bind` and
`identity unbind` talk to `omachat-serverd`; the server serves NIP-05.

IPC moves to version 4. Chat commands are rejected. Clients and the daemon
move together. A chat database is not migrated.

## Consequences

- Operators who need the Slack-style server check out `hosted-archive` at
  `825cf07123`. They do not upgrade that database with the `main` binary.
- The installed client set is `omachatd` and `omachat-ctl`. There is no
  `omachat` terminal binary and no desktop package entry.
- The server operator can still see handles and account metadata. There are
  no message bodies on this server to read.
- Publishing a handle-to-`npub` binding, once phase 1 lands, is a public
  correlation. The proof is consent for that binding; the interface must say so.
- ADR 0008's retirement of Nostr no longer describes `main`. ADR 0009's
  Slack/Discord target no longer describes `main`. Both documents stay as
  history of the archived product.
