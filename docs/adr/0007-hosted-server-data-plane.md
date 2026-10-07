# ADR 0007: Hosted server data plane alongside Nostr

> Retention decision superseded by [ADR 0008](0008-hosted-only.md). Nostr is retired.

- Status: Proposed; server and daemon transport slices implemented
- Date: 2026-09-30
- Depends on: ADR 0002 (account/control-plane separation)
- Supersedes for the hosted product: the relay data plane described in
  ADR 0002 section 2 and ADRs 0003 to 0006, which remain in force for the
  Nostr client only

## Context

OmaChat's stated product is an everyday chat client for Omarchy users that can
replace Slack, Teams and Discord. The desktop review and the headless
Quickshell run on the `feat/desktop-*` stack established, with evidence, where
the Nostr data plane hurts that product:

- a relay acknowledgement is not delivery, so the client can never show
  "delivered" or "read", and a slow relay produces an unknown send outcome the
  user must resolve by hand;
- NIP-29 rooms are relay-readable and NIP-17 group chat fans out one gift wrap
  per recipient, so there is no encrypted channel at workspace scale;
- reliability is the reliability of relays the project does not operate, and
  the daemon refuses to start while a private-message relay cannot be
  authenticated;
- identity is one secp256k1 key with no recovery and no multi-device story,
  which ADR 0002 already answers with a central registry.

The owner has decided that end-to-end encryption is not a requirement for the
hosted product. That removes the one property a relay data plane provides that
a conventional server cannot.

## Decision

OmaChat adds a hosted server data plane, `omachat-server`, built alongside the
Nostr transport rather than replacing it in one step.

1. **One operated server, plaintext to the operator.** The server stores
   accounts, workspaces, channels, direct conversations, messages and
   receipts. Message bodies are encrypted at rest under an operator-held key,
   with the conversation, sequence and message identifier as associated data.
   That protects a copied database file and nothing more: the operator, the
   host and anyone who compromises either can read every message. The
   README, SECURITY.md and user-facing documentation must say so wherever the
   hosted transport is described. Nothing in this ADR is an end-to-end
   encryption claim.
2. **Device keys remain the credential.** A client proves control of an
   Ed25519 device key by signing a challenge that binds the server's public
   key; the server signs the same challenge so clients can pin it independently
   of TLS. Accounts, device bindings and handle rules reuse `omachat-crypto`.
   Passwords and email recovery, when added, sit on top of this and never
   replace it.
3. **Server-assigned order and idempotent sends.** Every message carries a
   per-conversation sequence assigned by the server. A send carries a
   client-chosen identifier; repeating it returns the original sequence. An
   unknown outcome is therefore always safe to retry, which retires the
   "never auto-resend" rule for this transport. Delivered and read receipts are
   first-class.
4. **Loopback listener behind a TLS reverse proxy.** The server refuses to bind
   a non-loopback address. Caddy or an equivalent owns certificates, HTTP
   hygiene and the public socket, the same shape as `omachat-registryd`.
5. **Registration policy is explicit.** The operator chooses `open`, `invite`
   or `closed` on the command line; there is no default. Open registration
   logs a warning at start.
6. **The desktop stays transport-agnostic.** The desktop talks IPC v2 to the
   daemon only. A daemon adapter for this server is the next slice; the
   Quickshell shell, drafts, close guard and state modules are unchanged.
7. **Nostr code is retained, not removed.** `omachat-nostr`, the relay
   operations profile and the geohash/bitchat compatibility work stay in the
   tree. Whether they remain in the default build is a later decision taken on
   evidence from operating the hosted server.

## Consequences

- The operator becomes the custodian of every message and of the account
  directory, with the availability, retention, deletion, abuse and legal
  obligations that implies. Those are operational responsibilities OmaChat did
  not have with third-party relays.
- Interoperability with other Nostr clients is not available over the hosted
  transport. Contact links remain meaningful only for the Nostr transport.
- Message bodies are an opaque sealed blob to the server code paths that do
  not need them, so a later end-to-end mode can change clients without
  changing the schema; this ADR does not promise that mode.
- The central registry of ADR 0002 and the chat server may be one service.
  Handle uniqueness is enforced by the server's database in this slice; the
  signed receipts and key-transparency mechanism of ADR 0002 are not carried
  over yet and their necessity is reconsidered under a single operator.
- The desktop live-hardening work on unknown send outcomes stays correct for
  the Nostr transport and becomes unnecessary for the hosted one.

## Current evidence

The `omachat-server` crate contains the protocol, authentication, SQLite
storage, service actor, host limits, `omachat-serverd` and the
`omachat-server-cli` client, with unit and end-to-end tests over a real
loopback listener. See `docs/hosted-server.md` for the wire protocol, threat
model, deployment profile and the exact list of what has and has not been
verified. `omachatd` carries the hosted transport behind IPC v2 (`hosted`
configuration, `send` to `hosted:` conversations, the `hosted-*` commands and
the `hosted` status block), proved against an in-process server in
`crates/omachatd/tests/hosted_transport.rs`. No hosted server is deployed and
the desktop does not use the hosted commands yet; see
`docs/hosted-server-plan.md`.
