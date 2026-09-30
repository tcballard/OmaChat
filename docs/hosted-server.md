# Hosted server: protocol, threat model and deployment

`omachat-server` is the hosted data plane decided in
[ADR 0007](adr/0007-hosted-server-data-plane.md). This page is written for a
security review: it states what the server protects, what it deliberately does
not protect, exactly how the wire protocol works, and which claims have been
verified by which test.

**The operator can read every message.** Message bodies are encrypted at rest
under a key the operator holds, which protects a copied database file and
nothing more. This is the Slack model, chosen because end-to-end encryption is
not a requirement for the hosted product. It must be described that way to
users.

## Components

| Piece | File | Role |
|---|---|---|
| `omachat-serverd` | `crates/omachat-server/src/bin/omachat-serverd.rs` | The server process: loopback WebSocket listener, SQLite storage |
| `omachat-server-cli` | `crates/omachat-server/src/bin/omachat-server-cli.rs` | One-shot client for operators, reviewers and scripts |
| protocol | `src/protocol.rs` | Frame format, request set, error codes, size limits |
| auth | `src/auth.rs` | Challenge transcripts, server identity, secret files |
| storage | `src/storage.rs` | Schema, at-rest sealing, idempotent append, receipts |
| service | `src/service.rs` | Single-threaded actor: authorization, ordering, fan-out |
| session | `src/session.rs` | Per-connection state machine, rate limit, idle and auth deadlines |
| host | `src/host.rs` | Connection limits, loopback check, graceful shutdown |
| ops | `ops/server/` | Caddy reverse proxy, hardened systemd unit, first-start steps |

## Wire protocol (version 1)

One WebSocket, one JSON object per text frame, at most 16 KiB per frame in
either direction. Binary frames, non-JSON text, an empty or over-long `id`,
or a request before `hello` close the connection after one error frame.

Request:

```json
{"version": 1, "id": "any string up to 64 bytes", "method": "send", "params": {"...": "..."}}
```

Response, exactly one per request, in request order:

```json
{"version": 1, "id": "...", "ok": true, "result": {"...": "..."}}
{"version": 1, "id": "...", "ok": false, "error": {"code": "not-found", "message": "..."}}
```

Event, unsolicited, only after authentication:

```json
{"version": 1, "event": "message", "data": {"...": "..."}}
```

### Authentication

1. `hello {minimum_version, maximum_version, device_public_key}`. The device
   key is a hex Ed25519 public key. The reply is
   `{version, challenge, server_public_key, server_signature}` where
   `server_signature` is the server's Ed25519 signature over
   `"omachat-server-hello-v1\0" || challenge || device_public_key`. Clients pin
   `server_public_key` out of band and verify the signature, so a TLS
   compromise or a misdirected URL cannot impersonate the server.
2. `authenticate {signature, display_name?, invite_code?}`. `signature` is the
   device's Ed25519 signature over
   `"omachat-server-auth-v1\0" || server_public_key || challenge || device_public_key`.
   The challenge is 32 random bytes per connection and is never reused; the
   transcript binds the server key so a signature obtained for one server
   cannot be replayed to another. An unknown device registers a new account
   subject to the registration policy; a known device resumes its account and
   its stored display name is not overwritten.
3. Both steps must complete within the unauthenticated deadline (15 s by
   default) or the connection is closed. Failed authentication closes the
   connection.

### Requests after authentication

| Method | Params | Result | Authorization |
|---|---|---|---|
| `status` | none | account, device, server key, registration mode | self |
| `claim-handle` | `handle` | `{handle}` | once per account; unique server-wide |
| `resolve-handle` | `handle` | `{account_id, handle, display_name}` | any account |
| `create-workspace` | `name` | `{workspace_id, name}` | caller becomes owner |
| `add-member` | `workspace_id, handle` | `{workspace_id, account_id, channels_joined}` | workspace owner |
| `create-channel` | `workspace_id, name` | `{conversation_id, name}` | workspace owner; name unique per workspace |
| `open-dm` | `handle` | conversation summary | any two distinct accounts; idempotent per pair |
| `list-conversations` | none | `{conversations: [...]}` | member |
| `send` | `conversation_id, client_id, text` | `{conversation_id, sequence, id, sent_at, duplicate}` | member |
| `history` | `conversation_id, before_sequence?, limit?` | `{messages: [...]}` ascending, at most 200 | member |
| `mark-delivered` | `conversation_id, sequence` | receipt | member; never beyond last sequence |
| `mark-read` | `conversation_id, sequence` | receipt | member; implies delivered |

Handles follow `omachat-crypto`'s rule: 3 to 32 characters, lowercase
letters, digits and `_`, starting with a letter. Names are 1 to 64 bytes
without control characters or surrounding whitespace. Text is 1 to 8192
bytes. `client_id` is 1 to 64 characters of `[A-Za-z0-9_-]`.

### Ordering, idempotency and receipts

- The server assigns each message a per-conversation `sequence` starting at 1
  inside the same SQLite transaction that stores it. Two clients never see
  different orders.
- `send` is idempotent per `(device, client_id)`. Repeating a send after a
  timeout returns the original `sequence` and `id` with `duplicate: true` and
  no second event. A `client_id` cannot be reused for a different
  conversation. This is what lets a client retry an unknown outcome safely.
- The sender's own delivered and read sequence advance with each message it
  sends. Other members advance theirs with `mark-delivered` and `mark-read`;
  values never move backwards and cannot exceed the conversation's last
  sequence. Every member receives a `receipt` event.
- Events: `message` (the stored message, sent to every member including the
  sender's own sessions), `receipt`, `conversation` (a channel or direct
  conversation the recipient was just added to), `lagged` (see below).

### Limits and back-pressure

| Limit | Default | Where |
|---|---|---|
| Frame size | 16 KiB | WebSocket configuration, both directions |
| Message text | 8 KiB | `validate_text` |
| Requests per connection | 20 per second, burst 40 | token bucket, hello and authenticate excluded |
| Handshake deadline | 10 s | `admission_timeout` |
| Authentication deadline | 15 s | `unauthenticated_timeout` |
| Idle | 300 s | closes silent connections |
| Connections | 1024 global, 32 per IP | rejected before the handshake |
| Queued events per session | 256 frames | overflow marks the session lagged |
| Service request queue | 1024 | back-pressure on sessions |

A session whose event queue overflows receives one `lagged` event and is then
closed. Nothing is silently dropped: the client reloads conversations and
history, which are the source of truth. The service actor runs on its own
operating-system thread; SQLite calls never block the async runtime.

## Storage

SQLite in WAL mode with `synchronous = FULL` and foreign keys on, in a
0700 data directory; the database, WAL and shared-memory files are 0600.
Tables: `accounts`, `devices`, `workspaces`, `workspace_members`,
`conversations`, `conversation_members`, `messages`, `meta`.

Message text is sealed with XChaCha20-Poly1305 under the 32-byte storage key
with a random 24-byte nonce and associated data
`conversation_id || 0 || sequence (big-endian) || 0 || message_id`. A row
copied to another conversation or sequence fails authentication. The `meta`
table holds a sealed key-check value so a database is refused, rather than
silently unreadable, when opened with the wrong key. Everything else
(handles, display names, membership, sequences, timestamps, sender device
keys, client identifiers) is stored in the clear because the server needs it
to enforce authorization and ordering.

## Threat model

Assets: message content, the account directory (handles, display names,
device public keys), membership graphs, and the two operator secrets.

| Adversary | Protected? | How, or why not |
|---|---|---|
| Network attacker between client and server | Yes for confidentiality and integrity | TLS at the reverse proxy; the server key pin defeats a rogue or mis-issued certificate for authentication, though not for content once authenticated over a compromised TLS session |
| Another user of the same server | Yes | Every request is checked against membership; non-members get `not-found`, non-owners `forbidden`; handles and channel names are unique by database constraint; a client cannot forge a sender, sequence or receipt for anyone else |
| Client impersonation | Yes | Possession of the Ed25519 device private key is required per connection; challenges are fresh and bound to the server key |
| Replay of a captured `authenticate` | Yes | Challenge is per connection and never reused |
| Resource exhaustion by an authenticated client | Bounded | Frame, text and queue limits, per-connection rate limit, idle deadline, per-IP and global connection caps, lagged-session eviction |
| Resource exhaustion before authentication | Bounded | Handshake and authentication deadlines, connection caps enforced before the handshake |
| Someone who copies `messages.db` | Content yes, metadata no | Bodies are sealed under `storage.key`; every other column is readable |
| The operator, the host, or anyone who compromises either | **No** | Holds `storage.key` and the running process; can read, alter or delete everything and can register devices under any policy |
| Loss of a device key | No recovery | The account is unreachable; there is no recovery flow in this slice |
| Loss of `storage.key` | Content lost | Every stored body becomes unreadable; the operator must back it up separately |
| Compromise of `server.key` | Server impersonation | Clients pinning the key will accept an impersonator; rotate the key and republish |

Not addressed in this slice, deliberately: end-to-end encryption, multi-device
accounts, account recovery, handle rename or reuse, message edit or delete,
retention and deletion policy, per-workspace roles beyond owner and member,
private channels, invitations that expire, audit logging, and administrative
endpoints. Each is a product decision that belongs in its own ADR.

## Deployment

`ops/server/README.md` has the first-start steps. The shape is:

- `omachat-serverd` binds `127.0.0.1:7448` and refuses any other address;
- Caddy terminates TLS at the public name and proxies WebSocket upgrades;
- the process runs as a dedicated user under the hardened unit in
  `ops/server/omachat-serverd.service`, with `UMask=0077`, no capabilities,
  a read-only system and a private 0700 state directory;
- both secrets are generated with `omachat-serverd --generate-secret` and
  must stay owner-only, or the server refuses to start;
- registration mode is a required argument; `invite` with a code file is the
  recommended setting for a review instance.

## Verified

Every row names the test that proves it. Unit tests run with
`cargo test -p omachat-server`; the end-to-end suite is
`crates/omachat-server/tests/server.rs` and drives a real loopback listener
through `tokio-tungstenite`.

| Claim | Evidence |
|---|---|
| Hello signature proves server identity; device signature bound to server key and challenge; wrong server or wrong challenge fails | `auth::tests::device_signature_round_trips_and_binds_every_field`; every end-to-end login verifies the hello signature |
| Forged signature, stale challenge from another connection, request before hello, unsupported version and non-JSON text are refused and close the connection | `bad_signatures_wrong_order_and_bad_versions_are_refused` |
| Open, invite and closed registration; known devices still authenticate when closed; display name not overwritten | `invite_and_closed_registration_modes`, `registration_authentication_and_status`, `service::tests::registration_policy_is_enforced_for_new_devices_only` |
| Handles unique and set once; invalid handles refused; owner-only channel creation and member addition; non-members cannot send or read; channel names unique per workspace; direct conversation unique per pair | `workspace_channel_and_direct_message_flow`, `storage::tests::*` |
| Server-assigned sequences; idempotent resend returns the original message with no second event; `client_id` cannot cross conversations; history pagination; receipts fan out and never run ahead | `workspace_channel_and_direct_message_flow`, `storage::tests::channels_membership_and_idempotent_messages` |
| Rate limit, oversize text, oversize frame closes, unauthenticated and idle deadlines, global connection cap | `limits_are_enforced`, `connection_limits_reject_excess_clients`, `session::tests::token_bucket_limits_bursts` |
| Overflowing event queue flags the session lagged rather than dropping silently | `service::tests::overflowing_subscribers_are_flagged_lagged_not_silently_skipped` |
| State survives restart; message text absent from the database and WAL files on disk; wrong storage key refused | `state_survives_restart_and_content_is_sealed_at_rest`, `storage::tests::wrong_storage_key_is_refused` |
| Secret files must be owner-only and exactly 64 hex characters; generation never overwrites | `auth::tests::seed_files_require_owner_only_mode_and_exact_hex` |
| Non-loopback listen and inconsistent limits are refused at argument parsing | `process::tests::rejects_incomplete_or_unsafe_configurations` |
| Graceful shutdown closes clients and reports counts | `shutdown_closes_clients_gracefully` |
| Dependency policy: the SQLite tree adds only MIT, Apache-2.0 and one Zlib crate (`foldhash`, scoped by an exception in `deny.toml`); advisories clean with Rustls 0.23.45 | `cargo deny check` 0.20.2, local run on 2026-09-30 |
| The real `omachat-serverd` and `omachat-server-cli` binaries perform the full flow: invite refusal, registration, handles, workspace, channel, member addition, live `message` and `receipt` events to a listening client, idempotent resend, history, wrong pin rejected, 0600 database files, refusal of a public bind and of a group-readable key | Manual run on 2026-09-30 in the development container, recorded in the PR description |

## Not verified

- No deployment behind Caddy or any TLS endpoint has been exercised; the
  Caddyfile and unit are written from documentation, not from a running host.
- No daemon adapter exists yet: the desktop cannot use this server until the
  next slice adds a hosted transport to `omachatd` behind IPC v2.
- Load, soak and fuzz testing are absent; the limits above are asserted
  functionally, not under pressure.
- No external security review has taken place. This document is the input to
  one.
