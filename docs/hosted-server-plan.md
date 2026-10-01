# Hosted server: delivery plan

Status: working plan, maintained on `feat/hosted-server`
Decision record: [ADR 0007](adr/0007-hosted-server-data-plane.md)
Review input: [hosted-server.md](hosted-server.md)

This is the complete list of work between the code on this branch and a
hosted OmaChat that a team can use every day in place of Slack. Each slice
names its scope, what "done" means, the evidence that proves it, and who has
to act. A slice is not done because its code exists; it is done when the
acceptance line is met and the evidence is recorded.

The order matters. Slices 2 and 3 make the product usable end to end. Slice
4 puts it on a host. Slice 5 is the security review you asked for. Slice 6
is the feature work that separates "chat works" from "replaces Slack", and
each item there is a product decision that needs its own ADR before code.

## Where this stands

| Slice | State | Evidence |
|---|---|---|
| 1. Server crate | Done on this branch | 23 tests, full workspace suite green, real binaries driven end to end in the development container |
| 2. Daemon transport | Done on this branch | `crates/omachatd/tests/hosted_transport.rs`, three end-to-end tests over an in-process server; full workspace suite green |
| 3. Desktop support | Implemented on `feat/hosted-desktop`; pending PR review | [Desktop evidence](hosted-desktop-evidence.md), real server/two-daemon adapter test and production headless Quickshell run |
| 4. Deployment | Not started; needs a host, a name and an operator | |
| 5. Security review | Not started; needs the reviewers named | |
| 6. Product features | Not started; each needs an ADR | |
| 7. Nostr code decision | Deferred by ADR 0007 until slice 4 has run for a while | |

## Slice 1: server (done)

`crates/omachat-server`: accounts, workspaces, channels, direct
conversations, server-ordered history, delivered and read receipts,
idempotent sends, device-key authentication with a pinnable server key,
open/invite/closed registration, per-connection and per-host limits, SQLite
storage with message bodies sealed at rest, `omachat-serverd` and
`omachat-server-cli`, a Caddy and systemd profile, and the review document.

Not in slice 1 and not promised by it: end-to-end encryption, multi-device
accounts, account recovery, handle rename, message edit or delete, retention,
roles beyond owner and member, private channels, expiring invitations, audit
logging, administrative endpoints.

## Slice 2: daemon transport (done on this branch)

Goal: `omachatd` connects to a hosted server so that any IPC v2 client, the
desktop included, can use hosted conversations without knowing the server
protocol.

Scope:

- `hosted` section in the daemon configuration: server URL (`wss://`, or
  loopback `ws://` for tests), the pinned server public key (required), an
  optional display name and invite code. A change requires a daemon restart,
  like every other transport setting.
- The device credential is the daemon's existing Ed25519 signing key, the
  same key that signs the local account binding. The hosted account is
  therefore bound to the `device_id` the daemon already reports. The two
  transcripts are domain-separated (`omachat-server-auth-v1` against the
  local binding domain), so a signature for one can never be a signature for
  the other. No new secret is stored.
- A hosted service task owns one WebSocket: connect, verify the server's
  hello signature against the pin, sign the challenge, authenticate,
  multiplex requests, forward events, and reconnect with backoff (1 s
  doubling to 30 s) when the connection drops. Every request has a deadline.
- Conversation identifiers on IPC are `hosted:<conversation_id>`. The
  existing `send` command routes on that prefix. The daemon generates the
  idempotency `client_id`, retries the same identifier across a reconnect
  until its deadline, and remembers an unacknowledged identifier for the
  same conversation and text so that a user's manual resend after a timeout
  cannot produce a duplicate.
- New IPC commands, all prefixed `hosted-`: `conversations`, `history`,
  `mark-read`, `open-dm`, `claim-handle`, `resolve-handle`,
  `create-workspace`, `create-channel`, `add-member`. Each is a thin, typed
  pass-through with the daemon's own validation and error codes.
- IPC events: `messages` for every stored message (own messages marked
  outgoing), `delivery` for receipts, `conversations` for channels and
  direct conversations the account joins, `status` when the hosted
  connection state changes. The daemon marks a message delivered when it
  has actually received it, never earlier.
- `status` gains a `hosted` block: state, URL, account id, handle, display
  name and the pinned key.
- `omachat-ctl` gains matching subcommands.
- The shared wire contract (transcripts, protocol constants, validators)
  moves to `omachat-proto::hosted` so the daemon does not depend on the
  server crate. The server binaries stay out of the installed client set and
  the size ceiling is unchanged.

Acceptance:

- A daemon configured against an in-process server authenticates, and a
  wrong pin is refused before any request is sent.
- `send` to a hosted conversation returns the server sequence; the same
  message arrives as a `messages` event on a second daemon for the other
  member; that daemon's automatic delivered receipt reaches the sender as a
  `delivery` event; `hosted-mark-read` does the same for read.
- Killing the server mid-send and restarting it yields exactly one stored
  message, and the daemon's send answers with the original sequence.
- `hosted-history` pages backwards and marks the fetched range delivered.
- The full local check suite passes, including the release size guard.

Evidence: `crates/omachatd/tests/hosted_transport.rs`, and the verified
claims table in `hosted-server.md`. Every acceptance line above is covered
by those tests except the last, which the check suite covers. Not covered:
the `wss://` path against a real certificate, which needs slice 4.

## Slice 3: desktop support

The desktop stack (#230 to #238) is merged into main and reconciled with
`feat/hosted-server`. The implementation is in `feat/hosted-desktop`; see
[hosted desktop evidence](hosted-desktop-evidence.md) for validation and limits.

Scope:

- At snapshot time the adapter calls `hosted-conversations` and, for the
  selected conversation, `hosted-history`, in addition to the existing
  subscription snapshot.
- Delivery labels for `delivered` and `read`; the `delivery` topic payload
  carries per-conversation sequences rather than per-message ids, so the
  state module derives per-message state from them.
- "New direct message" accepts a handle when the daemon reports a hosted
  connection, alongside the existing npub path.
- Channel list grouped by workspace; unread counts from
  `last_sequence` against `read_sequence`; `hosted-mark-read` when a
  conversation is focused.
- Workspace administration (create workspace, create channel, add member)
  behind a small dialog, owner only, driven by the same commands.
- Hosted connection state in the identity panel, including the honest "the
  operator can read messages on this server" line the ADR requires.

Acceptance: the headless Quickshell run from #238 extended with a hosted
server in the container, two daemons, and the screenshots recorded in
`docs/images/desktop-headless/`.

## Slice 4: deployment

Owner actions, none of which can be done from this repository:

1. Choose a host and a DNS name. The server needs one small Linux host
   with a public name; the review instance can be a single small VM.
2. Install `omachat-serverd` under the unit in `ops/server/`, generate
   both secrets, choose `invite` registration and a code file, put Caddy in
   front with the provided Caddyfile, and confirm the listener refuses
   anything but loopback.
3. Back up `storage.key` somewhere that is not the host. Losing it makes
   every stored message unreadable, by design.
4. Publish the server public key out of band so clients can pin it.
5. Point one daemon at it from a real Omarchy machine and repeat the
   slice 2 acceptance over real TLS.

Repository work for this slice: a `scripts/check-hosted-deployment.sh`
that connects with `omachat-server-cli`, verifies the pin, and exercises
registration and a send, so the deployment can be re-verified after every
change; a short runbook for key rotation, restore from backup, and adding an
invite code.

Acceptance: the check script passes against the named host from a machine
that is not the host, and the runbook has been followed once for a restore.

## Slice 5: security review

Input: `hosted-server.md`, the threat model table, and the verified claims
table. Reviewer actions:

- Confirm the trust statement: the operator reads everything; there is no
  end-to-end claim; the pin is the only protection against a rogue TLS
  endpoint and it is an out-of-band trust decision.
- Check the authentication transcript binding and the reuse of the device
  signing key across the local binding and hosted authentication.
- Check the SQLite at-rest sealing: associated data, key check, WAL
  handling, file modes.
- Check the limits under load, not just functionally.

Repository work to make the review cheaper:

- A fuzz target for the server frame decoder and request parser under
  `fuzz/`, alongside the existing hostile-codec target, run on the nightly
  schedule.
- A load script (`scripts/load-hosted-server.sh` or a small Rust example)
  that opens N connections and sends at the rate limit, recording memory
  and latency, so the "bounded" rows in the threat model become measured.
- A written list of findings with a fix or a documented acceptance for each.

Acceptance: the findings list exists, every item is either fixed with a test
or accepted in writing by the owner, and the review's date and scope are
recorded in `hosted-server.md`.

## Slice 6: product features for a Slack replacement

Each needs an ADR because each changes the data model, the trust statement,
or both. Rough order by how often a team hits the gap:

| Feature | Why it needs a decision first |
|---|---|
| Multi-device accounts | The account is currently one device key; a second device means either a shared secret or a device enrollment flow signed by an existing device, and revocation |
| Account recovery | Loss of the key loses the account; recovery means the operator or a recovery key can rebind, which is a trust change |
| Message edit and delete | Server-ordered history is append-only; edits and deletes are new events with policy on who may do them and whether history keeps the original |
| Retention and deletion | The operator holds every message; a retention policy is a promise to users and a legal position |
| Private channels and roles | Only owner and member exist; roles decide who can invite, remove, rename, delete |
| Threads and reactions | New message kinds and a parent reference; affects unread counts and receipts |
| Search | Bodies are sealed at rest; search means either decrypting server-side (the operator already can) or client-side indexes |
| Files and images | Storage, size limits, virus scanning, retention, and the same at-rest sealing question |
| Presence and typing | Ephemeral events with a privacy cost; cheap to add, worth deciding deliberately |
| Notifications | Desktop notifications from the daemon; an Omarchy integration question as much as a server one |
| Expiring invitations and self-service registration | Invite codes are static in a file today |
| Administrative endpoints and audit log | Suspend accounts, remove members, see who did what |

Acceptance for each: an ADR accepted, server and daemon changes with tests,
the review document updated, and the desktop change in its own PR.

## Slice 7: what happens to the Nostr code

ADR 0007 keeps `omachat-nostr`, the relay operations profile and the
geohash/bitchat compatibility work in the tree and makes no decision about
the default build. Revisit after slice 4 has run for long enough to know
whether anyone uses the Nostr transport. Options, in order of how much they
remove: keep both in the default build; put Nostr behind a Cargo feature
that the package enables; move it to a separate package. The size ceiling
and the installed-set check decide what is affordable.

## Open decisions for the owner

1. Name. Whether the hosted product keeps the OmaChat name. This decides
   nothing technical and was the only real argument for a fork.
2. Registration policy for the first real instance: `invite` is the
   recommendation and the default in the deployment profile.
3. Whether the central registry of ADR 0002 and this server become one
   service. The ADR leaves it open; the server enforces handle uniqueness
   in its own database today.
4. Who reviews. Slice 5 needs named people and a date.

## What is deliberately not on this list

Federation between hosted servers, bridging hosted conversations to Nostr,
mobile clients, a web client, and single sign-on. Each is real work; none is
needed for a team on Omarchy to stop using Slack.
