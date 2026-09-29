# Make OmaChat useful enough to choose daily

29 September 2026. Product direction for the next development milestones.

The goal is an approachable Omarchy communications app that ordinary people
can use before enabling any agent feature. Becoming an upstream default is a
separate community/maintainer adoption decision; this roadmap cannot grant it.
Keep the Nostr identity, relay and sealed-storage work. Deliver complete user
workflows on it, then add coordination where it demonstrably helps.

## First slice: desktop conversations (this PR)

Standalone Quickshell/Qt Quick window, Rust daemon authority, and a small
Python-standard-library IPC adapter. Quickshell is already relevant to the
Omarchy target and supplies native Wayland windows, Qt text input and controls.
This avoids introducing a web runtime or changing the Rust protocol/storage
stack. It is an optional source-run client, outside the three-Rust-binary size
ceiling, with no change to the existing package payload.

The UI owns selection, filtering, layout and ephemeral per-chat drafts. The
adapter owns framing, correlation, deadline and queue bounds; it cannot change
keys, configuration, global handles or destructive state. The daemon owns
identity, cryptography, room authority, history, network and retries. Closing
the app closes the adapter/socket and leaves the daemon running.

Acceptance: two authorized users can copy device public keys, open a DM,
exchange messages, distinguish queueing from relay acknowledgement, switch
chats without losing/misrouting drafts, and recover after a daemon restart.
Rooms identify their distinct relay semantics. Text input must remain
responsive while the daemon is slow. No network I/O runs in the QML UI thread.

## Next: onboarding and durable conversations

- Finish and merge the existing trial foundation after its remaining gates.
- Provide a first-run flow for identity, a working relay choice, connection
  diagnostics and a contact link/QR; do not ship placeholder relay addresses.
- Support npub/contact links and signed profile discovery, preserving the
  distinction between a display name, device key and verified authority.
- Add daemon-owned sealed, paginated history and sealed drafts, explicit
  retention controls and migration/recovery tests. The desktop must never
  create an unencrypted parallel chat database.
- Demonstrate two real machines exchanging messages, network loss/rejoin,
  duplicate suppression, keyring lock/reboot and a failed-send recovery path.

Exit: a new user can complete the first conversation without editing JSON or
copying a 64-character hexadecimal key. History and drafts survive restart.

## Then: a community worth staying in

Room discovery/creation, member and moderator controls, invite handling,
replies/threads, image/file sharing, local search and opt-in notifications.
Specify privacy, encryption and retention for each feature before claiming
parity with Matrix or Discord. Accessibility, IME, long-message layout and
large-history performance are acceptance work, not post-release polish.

Exit: a real small community can use OmaChat for a week without a second app
for routine communication. Measure cold start, idle CPU/RAM, send latency and
scroll responsiveness on Tom's XPS; set budgets from observed bottlenecks.

## Finally: the distinctive coordination workflow

Keep proposed ADR 0006 explicitly proposed until reviewed and accepted. Build
one source-backed commitment/decision workflow with human and agent authorship
clearly distinguished, scoped permissions, revocation, immutable source links
and bounded automation. Raw social rooms stay usable without AI. Do not block
basic chat on this work or label a generic bot account an authorized agent.

## Release and adoption gates

Complete the existing security/interoperability gates, clean Arch packaging,
install/update/remove tests, recovery documentation and multi-user soak.
Publish honest screenshots and supported-version evidence, then seek upstream
review. No automatic protocol switch to Matrix, production service deployment,
repository merge or release is part of this desktop development change.
