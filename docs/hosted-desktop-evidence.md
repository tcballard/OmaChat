# Hosted desktop acceptance

Validated on 2026-10-01, on `feat/hosted-desktop`, after merging main's
#230–#238 stack into `feat/hosted-server` (merge `6a02b87`).

The production adapter and Quickshell UI now discover hosted conversations,
load selected history, page backwards, open DMs with @handles, group channels
by workspace, report unread sequence cursors, mark focused loaded history
read, and display delivered/read receipts. Receipt labels mean at least one
other member, not all members. The identity panel states that the server
operator can read messages. Hosted drafts retain the sealed-store conflict
and close protections. Workspace administration offers only owned workspaces
for channel/member changes; the server separately enforces permissions.

Two additive data-plane fields make the UI restart-safe: list-conversations
returns account-visible workspaces (including empty ones) and conversation
summaries return stored receipts. The IPC response budget is shared by the
conversation and workspace arrays. No authentication or authorization rule
was relaxed.

## Automated evidence

- 599 Rust tests passed, zero failures or ignored tests.
- Formatting, Clippy with warnings denied, warning-free rustdoc, debug and
  release workspace binaries, version contract and packaging passed.
- Installed client release binaries total 6,634,168 bytes, under 10 MiB.
- 31 Python/Qt tests passed on PySide6 6.8.3, including the owned-workspace
  selector and existing draft/close/relay setup regressions.
- JavaScript state, contact, draft and hosted suites passed. Hosted checks
  cover history deduplication, sequence ordering, account-specific receipt
  handling, unread acknowledgement, disconnected drafts, and receipt
  enrichment of a cached snapshot that lacks server sequence numbers.
- `python3 scripts/test-hosted-desktop.py` passed with debug and release
  binaries. It starts a real loopback server, two real daemons and both
  production adapters under generated temporary identities. It verifies
  handles, empty workspace discovery, owner/member roles, denial of channel
  creation to a non-owner, channel membership, DMs, history paging, read
  receipts, persisted receipt metadata and sealed hosted drafts.
- Existing real-daemon desktop adapter and PTY smoke tests passed against
  release binaries. CI runs the new two-daemon adapter smoke test after build.

## Production headless window

Runtime: Debian sid container, Quickshell 0.3.1, Qt 6.11.2, Sway 1.12 headless,
software rendering. The production launcher, ChatService, ChatView and Python
adapter connected to Alice's real daemon while Bob's real daemon shared the
same local hosted server. `wtype` supplied keyboard input; `grim` captured the
screenshots. This is production-shell evidence, not the Qt fixture backend.

Verified: hosted conversation/history loading, restored read labels, workspace
grouping, recovered sealed draft, opening @bob through New message, viewing
hosted connection/handle/trust text, and creating "Headless acceptance" through
the Workspaces dialog. A separate daemon IPC lookup confirmed the new workspace
and Alice's owner role. The dialog was also rendered at 440×600 with scrolling.
No application QML errors occurred. Qt logged keyboard-leave warnings during
virtual-keyboard attach/detach; these are recorded rather than counted as a
warning-free compositor run.

Screenshots:

- [Conversation and read receipt](images/desktop-headless/hosted-conversation.png)
- [Identity and trust disclosure](images/desktop-headless/hosted-identity.png)
- [Workspace administration](images/desktop-headless/hosted-workspaces.png)
- [Narrow workspace dialog](images/desktop-headless/hosted-narrow.png)

To reproduce the backend fixture, build the workspace then run
`python3 scripts/test-hosted-desktop.py --serve`. It prints a temporary fixture
path; point `OMACHAT_SOCKET` at its `alice/omachat.sock` and launch
`desktop/omachat-desktop` in a Quickshell-capable graphical session. Stop the
fixture with SIGINT when finished. The fixture never uses real account state.

## Remaining boundaries

No production server was deployed. Real TLS, Omarchy/Hyprland, hardware/GPU,
external networks, and deployment/security-review slices remain unverified.
The desktop is a bounded 128-conversation/128-message view; server frame/list
limits still apply. Workspace administration and history are not an unbounded
archive browser. Repeated failed read acknowledgements are throttled; unread
state is cleared only on a server receipt. The desktop change is for PR review
and is not merged by this work.
