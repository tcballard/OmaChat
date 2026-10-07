> Historical document. Nostr and its compatibility/relay workflows are retired by [ADR 0008](adr/0008-hosted-only.md). See [the hosted plan](hosted-server-plan.md) for current work.

# Desktop live-hardening evidence

29 September 2026. Stacked on the guided relay configuration slice. This is a
development record, not a release claim, and nothing here was run on Omarchy.

## Findings fixed

- The daemon serves one client's requests in order, and a direct-message send
  waits for its relay round trip (connect and response timeouts of 20 s each).
  The adapter's single 5 s deadline therefore ended the whole session on any
  slow relay: every send slower than 5 s produced "Disconnected; reconnecting",
  marked every in-flight send unknown and reset draft state. The adapter now
  allows 30 s for `send`, `join-room` and `leave-room`, answers a missed UI
  deadline once as an unknown outcome, discards the late daemon reply and
  keeps the subscription open. Internal requests still end the session on a
  timeout, and 64 unanswered UI requests end it as well.
- A send with an unknown outcome now sets the conversation's unknown flag,
  which blocks resending until the user checks, instead of a plain error that
  allowed an immediate duplicate send.
- A draft save with an unknown outcome is reread rather than retried blind. A
  refused save whose stored text already equals the local text adopts the
  stored revision instead of raising a conflict prompt with identical text.
- Quickshell watches loaded QML/JS files and reloads on change by default. A
  reload destroys the adapter process, forgets in-flight sends and loses
  memory-only edits. The launcher now turns file watching off at startup;
  `Quickshell.watchFiles` is a writable property in Quickshell 0.3.1
  (`src/core/qmlglobal.hpp`, `src/core/rootwrapper.cpp`).
- The setup helper installs a SIGTERM handler so the desktop's 5 s deadline
  kill unwinds through cleanup and removes its temporary file.
- Save-and-close now waits 35 seconds instead of ten, covering one full send
  deadline, and its failure text names pending sends.

## Verified in this environment

Ubuntu 24.04 container, Rust 1.98.0, Python 3.11, Node 22, PySide6 6.8.3
offscreen. Unix sockets are available. No Quickshell, no Wayland, no relay.

- `cargo build --workspace --all-targets --locked` and
  `cargo test --workspace --locked`: all passing, exit 0.
- `node desktop/tests/test_state.js`, `test_contact.js`, `test_drafts.js`:
  passing, including the new unknown-outcome and identical-text cases.
- `python3 -m unittest discover -s desktop/tests -p 'test_bridge.py'`:
  11 tests passing over real Unix sockets and a real adapter process.
- `python3 -m unittest discover -s desktop/tests -p 'test_setup.py'`: 8 passing.
- `QT_QPA_PLATFORM=offscreen ... test_view.py`: 10 passing with the
  production ChatView, CloseGuard and RelaySetup over fixture backends.
- `scripts/test-desktop-bridge.py` against the daemon built from this branch:
  private 0600 socket, hello/subscribe snapshot, `drafts_version` 1, drafts
  saved from one adapter and read by another, stale-revision refusal in both
  directions, oversize refusal, destructive command refusal, daemon restart
  with drafts persisting, sealed records without plaintext, adapter exit code
  1 on daemon loss and 0 on stdin EOF.
- Recent-history snapshot bound: the daemon caps the sealed cache at 32 KiB
  encoded (`chat_history.rs`) under its 64 KiB IPC line limit, so a snapshot
  can never trip the adapter's 64 KiB frame limit.
- Quickshell 0.3.1 source check: `Quickshell.shellPath()` is current (not
  deprecated), `FloatingWindow.minimumSize`, `Process.write`/`stdinEnabled`,
  `SplitParser.read`, `Quickshell.env`, `Quickshell.lastWindowClosed` and the
  `QQmlEngine::quit` connection all exist; a running `Process` is killed when
  its object is destroyed.

## Headless Quickshell run (same day, after the fixes above)

An Arch Linux userland (Quickshell 0.3.1, Qt 6.11.2, Sway 1.12 with the
headless wlroots backend and pixman rendering, Mesa 26.2) was set up in this
container with the production `desktop/omachat-desktop` launcher, the real
`bridge.py` and `setup.py`, and the daemon built from this branch. Pointer and
keyboard input came from a virtual keyboard and pointer helper; screenshots
came from `grim`. This is real Quickshell process and IPC evidence. It is not
Hyprland, not Omarchy, and not a GPU-backed session. Screenshots are in
`docs/images/desktop-headless/`.

Passed:

- Launch through the launcher: one `quickshell` process, one `bridge.py`
  child, an `xdg` toplevel with app id `dev.omachat.Desktop`, no QML warnings
  in the Quickshell log across three instances.
- Connect, contact link preview, opening a direct conversation, typing, and
  "Draft saved securely" with the daemon's draft store confirming the text
  and revision.
- Daemon stop while typing: "Offline" status; a compositor close request then
  opened the close guard with Save and close disabled and Keep editing and
  Close anyway available. After the daemon restart the offline edits were
  reconciled and saved without a prompt (verified through IPC).
- Two windows on one daemon: the second recovered the saved draft with the
  review prompt and Send disabled; typing into the stale copy produced the
  "Another client changed this draft" choice with local text preserved; Use
  saved text replaced the composer.
- Save and close: typed text, close request, dialog, Save and close; the
  window and its adapter exited and the daemon held the final revision.
- Unknown outcome: with the daemon paused (SIGSTOP), Send showed "Sending…"
  with the window still connected; at 30 s it showed "Delivery is unknown"
  with "I checked — allow another send" and Send disabled; after SIGCONT the
  message appeared through the subscription and nothing was resent.
- Storage failure: with the records directory mounted read-only, typing
  showed the daemon's "Read-only file system" error and "Retry draft
  recovery" with text intact; after restoring, retry saved the draft.
- Relay setup through the real helper process against a custom
  `OMACHAT_CONFIG` path: load, save a URL, canonical form shown, unrelated
  `joined_geohashes` preserved, a 0600 backup created, the restart notice shown.
- Hot reload: appending to `ChatView.qml` while the window ran caused no
  reload and no state loss.
- Narrow layout at 640 px and at the 440×480 minimum, the Chats toggle, and
  the light theme read from `colors.toml`.
- Forced termination (SIGTERM to quickshell) and Close anyway both left no
  adapter process behind.

Defects found by this run and fixed in this PR:

- On Qt 6.11 the bindings on the active conversation's `busy`, `uncertain`
  and `error` fields never refreshed (same object reference each revision), so
  "Sending…", send errors and the "allow another send" button never appeared;
  Send simply went dark. The offscreen Qt 6.8 fixture does refresh them, so
  fixture tests had not caught it.
- Dialog titles were invisible on a light default header; the conflict
  preview and identity link were white boxes with light text; relay dialog
  labels clipped instead of wrapping.
- Reconnect backoff reached 30 s, so a daemon restart could go unnoticed for
  half a minute; capped at 10 s.

Daemon behaviour observed, not changed here: with an unreachable NIP-17 relay
configured the daemon exits at startup ("relay authentication timed out")
instead of running degraded, so a wrong relay URL leaves the desktop
disconnected until the URL is corrected and the daemon restarted. The relay
dialog and the XPS guide now say so.

## Not verified

Hyprland and Omarchy themselves, GPU rendering, the Omarchy close-window
binding, real relays, NIP-17 and NIP-29 delivery between machines, and the
clipboard copy of the contact link. See [XPS live testing](xps-live-testing.md).
Fixture and headless-container results are not Omarchy evidence.
