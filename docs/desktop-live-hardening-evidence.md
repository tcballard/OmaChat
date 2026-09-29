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

## Not verified

Everything in [XPS live testing](xps-live-testing.md): an actual Quickshell
window, compositor close shortcuts, themes, restart and recovery on Omarchy,
two live clients, relay reachability and two-machine messaging. Fixture and
container results are not live evidence.
