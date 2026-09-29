# Desktop development evidence — 29 September 2026

## Inputs and scope

- Base: `bf49de52a30cf834929261f499e4e1a09f22bd8c`, branch `feat/xps-trial`,
  PR #230. This change is stacked on that branch; it does not merge it.
- New code/test input hashes: [desktop/SHA256SUMS](../desktop/SHA256SUMS).
  Verify from the repository root with `sha256sum -c desktop/SHA256SUMS`.
  Hashes identify inputs; they are not test results.
- Protocol inspected: base `omachat-proto/src/ipc.rs`, `omachat-ctl/src/lib.rs`,
  `omachatd/src/core.rs`, `room_service.rs`, `config.rs`, and live TUI code.
- Quickshell API source inspected at
  `41651d7dcd62a9400eb6f4f8a8580efe00901efb`:
  `src/io/process.hpp`, `src/window/floatingwindow.hpp`,
  `src/window/windowinterface.hpp`, `src/core/qmlglobal.hpp`.
- Local environment: Linux container, Python 3.12, Qt/PySide6 6.8.3,
  offscreen QPA, Node.js. No Quickshell executable or Rust toolchain installed.

## Reproduced locally

- `python3 -m unittest discover -s desktop/tests -p 'test_view.py' -v`:
  **3 tests passed**, exit 0. Loads the actual production ChatView with a
  test-only deterministic backend. Covers multiline/send behavior, keyboard
  DM entry, offline draft preservation, narrow/light rendering and zero QML
  engine warnings.
- `node desktop/tests/test_state.js`: **passed**, exit 0. Covers draft
  ownership across conversation switches and late replies, duplicate events,
  UTF-8 limits, rejected/unknown sends, unread and deletion behavior, history
  bounds, absence of DM configuration and changes of daemon identity.
- The seven pure protocol tests in `test_bridge.py` passed during the complete
  suite: bounded framing, split Unicode input, event/snapshot ordering,
  response correlation, timeout, queue bounds and destructive-command refusal.
- `sh -n desktop/omachat-desktop`: passed, exit 0.
- Visually inspected offscreen render at 1080×760. It is a test-fixture render,
  not a screenshot of Omarchy or proof of live Nostr messaging.

## Failed / environment-blocked locally

`python3 -m unittest discover -s desktop/tests -p 'test_*.py' -v`:
**10 passed, 2 errors**, exit 1. Both socket integration checks failed at
`socket(AF_UNIX)` with `PermissionError: Operation not permitted` before the
adapter could be exercised. They were not skipped or relabelled as passes.
The dedicated desktop CI job requires both to run on its Linux runner.

## Historical only

PR #230 reports a real XPS 9320 / Omarchy 4.0.2 TUI and a two-daemon NIP-17
exchange through a localhost Grain relay. Those results were not reproduced
here and do not establish that this new desktop works on that machine.

## Not run / required before desktop release

- Production Quickshell launch and close lifecycle, actual Wayland focus,
  accessibility/IME, theme changes, and real daemon/desktop interoperability.
- Two-machine DM and NIP-29 room admission, denial, leave, reconnect and restart
  scenarios; latency, long history and idle CPU/RAM measurements on the XPS.
- Fresh setup, keyring lock/reboot, package install/update/remove, persistent
  draft/history design and the existing release soak gates.
- Rust checks were not rerun locally: no Rust files or manifests changed and
  no Rust toolchain is available. Existing Rust CI remains enabled for the PR.

This handoff is a reviewable development client, not release readiness or an
upstream adoption claim. See the PR checks for subsequent CI results against
its exact head commit; do not replace the local observations above with them.
