# Hosted paging and setup hardening evidence

7 October 2026. Based on `d6d63634464cc5b45e51f59755144a13ae3c4437`
(the top of #239–#241). Exact changed executable/test inputs are recorded in
[hosted-hardening-inputs.sha256](hosted-hardening-inputs.sha256); verify from
the repository root with `sha256sum -c docs/hosted-hardening-inputs.sha256`.
Documentation-only edits do not establish new runtime results.

## Reproduced locally

Linux development container, Rust 1.98.0. Portable checks:

- Formatting and Clippy, workspace/all targets with warnings denied: pass.
- Hosted server tests: pass, including strict 16 KiB receiving sockets, multi-page
  maximum-size/Unicode/escaped history with no skipped or duplicate rows, encoded
  overflow rejection, 40 channels, 36 workspaces, 65 members, complete roster
  traversal, full-roster peer receipts and authorization on paged queries.
- Hosted daemon integration suite: five tests pass, including 40 channels through
  IPC command handling, five 4096-byte messages paged without loss, malformed and
  oversized cursor rejection and encoded-text rejection without disconnect.
- Strict hosted IPC round-trip/rejection tests: two pass.
- All four JavaScript suites: pass, including retention of workspaces across
  pages, repeated/invalid cursor termination, final history page and peer receipt
  restoration beyond the member preview.
- Debug workspace binary build, binary version contract, packaging structure,
  launcher/setup-test shell syntax and whitespace checks: pass.

## Failed or blocked locally

- `cargo test --workspace --locked`: existing CLI Unix-socket fixtures fail at
  `UnixListener::bind` with EPERM in this container. A library-only run similarly
  hits the daemon's private-socket fixture. These are not reported as passes.
- `scripts/test-hosted-setup.sh`: blocked at chown because this container maps
  only UID/GID 0; the existing `nobody` account is unmapped. The new CI step runs
  as root on the ordinary Ubuntu runner and tests actual startup as `nobody`
  using a temporary copy of the binary and temporary secrets. It touches no
  system configuration or user accounts, verifies 0600 files and no-overwrite
  generation, and verifies the runtime user cannot write the secret directory.
- A targeted daemon build first hit a zero-length zbus build-object error;
  cleaning that generated package output and rebuilding succeeded. The final
  targeted daemon integration run passed all five tests.
- Qt checks are not run locally: PySide6 is unavailable. The existing desktop CI
  job installs its pinned Qt dependency and runs the Qt/protocol checks.

## CI and live acceptance

The PR's check runs are authoritative for full workspace, real Unix-socket
adapters, the new root/service-user setup regression, Qt, release size and TUI
PTY checks. Do not infer success until the run for the reviewed commit finishes.
Previous green checks on #239–#241 are historical and do not validate this diff.

No physical Omarchy/Hyprland version, public TLS endpoint, deployment restore,
load/soak run or external security review was exercised by this change. The
128-conversation/workspace desktop session limits remain explicit product work.
See the replacement roadmap for subsequent acceptance gates. No release or
production deployment is made by this change.
