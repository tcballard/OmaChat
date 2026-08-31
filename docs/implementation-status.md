# 0.0.1 implementation status

This is a code/evidence inventory, not an issue-closure claim. A row marked
implemented means the machine-independent implementation and local tests exist.
The acceptance gates in `build-backlog.md` remain authoritative.

| Area | Implemented in this branch | Still requires external evidence or work |
|---|---|---|
| G0 prerequisites | Frozen pins, fixtures, georelay policy, BlueR/proxy/keyring probes | Named-adapter dual-role capture; Omarchy keyring/service lifecycle matrix; live system-Tor/Arti observations |
| G1 Nostr product | Sealed providers/records and explicit migration; four independent identity roots; strict event/envelope/relay/pool/georelay/mailbox/outbox code; versioned IPC; CLI/TUI; daemon relay actor, subscriptions, publish/receive, reload and restart tests | Pinned iOS/Android live chat/presence/private delivery; real relay/proxy gate; target-host keyring lifecycle; TUI remains line-input rather than a ratatui/crossterm raw-event loop |
| G2 public mesh | Bounded v1/v2 packet, compression/signing, announce, fragmentation, GCS/request-sync, presence/routing/dedup/source-route logic, six-hour sealed public archive, 15-minute transient caches, bounded RSR backfill selection, production BlueR GATT/advertise/discover/read/write runtime, duplicate-link and adapter-loss state | Daemon-level mesh orchestration; real BlueZ policy/adapter qualification; pinned Swift/Android one/two-hop corpus and live tests; long-running radio convergence |
| G3 private mesh | Exact captured Noise XX transcript/transport; replay/reorder/rekey state; authenticated pins; private messages/receipts/dedup; favorite/challenge/vouch controls; sealed favorites/verification/blocks; deterministic mesh/Nostr/queue route policy; transport-attempt history; ANSI QR output through packaged `qrencode` | Live Noise/QR/favorite exchange against pinned phones; daemon-level mesh session/outbox orchestration; scanned-QR input workflow |
| G4 courier/bridge | Exact pinned courier v1/v2/day-tag captures; prekey grace; sealed quotas/deposits/spray/handover; kind-1401 relay drops; carrier type 28 bounded TLVs; signed rendezvous `r`/optional `m`; bridge identity domain, loop guard and metrics; persisted public/courier restart tests | Exact upstream carrier golden capture; daemon bridge orchestration/health gating; pinned iOS live courier and bridge tests; two-hour multi-node backfill rig |
| G5 hardening/release | Cryptographic panic transaction and proof; persisted block state; hardened user unit; desktop entry; shell completions; man pages; tagged/`-git` PKGBUILDs; Quattro widget; legacy Waybar example; security/privacy/install docs; nightly parser fuzz workflow | Omarchy v4.0.1 validation/install/upgrade/removal; Secret Service panic test; package archive checksum after an authorized tag; clean-chroot/namcap; widget live validation; 72-hour soak and signed release evidence |

## Local verification

The machine-independent workspace currently passes formatting, Clippy with all
warnings denied, every workspace test, rustdoc with warnings denied, all binary
builds, the frozen version contract, and packaging structure checks. The fuzz
target is committed for scheduled nightly execution; this container does not
have `cargo-fuzz`/`libfuzzer-sys` installed locally.

## Deliberate non-claims

- No issue whose acceptance requires a named machine, phone, adapter, public
  relay, target desktop, long-duration run, tag, publication, or owner action is
  closed solely by this branch.
- The tagged PKGBUILD contains a failing checksum marker until an authorized
  release archive exists.
- Bridge advertising must remain off until the live carrier/rendezvous path is
  healthy; codec presence is insufficient.
- Panic is cryptographic erasure, not guaranteed physical overwrite or remote
  deletion.
