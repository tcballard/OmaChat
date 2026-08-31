# 0.0.1 implementation status

This is a code/evidence inventory, not an issue-closure claim. A row marked
implemented means the machine-independent implementation and local tests exist.
The acceptance gates in `build-backlog.md` remain authoritative.

## Product direction

[ADR 0002](adr/0002-account-registry-and-text-collaboration.md) records the
accepted text-collaboration direction: persistent accounts and globally unique
handles use a central identity/control plane with signed registry receipts and
key transparency, while Nostr relays carry end-to-end encrypted collaboration
data. Workspaces, membership, permissions, and channels follow the account
foundation; they are not implemented by the existing geohash surface.

Bluetooth G2 through G4 are substantially deferred from the current critical
path. Their code, fixtures, and evidence remain in the repository as retained
compatibility work.

OC-065 is open. Its first local slice now implements cryptographically distinct,
co-resident account/recovery roots, stable account/device IDs, strict candidate
handles, signed device/profile binding, sealed account state, and truthful
daemon status. A transport-independent authoritative state machine now proves
atomic uniqueness, revision CAS, idempotency, exact claim-to-receipt binding,
and signed global/per-account hash chains hermetically. Sealed registry state
and complete accepted-claim evidence now survive restart. A strict bounded
service/client adapter returns a receipt only after durable persistence and
provides handle/account lookups that verify the exact claim-bound receipt
against a separately pinned registry key. Historical snapshots remain readable
but lookup fails closed when they predate persisted claim evidence. Handle rename and reuse policy is
deliberately deferred. A normalized local handle is not globally unique until a
deployed registry returns a receipt that the daemon verifies and caches.

| Area | Implemented in this branch | Still requires external evidence or work |
|---|---|---|
| G0 prerequisites | Frozen pins, fixtures, georelay policy, BlueR/proxy/keyring probes | Named-adapter dual-role capture; Omarchy keyring/service lifecycle matrix; live system-Tor/Arti observations |
| G1 Nostr product | Sealed providers/records and explicit migration; four independent identity roots; strict event/envelope/relay/pool/georelay/mailbox/outbox code; versioned IPC; CLI/TUI; daemon relay actor, subscriptions, publish/receive, reload and restart tests | Pinned iOS/Android live chat/presence/private delivery; real relay/proxy gate; target-host keyring lifecycle; TUI remains line-input rather than a ratatui/crossterm raw-event loop |
| G1 account foundation | Distinct, provisionally co-resident sealed account/recovery roots; stable account/device IDs; strict candidate handles/display names; signed local device/profile binding; restart-stable daemon status that labels configured handles `local-only`; authoritative uniqueness/CAS/idempotency state with sealed restart-safe persistence; durable accepted-claim evidence; exact claim-bound, pinned-key global/per-account hash-chained receipts; verified handle/account lookup over a bounded versioned service/client adapter; rename/reuse policy explicitly deferred | Off-device recovery custody; registry deployment and daemon integration; sealed verified freshness cache; device enrollment/revocation/recovery; key-transparency evidence; no live claim |
| G2 public mesh (retained, deferred) | Bounded v1/v2 packet, compression/signing, announce, fragmentation, GCS/request-sync, presence/routing/dedup/source-route logic, six-hour sealed public archive, 15-minute transient caches, bounded RSR backfill selection, production BlueR GATT/advertise/discover/read/write runtime, duplicate-link and adapter-loss state | Daemon-level mesh orchestration; real BlueZ policy/adapter qualification; pinned Swift/Android one/two-hop corpus and live tests; long-running radio convergence |
| G3 private mesh (retained, deferred) | Exact captured Noise XX transcript/transport; replay/reorder/rekey state; authenticated pins; private messages/receipts/dedup; favorite/challenge/vouch controls; sealed favorites/verification/blocks; deterministic mesh/Nostr/queue route policy; transport-attempt history; ANSI QR output through packaged `qrencode` | Live Noise/QR/favorite exchange against pinned phones; daemon-level mesh session/outbox orchestration; scanned-QR input workflow |
| G4 courier/bridge (retained, deferred) | Exact pinned courier v1/v2/day-tag captures; prekey grace; sealed quotas/deposits/spray/handover; kind-1401 relay drops; carrier type 28 bounded TLVs; signed rendezvous `r`/optional `m`; bridge identity domain, loop guard and metrics; persisted public/courier restart tests | Exact upstream carrier golden capture; daemon bridge orchestration/health gating; pinned iOS live courier and bridge tests; two-hour multi-node backfill rig |
| G5 hardening/release | Cryptographic panic transaction and proof; persisted block state; hardened user unit; desktop entry; shell completions; man pages; tagged/`-git` PKGBUILDs; Quattro widget; legacy Waybar example; security/privacy/install docs; nightly parser fuzz workflow; size-optimized release profile and hard installed-binary aggregate ceiling | Omarchy v4.0.1 validation/install/upgrade/removal; Secret Service panic test; package archive checksum after an authorized tag; clean-chroot/namcap; widget live validation; 72-hour soak and signed release evidence |

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
- No central registry is deployed or connected to the daemon, no handle has
  live global-uniqueness evidence, and no key-transparency claim is complete.
- Workspaces, membership, permissions, channels, threads, reactions, search,
  files, and native notifications are future text-collaboration work.
