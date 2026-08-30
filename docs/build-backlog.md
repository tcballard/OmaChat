# OmaChat build backlog

Status: proposed issue/PR plan

Derived from: [`upstream-validation.md`](upstream-validation.md)

Planning date: 2026-08-30

## Delivery rules

- One issue maps to one reviewable pull request unless the issue explicitly says it is a bootstrap or test-run exception.
- Every PR names its upstream compatibility pin and includes tests or captured evidence for changed behavior.
- Protocol and cryptographic PRs must consume committed cross-implementation fixtures; self-generated Rust round trips are necessary but not sufficient.
- Android is an acceptance peer only for features present in Android v2.0.1. Courier, prekey, RSR, and current bridge acceptance use Swift/iOS.
- No PR may silently adopt upstream `main`; pin changes require a dedicated drift review.
- No merge is implied by this document. Opening issues, pushing branches, and merging remain separate repository actions.

Suggested labels: `gate:g0` through `gate:g5`, `area:proto`, `area:crypto`, `area:nostr`, `area:ble`, `area:store`, `area:daemon`, `area:tui`, `area:packaging`, `type:spike`, `type:test`, and `blocked`.

## Gate summary

| Gate | Product result | Blocking issues |
|---|---|---|
| G0 | Source, legal, hardware, key-storage, relay, and proxy risks closed | `OC-001`–`OC-009` |
| G1 | Usable Nostr-only daemon, CLI, and TUI | `OC-010`–`OC-026` |
| G2 | Public BLE mesh and gossip | `OC-027`–`OC-041` |
| G3 | Live private messaging and fallback | `OC-042`–`OC-049` |
| G4 | Courier infrastructure and current bridge paths | `OC-050`–`OC-057` |
| G5 | Installable, documented, hardened release | `OC-058`–`OC-064` |

## Bootstrap exception

### BOOT-000 — Create the base branch

- **Type:** repository bootstrap; not PR-able because no target branch exists.
- **Current state:** the GitHub repository has no commits and its local clone reports no valid `origin/main`.
- **Action:** the owner creates the initial `main` commit, preferably a minimal `README.md` plus chosen license, or explicitly authorizes a bootstrap commit.
- **Done when:** `origin/main` exists, branch protection can be configured, and all following work can use pull requests.
- **Excludes:** project scaffolding, protocol design, or feature code.

## G0 — Source and feasibility

### OC-001 — Freeze the compatibility and license policy

- **Depends on:** `BOOT-000`.
- **Deliverable:** `docs/compatibility-profile.md` recording Swift v1.7.1, Android v2.0.1, Omarchy v4.0.1, whitepaper hash, authority order, Android clean-room restriction, and chosen OmaChat license.
- **Acceptance:** `omachat --version` output contract is documented; every pin is an immutable commit; Android's README/license conflict is called out; name status is marked provisional.
- **Excludes:** generated vectors and dependency selection.

### OC-002 — Scaffold the Rust workspace and CI

- **Depends on:** `BOOT-000`, `OC-001`.
- **Deliverable:** the eight-crate workspace skeleton, locked toolchain/MSRV policy, formatting, clippy, unit-test, docs, dependency-audit, and minimal-deny CI jobs.
- **Acceptance:** a clean checkout passes all jobs; each binary prints its own version plus compatibility-profile IDs; no protocol implementation is stubbed with guessed constants.
- **Excludes:** release packaging and runtime behavior.

### OC-003 — Define conformance fixture provenance

- **Depends on:** `OC-001`, `OC-002`.
- **Deliverable:** `conformance/README.md`, a machine-readable fixture manifest, source-commit/build metadata, input/secret handling rules, and a fixture loader used by Rust tests.
- **Acceptance:** one harmless sample fixture proves schema validation; fixtures distinguish public committed inputs from test-only private inputs; regeneration steps are documented.
- **Excludes:** real protocol vectors.

### OC-004 — Extract the release-critical crypto vectors

- **Depends on:** `OC-003`.
- **Deliverable:** captured Swift fixtures for geohash identity, active NIP-13 creation/acceptance policy, 33-byte compressed ECDH point, HKDF key, full 14→13→1059 envelope, Noise XX transcript/transport counters, courier v1, courier v2/prekey, and day tags; Android fixtures for its supported Nostr shapes.
- **Acceptance:** fixture bytes reproduce twice from pinned source builds; secrets are synthetic; manifests identify every intermediate representation and endianness.
- **Excludes:** Rust crypto implementation.

### OC-005 — Freeze georelay data and compatibility policy

- **Depends on:** `OC-001`.
- **Deliverable:** content-addressed Swift and Android relay-directory snapshots, deterministic nearest-five implementations used only as an oracle, and an ADR selecting OmaChat's bounded union/replacement policy.
- **Acceptance:** expected relay sets are recorded for at least two distant geohashes plus tie cases; update cadence and maximum simultaneous geo relays are explicit; mutable `main` URLs are not runtime authority.
- **Excludes:** WebSocket connections.

### OC-006 — Qualify BlueR dual-role hardware

- **Depends on:** `OC-001`.
- **Deliverable:** a disposable probe and report for the target internal adapter and one named USB adapter covering supported states, advertising instances, local GATT, scan+connectable advertise, inbound/outbound links, MTU observations, and EATT behavior.
- **Acceptance:** service/characteristic discovery and bidirectional bytes work concurrently for 30 minutes; failures produce actionable capability output; no root, custom polkit rule, or extended advertising is assumed.
- **Excludes:** production mesh manager.

### OC-007 — Prove key-storage and user-service lifecycle

- **Depends on:** `OC-002`.
- **Deliverable:** a minimal Secret Service/file-fallback probe and hardened test user service using `RuntimeDirectory=omachat`.
- **Acceptance:** graphical login, locked keyring, logout with and without linger, boot before keyring unlock, state-dir creation, and socket permissions are recorded on Omarchy v4.0.1; active storage mode is queryable.
- **Excludes:** production encrypted records and panic wipe.

### OC-008 — Prove proxy and Tor transport semantics

- **Depends on:** `OC-002`.
- **Deliverable:** WebSocket-over-direct and WebSocket-over-SOCKS5 transport prototype with remote DNS; separately feature-gated Arti bootstrap prototype.
- **Acceptance:** a controlled DNS test shows system-Tor mode does not resolve relay hostnames locally; TLS/SNI and reconnect work; Arti state/shutdown behavior is documented.
- **Excludes:** relay pool and user-facing Tor claims.

### OC-009 — Close G0 and re-estimate

- **Depends on:** `OC-001`–`OC-008`.
- **Deliverable:** a short gate report linking all evidence, recording retained risks, and replacing the draft's 225–350 hour estimate with work informed by the spikes.
- **Acceptance:** no red unknown remains for license provenance, NIP-13 policy, Nostr shared-point bytes, geo relay selection, dual-role BLE, keyring/user-service lifecycle, or remote-DNS proxying.
- **Excludes:** waiving failed gates to preserve the original schedule.

## G1 — Nostr-only product

### OC-010 — Implement master-key providers and sealed records

- **Depends on:** `OC-007`, `OC-009`.
- **Deliverable:** Secret Service provider, mode-0600 file provider, versioned XChaCha20-Poly1305 record envelope, atomic writes, and zeroized key wrappers in `omachat-store`.
- **Acceptance:** fallback is selected only on first run or explicit migration; a previously selected but locked/unavailable Secret Service fails closed instead of silently creating a new key or identity; tampering fails closed; status reports provider type without key material; crash-recovery tests cover interrupted writes.
- **Excludes:** domain-specific outbox/courier schemas and panic.

### OC-011 — Implement long-term and derived identities

- **Depends on:** `OC-004`, `OC-010`.
- **Deliverable:** Noise static, Ed25519 signing, separate Nostr device seed, peer fingerprint/ID, per-geohash and `bridge|cell` secp256k1 derivation.
- **Acceptance:** all identity fixtures pass, invalid secp scalars retry exactly, fallback derivation is tested, and regeneration happens only after explicit identity absence.
- **Excludes:** favorites and QR.

### OC-012 — Implement strict geohash codec

- **Depends on:** `OC-002`.
- **Deliverable:** standard base32 encoder/decoder, precision validation, normalization rules, cell center calculation, and fuzz/property tests.
- **Acceptance:** matches pinned mobile constants and public reference cases; invalid alphabet/precision fails predictably; no location acquisition is introduced.
- **Excludes:** city lookup table and relay selection.

### OC-013 — Implement canonical Nostr events and signatures

- **Depends on:** `OC-004`, `OC-011`.
- **Deliverable:** strict NIP-01 event ID serialization, x-only key handling, Schnorr sign/verify, size/time/tag limits, and relay frame codec.
- **Acceptance:** canonical JSON/event-ID fixtures pass; duplicate/unknown fields follow documented policy; malformed hostile events never panic.
- **Excludes:** proprietary encryption and relay sockets.

### OC-014 — Implement proprietary private-envelope crypto

- **Depends on:** `OC-004`, `OC-013`.
- **Deliverable:** compressed-point ECDH, HKDF, `v2:` XChaCha framing, kinds 14/13/1059 creation and strict opening.
- **Acceptance:** every intermediate Swift vector passes; emitted Swift shape decrypts on pinned iOS; Android's released one-`p` inner shape and older randomized dates are accepted; ordinary NIP-44 helpers are not used.
- **Excludes:** relay subscriptions and mailbox policy.

### OC-015 — Implement one relay connection

- **Depends on:** `OC-008`, `OC-013`.
- **Deliverable:** one NIP-01 WebSocket connection with direct/SOCKS stream injection, REQ/EVENT/EOSE/OK/CLOSE handling, bounded queues, ping/timeout, and clean cancellation.
- **Acceptance:** hermetic relay tests cover publish acknowledgements, subscriptions, reconnect, backpressure, malformed frames, event-size cap, and auth-required rejection.
- **Excludes:** multi-relay policy.

### OC-016 — Implement the relay pool

- **Depends on:** `OC-015`.
- **Deliverable:** connection-per-relay pool, jittered exponential backoff, health state, deduplicated subscriptions/events, publish-to-healthy and configurable acknowledgement threshold.
- **Acceptance:** deterministic-clock tests cover flapping relays and quorum outcomes; failure of one relay cannot block shutdown or healthy relays.
- **Excludes:** geo relay selection and product routing.

### OC-017 — Implement geo-relay selection

- **Depends on:** `OC-005`, `OC-012`, `OC-016`.
- **Deliverable:** runtime selection from the pinned snapshot/profile, bounded de-duplicated Swift/Android-compatible set, health fallback, and status diagnostics.
- **Acceptance:** all frozen cell/tie fixtures pass; profile/hash appear in status; user overrides have explicit supplement-versus-replace semantics.
- **Excludes:** geohash event handling.

### OC-018 — Implement geohash chat and presence

- **Depends on:** `OC-011`–`OC-013`, `OC-017`.
- **Deliverable:** kind-20000 chat, kind-20001 presence, `g/n/t/nonce` validation, NIP-13 policy from captured evidence, subscriptions, dedup, and local blocking.
- **Acceptance:** signed chat and presence work both ways with pinned iOS and Android; invalid signatures/tags are rejected; two cells can be joined concurrently without identity linkage.
- **Excludes:** private messages and mesh bridging.

### OC-019 — Implement private Nostr mailbox and DMs

- **Depends on:** `OC-014`, `OC-016`.
- **Deliverable:** private relay profile, outer-`p` subscription, compatible lookback policy, envelope open/verify/dedup, and send/publish result model.
- **Acceptance:** iOS and Android both decrypt OmaChat output; OmaChat accepts both released shapes; offline-then-online delivery succeeds across the compatibility lookback; blocked sender content is hidden after authenticated open.
- **Excludes:** favorites negotiation and mesh fallback.

### OC-020 — Implement Nostr outbox persistence

- **Depends on:** `OC-010`, `OC-019`.
- **Deliverable:** sealed per-peer queue, 100-message/24-hour bounds, attempt accounting, acknowledgement clearing, and visible terminal failure state.
- **Acceptance:** restart/reconnect tests preserve ordering and caps; eight failed attempts surface `failed`; plaintext never appears in backing files.
- **Excludes:** BLE reconnect triggers and read receipts.

### OC-021 — Define and implement IPC v1 framing

- **Depends on:** `OC-002`, `OC-010`.
- **Deliverable:** versioned JSONL request/response/event types, bounded decoder, hello negotiation, correlation IDs, subscriptions, and mode-0600 socket server under systemd runtime directory.
- **Acceptance:** malformed/oversized lines cannot exhaust the daemon; slow subscribers are bounded/disconnected; reconnect and version mismatch are tested.
- **Excludes:** all command handlers beyond health/status fixtures.

### OC-022 — Implement `omachat-ctl`

- **Depends on:** `OC-021`.
- **Deliverable:** hello, status, fingerprint, join/leave, send, and deterministic `status --json` contracts with meaningful exit codes.
- **Acceptance:** shell tests cover absent daemon, incompatible protocol, timeout, JSON stability, and no color when redirected.
- **Excludes:** panic and QR verification.

### OC-023 — Implement the TUI shell

- **Depends on:** `OC-021`.
- **Deliverable:** ANSI-16 ratatui layout, attach/reconnect, conversation sidebar, scroll/input modes, status bar, detach behavior, and terminal restoration.
- **Acceptance:** snapshot tests use 80×24 and narrow layouts; no truecolor escapes; crashes/signals restore the terminal; quitting detaches without stopping the daemon.
- **Excludes:** final command set and QR.

### OC-024 — Add Nostr messaging to the TUI

- **Depends on:** `OC-018`–`OC-020`, `OC-023`.
- **Deliverable:** geohash and DM views, send/join/who/block commands, unread state, delivery glyphs, errors, and one-time transport-security notice.
- **Acceptance:** a user can complete the G1 chat/DM scenarios without `ctl`; delivery state survives TUI restart because it comes from the daemon.
- **Excludes:** mesh peers, favorites, and courier glyph behavior.

### OC-025 — Assemble the Nostr-only daemon

- **Depends on:** `OC-016`–`OC-022`.
- **Deliverable:** config loading, Nostr router, identity/store lifecycle, IPC handlers/events, clean shutdown, and SIGHUP reload for Nostr/channels.
- **Acceptance:** daemon restart preserves identity/outbox; invalid hot reload leaves prior config active; TUI/ctl may attach concurrently; no protocol state lives in clients.
- **Excludes:** BLE transport.

### OC-026 — Run and record the G1 conformance gate

- **Depends on:** `OC-024`, `OC-025`.
- **Deliverable:** reproducible report and sanitized logs for two geohashes, both mobile platforms, private send/receive, offline mailbox, reconnect, proxy mode, and TUI detach.
- **Acceptance:** every G1 row in `upstream-validation.md` is green or the gate remains open; failures become linked issues rather than prose waivers.
- **Excludes:** public release packaging.

## G2 — Public BLE mesh and gossip

### OC-027 — Implement the bounded packet codec

- **Depends on:** `OC-003`, `OC-009`.
- **Deliverable:** strict v1/v2 header/parser, full pinned outer enum, flags, recipient, source route, RSR, timestamp, signature fields, and safe unknown-type policy.
- **Acceptance:** Swift/Android golden bytes round-trip canonically; every length calculation is checked; truncated/oversized input returns typed errors without allocation spikes.
- **Excludes:** compression, signing, and padding policy.

### OC-028 — Add packet compression, canonical signing, and padding

- **Depends on:** `OC-027`.
- **Deliverable:** exact zlib heuristic/bounds, canonical signature bytes and verification, and BLE Noise-only padding policy.
- **Acceptance:** compressed and uncompressed fixtures pass; decompression-bomb corpus stays within resource bounds; TTL mutation preserves signature validity while other signed changes fail.
- **Excludes:** relay logic.

### OC-029 — Implement announce and authenticated-state codecs

- **Depends on:** `OC-027`, `OC-011`.
- **Deliverable:** announce TLVs, minimal little-endian capabilities, bridge hints, neighbor limits, and authenticated-peer-state inner record.
- **Acceptance:** fixtures pass; unknown TLVs skip safely; public announce never upgrades a pinned key without authenticated Noise state.
- **Excludes:** presence timers and Noise session establishment.

### OC-030 — Implement fragmentation and reassembly

- **Depends on:** `OC-027`.
- **Deliverable:** dynamic chunk planner, fragment codec, 128-assembly manager, 30-second expiry, per-assembly bounds, global memory budget, duplicate/conflict handling.
- **Acceptance:** shuffled, duplicate, missing, conflicting, and over-budget simulations pass; multiple link limits match fixtures; expired state is reclaimed.
- **Excludes:** file/media UI.

### OC-031 — Implement GCS and request-sync codecs

- **Depends on:** `OC-027`.
- **Deliverable:** packet IDs, exact mapping/Golomb-Rice bits, request TLVs, filter caps, and RSR request-window token model.
- **Acceptance:** known-set Swift filter bytes match; malformed unary runs/TLVs are bounded; false-positive statistical test is within tolerance.
- **Excludes:** cache scheduling and radio transmission.

### OC-032 — Add continuous fuzz and property suites

- **Depends on:** `OC-027`–`OC-031`.
- **Deliverable:** cargo-fuzz targets for packet, announce, fragment, request-sync, Noise-inner, and Nostr-envelope parsers; property tests for canonical round trips.
- **Acceptance:** CI smoke fuzzing runs on every PR; scheduled jobs retain crash artifacts; a seeded malformed corpus covers every optional branch and size limit.
- **Excludes:** claiming a time-limited fuzz run proves absence of vulnerabilities.

### OC-033 — Implement the BlueR peripheral role

- **Depends on:** `OC-006`, `OC-028`.
- **Deliverable:** mainnet local GATT service/characteristic, service-UUID advertisement, read/write/notify handling, per-link outbound sizing, and structured diagnostics.
- **Acceptance:** pinned phone discovers, writes, reads, subscribes, and receives notifications without root; registration/restart failures clean up stale objects.
- **Excludes:** scanning and connection policy.

### OC-034 — Implement the BlueR central role

- **Depends on:** `OC-006`, `OC-028`.
- **Deliverable:** service-filtered scanning, optional Android peer-ID service-data parser, connection, service discovery, write-mode selection, notifications, and reconnect cancellation.
- **Acceptance:** both pinned phones connect and exchange raw framed packets; absent/malformed optional service data is handled safely; no RSSI gate is imposed.
- **Excludes:** multi-peer scheduling.

### OC-035 — Implement dual-role connection management

- **Depends on:** `OC-033`, `OC-034`.
- **Deliverable:** simultaneous central/peripheral ownership, duplicate physical-link resolution, ingress identity, per-peer link set, backoff, adapter-loss recovery, and capability status.
- **Acceptance:** multiple inbound/outbound links run for 30 minutes on qualified hardware; adapter reset recovers; shutdown unregisters advertisements/GATT and cancels connections.
- **Excludes:** packet routing semantics.

### OC-036 — Implement mesh presence and peer reachability

- **Depends on:** `OC-029`, `OC-035`.
- **Deliverable:** signed announce scheduling, isolated/connected backoff, 60-second reachability, direct-neighbor publication, leave handling, and peer events to IPC.
- **Acceptance:** timing tests use a deterministic clock; blank nickname interoperates; unverified announce data remains explicitly untrusted.
- **Excludes:** source routing and favorites.

### OC-037 — Implement relay, dedup, jitter, and fanout

- **Depends on:** `OC-028`, `OC-035`.
- **Deliverable:** TTL origin/clamps, 1000-entry/5-minute dedup, cancel-on-duplicate jitter, split horizon, full-fanout exceptions, directed jitter classes, and local-link deterministic subsetting.
- **Acceptance:** lossy N-node simulations prove termination, duplicate suppression, dense/sparse TTL behavior, ingress exclusion, and request-sync non-relay.
- **Excludes:** topology source routes.

### OC-038 — Implement topology and source routes

- **Depends on:** `OC-036`, `OC-037`.
- **Deliverable:** 60-second topology map, fresh bidirectional BFS routes, route encoding/forwarding, route failure detection, and flood fallback.
- **Acceptance:** simulations cover stale/asymmetric edges, broken next hop, loops, route cap, and fallback delivery without duplicate explosion.
- **Excludes:** application delivery acknowledgement.

### OC-039 — Implement public mesh chat and caches

- **Depends on:** `OC-030`, `OC-036`–`OC-038`.
- **Deliverable:** public message creation/verification, router integration, 1000-entry sealed public archive, separate bounded transient stores, local history, and IPC/TUI events.
- **Acceptance:** public text works both ways with pinned iOS/Android across one and two hops; invalid signatures are hidden and never archived; restart retains only intended public history.
- **Excludes:** private Noise messaging.

### OC-040 — Implement live gossip synchronization

- **Depends on:** `OC-031`, `OC-039`.
- **Deliverable:** per-type schedules/windows, direct TTL0 requests, registered 30-second RSR responses, missing-item selection/chunking, and restart-safe public history.
- **Acceptance:** simulated peers converge under loss; unsolicited RSR is rejected; a phone missing a known interval backfills; filters remain within 400 bytes.
- **Excludes:** two-hour soak gate execution.

### OC-041 — Run and record the G2 conformance gate

- **Depends on:** `OC-032`, `OC-040`.
- **Deliverable:** packet captures and report for both phones, dual role, one/two-hop public chat, compression, fragmentation, link-local sync, adapter recovery, and resource limits.
- **Acceptance:** all G2 criteria are green and fuzz/property CI is stable; deviations are explicitly classified as compatibility bugs or intentional local policy.
- **Excludes:** private DMs.

## G3 — Live private messaging and fallback

### OC-042 — Implement Noise XX handshakes

- **Depends on:** `OC-004`, `OC-028`, `OC-035`.
- **Deliverable:** XX state machine, empty prologue, GATT packet mapping, lower-peer-ID crossed-initiation rule, timeouts, recovery, and session identity binding.
- **Acceptance:** captured transcripts match; simultaneous initiation converges deterministically; malformed/failing handshakes do not pin attacker-provided state.
- **Excludes:** application ciphertext transport.

### OC-043 — Implement stateless Noise transport and rekey

- **Depends on:** `OC-042`.
- **Deliverable:** explicit 4-byte BE counter, Noise nonce mapping, 1024-window replay protection, counter exhaustion, session lifetime, idle/rekey policy, and peer-initiated rehandshake.
- **Acceptance:** ordered/reordered/duplicate/stale/exhaustion vectors pass against Swift; Android rekey initiation is accepted; keys and old replay state are zeroized on replacement.
- **Excludes:** private message semantics.

### OC-044 — Pin authenticated peer state

- **Depends on:** `OC-029`, `OC-043`.
- **Deliverable:** authenticated-state exchange, signing-key/capability pin/update rules, mismatch handling, persistence, and security events.
- **Acceptance:** copied self-signed announce cannot replace a pinned key; first contact completes only after Noise-authenticated state; mismatch fails closed and is visible.
- **Excludes:** user verification/favorites.

### OC-045 — Implement private messages and receipts

- **Depends on:** `OC-043`, `OC-044`.
- **Deliverable:** inner typed payload framing for private text, delivered, and read receipts; message IDs/dedup; BLE send/receive; IPC delivery transitions.
- **Acceptance:** DMs and receipts work both ways with both pinned phones; relays see only Noise ciphertext; duplicates do not create duplicate UI messages.
- **Excludes:** files, groups, and voice UI.

### OC-046 — Implement favorites, verification, and blocking

- **Depends on:** `OC-011`, `OC-044`, `OC-045`.
- **Deliverable:** full-Noise-key favorite records, mutual favorite/Nostr-key exchange, ANSI QR fingerprint, challenge/response/vouch handling required by the pin, and local block rules.
- **Acceptance:** favorite is permitted only for a mesh-bound peer; geohash `/fav` is rejected; QR verifies the expected key; blocked public/courier content follows upstream semantics.
- **Excludes:** inventing out-of-band geohash identity bootstrap.

### OC-047 — Connect the sender outbox to mesh lifecycle

- **Depends on:** `OC-020`, `OC-045`.
- **Deliverable:** mesh reconnect triggers, delivery/read clearing, transport-attempt history, and consistent failure state across Nostr/mesh attempts.
- **Acceptance:** restart and alternating transport tests preserve caps/order; a successful receipt clears exactly once; eight failures are visible in CLI/TUI.
- **Excludes:** courier deposits.

### OC-048 — Implement mesh-first private routing with Nostr fallback

- **Depends on:** `OC-019`, `OC-046`, `OC-047`.
- **Deliverable:** deterministic route decision, live-mesh preference, mutual-favorite Nostr fallback, timeout/error semantics, and transport telemetry without identifiers.
- **Acceptance:** tests cover mesh success, mesh loss then Nostr, non-mutual favorite rejection, duplicate cross-transport delivery, and reconnect acknowledgement.
- **Excludes:** courier fallback.

### OC-049 — Run and record the G3 conformance gate

- **Depends on:** `OC-048`.
- **Deliverable:** report for XX collision/reorder/rekey, authenticated peer state, DM/receipts, favorite/QR/block, outbox restart, and mesh→Nostr fallback against both phones.
- **Acceptance:** every G3 criterion is green; private plaintext is absent from packet captures and sealed-state inspection.
- **Excludes:** courier claims.

## G4 — Courier infrastructure and current bridge paths

### OC-050 — Implement courier envelope, day tags, and v1 seals

- **Depends on:** `OC-004`, `OC-027`, `OC-043`.
- **Deliverable:** strict courier TLVs/limits, ±1-day tag matching, Noise-X `bitchat-courier-v1` seal/open, authenticated sender inner payload, and receiver dedup.
- **Acceptance:** Swift v1 vectors and live delayed delivery pass; expired/oversized/blocked/duplicate envelopes are handled exactly; docs state v1's lack of forward secrecy.
- **Excludes:** one-time prekeys, quotas, and spraying.

### OC-051 — Implement signed prekeys and courier v2

- **Depends on:** `OC-050`.
- **Deliverable:** prekey generation/storage, signed bundle outer type `24`, bundle sync/age/rebroadcast, v2 Noise-X prologue/BE ID, one-time consumption, 48-hour grace, and deletion.
- **Acceptance:** Swift/iOS vectors and live courier-v2 delivery pass; replay uses grace key without second consumption; unavailable prekey cleanly falls back to v1 policy.
- **Excludes:** Android acceptance, which the pinned release cannot provide.

### OC-052 — Implement courier persistence, quotas, and deposits

- **Depends on:** `OC-010`, `OC-046`, `OC-051`.
- **Deliverable:** sealed 40-slot pool, 20 verified-tier bound, 5 favorite/2 verified quotas, 16 KiB/24-hour caps, eviction order, deposit authorization, up-to-three courier tracking, and metrics.
- **Acceptance:** property tests prove verified traffic cannot crowd out favorite reservations; restart preserves budgets/carriers; invalid signatures never consume verified quota.
- **Excludes:** courier-to-courier spraying and handover.

### OC-053 — Implement spray-and-wait and handover

- **Depends on:** `OC-036`, `OC-038`, `OC-052`.
- **Deliverable:** copy budget 4/cap 8, half-budget transfer, distinct spray history, direct-recipient delivery/removal, relayed-recipient directed copy/retain, and ten-minute remote cooldown.
- **Acceptance:** simulated encounters conserve copy budget, survive restart, prevent duplicate recipients, and implement direct versus relayed announce semantics.
- **Excludes:** relay mailbox drop.

### OC-054 — Implement Nostr relay courier drops

- **Depends on:** `OC-016`, `OC-050`, `OC-053`.
- **Deliverable:** kind-1401 publish/subscribe, rotating `x`, `expiration`, base64 envelope content, throwaway signer, lookback, bounds, and dedup.
- **Acceptance:** pinned Swift peer deposits and opens through a hermetic/public relay test; true identity key is not used as the outer signer; stale tags and expired drops are rejected.
- **Excludes:** carrier/rendezvous bridge.

### OC-055 — Implement Nostr carrier and rendezvous bridging

- **Depends on:** `OC-017`, `OC-039`, `OC-054`.
- **Deliverable:** outer type `28` carrier TLVs/directions/16 KiB cap, `r` rendezvous chat/presence, optional `m`, bridge identity/capability announce, loop prevention, and bridge metrics.
- **Acceptance:** mesh↔Nostr public traffic works against pinned Swift bridge behavior without loops or identity collapse; malformed carrier events stay bounded; bridge claim is enabled only when this path is healthy.
- **Excludes:** generic IRC/Matrix bridges.

### OC-056 — Prove persisted gossip backfill

- **Depends on:** `OC-040`, `OC-053`.
- **Deliverable:** deterministic long-window integration rig and disk/restart assertions for public archive plus courier state.
- **Acceptance:** a phone missing two hours of public messages backfills after OmaChat restart; six-hour/15-minute windows and separate stores are enforced; no private plaintext is archived.
- **Excludes:** 72-hour release soak.

### OC-057 — Run and record the G4 conformance gate

- **Depends on:** `OC-051`–`OC-056`.
- **Deliverable:** iOS/Swift report for courier v1/v2, prekey redelivery, deposits/sprays/handover, relay drop, two-hour gossip, and carrier/rendezvous bridge.
- **Acceptance:** every G4 row is green; if `OC-055` is deferred, all full-bridge product language is removed before the gate can close.
- **Excludes:** treating Android's absent courier surface as a failure.

## G5 — Packaging, hardening, and release

### OC-058 — Implement cryptographic panic erase

- **Depends on:** `OC-010`, `OC-052`.
- **Deliverable:** daemon transaction that stops transports, rejects new clients, zeroizes memory, deletes Secret Service/file master keys, unlinks state, syncs metadata, and regenerates only on next start; ctl/TUI confirmations.
- **Acceptance:** previously captured ciphertext cannot decrypt after panic; all upstream-listed state is absent on restart; tests document CoW/snapshot/SSD/network-copy limits; no claim of guaranteed physical overwrite.
- **Excludes:** remote deletion from relays/peers.

### OC-059 — Ship and verify the hardened user service

- **Depends on:** `OC-007`, `OC-025`, `OC-058`.
- **Deliverable:** `omachatd.service` with runtime/state paths and applicable systemd hardening, plus explicit linger setup/removal documentation.
- **Acceptance:** clean Omarchy v4.0.1 install starts in-session; optional owner-enabled linger works across logout/reboot; suspend limitations are documented; service receives only intended writable paths.
- **Excludes:** silently enabling linger in package scripts.

### OC-060 — Add desktop entry, completions, and man pages

- **Depends on:** `OC-022`, `OC-024`, `OC-059`.
- **Deliverable:** terminal `.desktop` entry, shell completions, `omachat(1)`, `omachat-ctl(1)`, `omachatd(8)`, and `omachat-protocol(7)`.
- **Acceptance:** launcher opens the TUI on clean Omarchy; every CLI option/IPC stability promise is documented; man-page checks run in CI.
- **Excludes:** modifying user Hyprland configuration.

### OC-061 — Package reproducible Arch artifacts

- **Depends on:** `OC-059`, `OC-060`.
- **Deliverable:** release tarball/checksums, PKGBUILDs for tagged and `-git` packages, install layout, dependencies, user service, desktop/man assets, and local clean-chroot build recipe.
- **Acceptance:** package builds in clean Arch chroot, installs/upgrades/removes without modifying user config, and passes namcap or documented exceptions; no broad polkit rule is shipped.
- **Excludes:** publishing to AUR until owner authorization.

### OC-062 — Add an optional Omarchy Quattro widget

- **Depends on:** `OC-022`, `OC-060`.
- **Deliverable:** separately reviewable, validated third-party `bar-widget` plugin with bounded asynchronous status polling and install/enable instructions; legacy Waybar snippet in a clearly labeled directory.
- **Acceptance:** `omarchy plugin validate` passes on v4.0.1; daemon absence/timeouts cannot block or crash the shell; widget contains no install hook or privilege request.
- **Excludes:** automatic enablement and edits to `shell.json`.

### OC-063 — Publish security, privacy, and compatibility documentation

- **Depends on:** `OC-001`, `OC-055`, `OC-058`.
- **Deliverable:** README front matter, `SECURITY.md`, compatibility table, threat/metadata limits, key-storage mode, courier v1/v2 distinction, panic limits, “powered and awake” wording, and bridge feature gating.
- **Acceptance:** every material caveat in `upstream-validation.md` is represented; no secure-enclave, physical-wipe, standard-Nostr, blanket Android, or unconditional 24/7 claim remains.
- **Excludes:** legal advice or unsupported name clearance.

### OC-064 — Run release conformance and 72-hour soak

- **Depends on:** `OC-057`–`OC-063`.
- **Deliverable:** signed release-candidate evidence bundle covering clean install, both mobile peers where supported, adapter reset, relay loss, proxy mode, restart, panic, resource metrics, cache convergence, and 72-hour daemon run.
- **Acceptance:** zero panics, unbounded growth, secret-bearing logs, or unexplained interop failures; all G0–G5 reports are linked; release notes state exact pins and known deviations.
- **Excludes:** merging, tagging, AUR publishing, or announcement without owner approval.

## Critical dependency spine

The minimum path to a meaningful demo is:

`BOOT-000 → OC-001 → OC-003 → OC-004 → OC-009 → OC-010/011/013/014 → OC-015/016/019 → OC-021/023/025 → OC-026`

The minimum path to the infrastructure thesis is:

`G1 → OC-027/028/035/037/039/040 → G2 → OC-042/043/045/048 → G3 → OC-050/051/052/053/054/055/056 → G4`

The project should stop and revisit scope if G0 cannot prove the 33-byte ECDH representation, stable geo-relay interoperability, or simultaneous BLE roles on named hardware. Those are feasibility facts, not implementation polish.
