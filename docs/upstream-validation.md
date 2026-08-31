# OmaChat upstream validation

Status: completed research baseline

Audit date: 2026-08-30

Applies to: OmaChat implementation specification v0.1-draft

## Verdict

The proposed product shape is viable, but the draft is **not safe to implement unchanged**.

Keep the daemon/TUI/control-client split, Rust/BlueR stack, Nostr-first sequencing, sealed state, text-only UI, AUR distribution, and conformance-first approach. Replace the draft's source hierarchy and several wire, crypto, relay, bridge, Linux-service, and Omarchy assertions before writing protocol code.

The decisive conflict is temporal: the explanatory whitepaper is dated 2026-07-06, while tagged Swift v1.7.1 was released on 2026-07-31 and already implements behavior the whitepaper describes as future work. Tagged code must win.

## Frozen compatibility profile

| Role | Pin | Use |
|---|---|---|
| Canonical implementation | Swift [`v1.7.1`](https://github.com/permissionlesstech/bitchat/releases/tag/v1.7.1), commit [`9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa`](https://github.com/permissionlesstech/bitchat/commit/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa) | Normative wire and behavior |
| Partial compatibility peer | Android [`v2.0.1`](https://github.com/permissionlesstech/bitchat-android/releases/tag/v2.0.1), commit [`93e9594bad3e537b4ec6fd096c0fde7533f22e74`](https://github.com/permissionlesstech/bitchat-android/commit/93e9594bad3e537b4ec6fd096c0fde7533f22e74) | Feature-by-feature acceptance only |
| Explanatory document | [`WHITEPAPER.md`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/WHITEPAPER.md), v2.0 dated 2026-07-06 | Intent and rationale; loses conflicts with code |
| Linux desktop target | Omarchy [`v4.0.1`](https://github.com/basecamp/omarchy/releases/tag/v4.0.1), commit [`13f18b2cb7286fb54f87daf571a031aa6af3d8f0`](https://github.com/basecamp/omarchy/commit/13f18b2cb7286fb54f87daf571a031aa6af3d8f0) | Packaging and lifecycle acceptance |

At the audit date, Swift `main` was 22 commits ahead of v1.7.1 and included peer-ID rotation plus later fail-closed checks. OmaChat releases must print exact upstream commits in `--version`; `main` is monitored for drift and security fixes, never silently mixed into a pinned profile.

## Required authority and licensing corrections

The project must use this precedence:

1. pinned Swift source;
2. whitepaper where it agrees with the pin;
3. pinned Android only for features that release actually implements;
4. prior Linux ports as non-authoritative BlueZ examples only.

Swift's [`LICENSE`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/LICENSE) is the Unlicense. Android v2.0.1 is inconsistent: its [`README`](https://github.com/permissionlesstech/bitchat-android/blob/93e9594bad3e537b4ec6fd096c0fde7533f22e74/README.md) says public domain while its bundled [`LICENSE.md`](https://github.com/permissionlesstech/bitchat-android/blob/93e9594bad3e537b4ec6fd096c0fde7533f22e74/LICENSE.md) contains GPL-3.0. Until upstream resolves that conflict, 0BSD-licensed OmaChat must derive code from the Swift/Unlicense implementation and use Android only for clean-room behavioral comparison and live tests. Do not line-port Kotlin.

The draft's low-effort name search is not legal clearance. Treat “OmaChat” as provisional unless a separate adoption-grade search is completed.

## What is accepted

- `omachatd` owns all state and networking; clients communicate over a mode-0600 Unix socket.
- `omachat` is a render/input client and can detach without changing network behavior.
- `omachat-ctl` is the one-shot automation and status surface.
- Rust/Tokio, pure protocol/crypto crates, BlueR, ratatui, and strict vector/fuzz/live-peer gates are appropriate.
- Text-only v1 is valid, but the parser and relay must recognize the full pinned outer-type surface.
- AUR, systemd user service, `.desktop` entry, man pages, and optional desktop-shell integration are appropriate.
- Secret Service first with a plainly reported 0600-file fallback is honest, provided both modes are tested.

## Release-blocking corrections

### 1. Packet codec, announcements, and fragmentation

The draft omits compression and describes signature coverage incorrectly. The pinned codec has v1 14-byte and v2 16-byte headers; BE integers; Unix-millisecond timestamps; recipient, signature, compression, route, and RSR flags; optional v2 source route; deterministic zlib compression; and bounded decompression. Signing re-encodes a canonical packet with TTL zero, signature absent, and RSR cleared—it does not merely remove one TTL byte. Sources: [`BinaryProtocol.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/localPackages/BitFoundation/Sources/BitFoundation/BinaryProtocol.swift), [`CompressionUtil.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/localPackages/BitFoundation/Sources/BitFoundation/CompressionUtil.swift), and [`BitchatPacket.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/localPackages/BitFoundation/Sources/BitFoundation/BitchatPacket.swift).

Current outer types are:

| Name | Byte | Name | Byte |
|---|---:|---|---:|
| announce | `01` | message | `02` |
| leave | `03` | courier envelope | `04` |
| Noise handshake | `10` | Noise encrypted | `11` |
| fragment | `20` | request sync | `21` |
| file | `22` | board | `23` |
| prekey bundle | `24` | group | `25` |
| ping / pong | `26` / `27` | Nostr carrier | `28` |
| voice | `29` |  |  |

Source: [`MessageType.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/localPackages/BitFoundation/Sources/BitFoundation/MessageType.swift). Only BLE Noise handshake/encrypted packets use the 256/512/1024/2048 padding buckets.

Announcements are `u8 type/u8 length` TLVs: nickname `01`, Noise key `02`, signing key `03`, neighbors `04`, capabilities `05`, bridge geohash `06`. Empty nickname is legal. A self-signed announcement does not authenticate possession of the advertised Noise key, so signing-key/capability pinning must wait for the authenticated-peer-state payload sent inside established Noise. Source: [`Packets.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Protocols/Packets.swift).

Fragment payload is ID `8`, index `u16 BE`, total `u16 BE`, original type `u8`, then bytes. 469 is a default link budget, not a fixed protocol constant. Swift's 1 MiB ordinary limit is per assembly, not global; OmaChat should impose an additional local global-memory limit without lowering the valid per-assembly bound.

### 2. Flood, routing, and gossip sync

`REQUEST_SYNC` is link-local: originate it directly at TTL 0, never flood it, and return requested ordinary packets at TTL 0 with RSR set inside a registered 30-second response window. The draft's “sync packets use full fanout” rule is false for the pinned release. Sources: [`GossipSyncManager.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Sync/GossipSyncManager.swift) and [`RequestSyncManager.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Sync/RequestSyncManager.swift).

Fanout hashes `messageID + "::" + local physical-link UUID`; link IDs are local, so cross-client equality is not a correctness property. Route topology expires after 60 seconds, accepts fresh bidirectional claims, and falls back to flooding on route failure.

The GCS codec is a mandatory vector gate. Packet ID is the first 16 bytes of SHA-256(type, sender, timestamp BE, payload). Filter mapping hashes that ID again, uses the first eight bytes with its high bit cleared, then modulo `M`, mapping zero to one. Target FPR is 1% (normally `P=7`), filter cap 400 bytes, Golomb-Rice encoding is MSB-first, and request TLVs carry P, M, filter, types, since-time, and fragment IDs. Public-message history is the 1000-entry persistent/six-hour store; fragments, files, groups, and prekeys have separate stores and windows. Sources: [`GCSFilter.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Sync/GCSFilter.swift) and [`RequestSyncPacket.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Models/RequestSyncPacket.swift).

### 3. Live Noise XX is not generic sequential Snow transport

The handshake is `Noise_XX_25519_ChaChaPoly_SHA256` with empty prologue. After it, each ciphertext is prefixed by an explicit 4-byte BE counter; the AEAD nonce is the standard four zero bytes plus `u64 LE`. Receivers accept reordering through a 1024-message replay window. Use Snow stateless transport or an exact wrapper and vector-test reorder, replay, stale-window, and exhaustion behavior. Source: [`NoiseProtocol.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Noise/NoiseProtocol.swift).

Crossed initiation chooses the lexicographically lower short peer ID as initiator; the higher yields. Timeouts are 10 seconds initiator, 20 seconds responder, then a 200 ms recovery delay. Android rekeys more aggressively than Swift, so peer-initiated rehandshake must be tolerated.

### 4. Current couriers include one-time prekeys

Courier v1 uses Noise X with prologue `bitchat-courier-v1` and lacks forward secrecy. Swift v1.7.1 also implements courier v2 with signed one-time prekeys, Noise X prologue `bitchat-prekey-v1`, and a `u32 BE` prekey ID. Consumed prekeys remain for a 48-hour delayed-delivery grace before deletion. Implement v1 fallback plus v2 before claiming v1.7.1 courier compatibility. Android v2.0.1 has no courier/prekey implementation, so courier acceptance must use iOS/Swift. Sources: [`NoiseEncryptionService.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Services/NoiseEncryptionService.swift) and [`PrekeyBundle.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/localPackages/BitFoundation/Sources/BitFoundation/PrekeyBundle.swift).

Day tag is first 16 bytes of HMAC-SHA256 with key = recipient Noise static public-key bytes and message = ASCII `bitchat-courier-tag-v1` plus UTC epoch day `u32 BE`; receivers try yesterday/today/tomorrow. This is a rotating routing identifier, not a secret from a peer that retained the public key.

### 5. Proprietary Nostr crypto has a 33-byte ECDH trap

Kinds 14→13→1059 are proprietary and must not call a NIP-44/17/59 library. Encryption is `v2:` plus base64url(nonce24, XChaCha20-Poly1305 ciphertext, tag16), with no AAD. The shared secp256k1 point is serialized in compressed 33-byte form and used directly as HKDF-SHA256 input with empty salt, info `nip44-v2`, and 32-byte output. There is no additional key split. Many Rust ECDH helpers return only a 32-byte x coordinate, so an intermediate-point vector is a hard prerequisite. Source: [`NostrProtocol.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Nostr/NostrProtocol.swift).

Emit Swift's tagless inner kind-14 and ±15-minute randomized wrapper dates. Accept both that shape and Android's one-recipient-`p` inner tag plus up-to-48-hour backdating. Do not use the randomized date range as a validity condition.

### 6. Geohash relay selection is missing from M1

Geohash chat is signed plaintext kind 20000 with required `g`, optional `n`, optional `t=teleport`, and optional NIP-13 nonce. Presence is kind 20001 with only `g` and empty content.

Persona derivation uses a separate 32-byte device seed. HMAC key is the seed; message is geohash UTF-8 plus retry counter `u32 BE`, starting at zero; bridge identity uses `bridge|<cell>`. This is not derived from the Noise static key. Source: [`NostrIdentityBridge.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Nostr/NostrIdentityBridge.swift).

Private mail and geohash rooms use different relay policies. Swift's private defaults are Damus, nos.lol, Primal, and offchain.pub. Android replaces nos.lol with nostr21.com. Geohash rooms select the nearest five entries from a GPS relay directory; the released clients ship different snapshots/tie-break behavior. Vendor a content-addressed directory snapshot and define a bounded cross-client selection policy before M1. An empty fixed `relays` list is not sufficient.

### 7. “Bridge” requires current bridge protocols

A generic router does not produce current upstream bridge compatibility. The pinned Swift release includes Nostr carrier outer type `28`, carrier direction/geohash/event TLVs, rendezvous `r` events, optional mesh ID `m`, announcement bridge capabilities, and relay courier-drop kind 1401 with rotating `x` plus `expiration`. Implement these in the later bridge milestone or remove “24/7 bridge” from claims until they exist.

### 8. BLE constants are known; hardware concurrency is not guaranteed

Mainnet service UUID is `F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C`; characteristic UUID is `A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D`, with notify/write/write-without-response/read. Swift advertises only the service UUID. Android optionally includes its 8-byte peer ID as scan-response service data and accepts peers without it. The old `BC_...` name is obsolete. There is no app-level MTU negotiation. Sources: [`BLEService.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Services/BLE/BLEService.swift) and [`BLERadioController.swift`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/bitchat/Services/BLE/BLERadioController.swift).

BlueR exposes all required roles, but controller/firmware support for concurrent connectable advertising, scanning, local GATT, and inbound/outbound links must be measured. Remove the invented BlueZ 5.66/extended-advertising requirement. Run a preimplementation qualification on the target internal adapter and one known USB adapter. Stock BlueZ uses system-bus policy for these APIs; do not ship a broad polkit rule without a captured denial. Sources frozen on the audit date: [BlueR `57ec7045`](https://github.com/bluez/bluer/tree/57ec704503417a6476bca5d3bb01122686583709), [BlueZ bus policy](https://github.com/bluez/bluez/blob/e8141342284be2a52e16565b96b513ebe1297d84/src/bluetooth.conf), [advertising API](https://github.com/bluez/bluez/blob/e8141342284be2a52e16565b96b513ebe1297d84/doc/org.bluez.LEAdvertisingManager.rst), and [GATT API](https://github.com/bluez/bluez/blob/e8141342284be2a52e16565b96b513ebe1297d84/doc/org.bluez.GattManager.rst).

### 9. Linux lifecycle and Omarchy 4 integration need redesign

Omarchy 4.0.1 ships GNOME Keyring/libsecret; use Secret Service when available, but report it as software key storage and test boot/login/logout-with-linger/locked-keyring fallback. Panic acceptance is cryptographic erasure of the master key plus ciphertext unlinking, not physical overwrite guarantees on CoW/SSD/snapshots or retraction of network copies.

`WantedBy=default.target` is not boot persistence unless the user explicitly enables linger. Packaging must never silently enable it. Use systemd `RuntimeDirectory=omachat`, mode 0700, and a socket below `$RUNTIME_DIRECTORY`; live-test the hardened unit because `ProtectHome=read-only` can otherwise block runtime/state paths.

`tokio-tungstenite` does not dial SOCKS. System Tor needs SOCKS5 remote DNS plus a DNS-leak test; Arti remains a separately tested feature.

Waybar and Walker are stale targets. Omarchy 4 moved the shell to Quickshell. Ship an optional reviewed `bar-widget` plugin; keep Waybar only as Omarchy 3/general-Arch legacy. Quickshell plugins run unsandboxed inside the long-lived shell process, so the plugin must be tiny and nonblocking. Sources: Omarchy's [`Shell Plugins`](https://github.com/basecamp/omarchy/blob/v4.0.1/manual/32-shell-plugins.md) and [`Top Bar`](https://github.com/basecamp/omarchy/blob/v4.0.1/manual/05-the-top-bar.md) manuals.

## Resolved extraction checklist

| # | Area | Validated result | Required proof before trust |
|---:|---|---|---|
| 1 | GATT/ad/MTU | UUIDs/properties resolved; service-only Swift ad; optional Android service data; no protocol MTU | BlueR dual-role capture |
| 2 | Packet/signing | V1/v2, flags, route, compression, canonical signing resolved | Swift/Android golden corpus |
| 3 | Announce | TLVs `01`–`06`; blank nick legal | Golden bytes and authenticated-state fixture |
| 4 | Fragment | ID8/index2/total2/type1; dynamic chunk size | Multiple link-budget vectors |
| 5 | Fanout | Local-link SHA-256 ranking; bit-length subset | Simulated mesh behavior |
| 6 | Noise session | Inner enum, tiebreak/timeouts, explicit counter/replay resolved | Transcript and reorder vectors |
| 7 | Courier X | V1 and prekey-v2 prologues/ID resolved | Swift live/vector tests |
| 8 | Day tag | Public-key HMAC, label, BE day, 16-byte truncation, ±1 day | Fixed date vectors |
| 9 | Nostr crypto | Compressed shared point; empty-salt HKDF; no split | 33-byte point and full envelope vector |
| 10 | Geohash | Kinds/tags/seed derivation resolved | Active NIP-13 policy and identity vectors |
| 11 | Relays | Separate DM lists and nearest-five geo selection | Snapshot hash and compatibility policy |
| 12 | GCS | ID, mapping, P/M, encoding, TLVs, windows, TTL0+RSR resolved | Known-filter and live missing-set vectors |
| 13 | Geohash favorite | Unsupported; relationship requires mesh Noise key | Rejection UI test |
| 14 | Blank nickname | Legal in pinned Swift wire | Live acceptance against both clients |

## Acceptance gates

| Gate | Exit evidence |
|---|---|
| G0 — source/feasibility | License policy; exact pins; fixture provenance; Nostr shared-point vector; geo-relay snapshot/policy; BlueR dual-role matrix; keyring/systemd lifecycle; remote-DNS SOCKS proof |
| G1 — Nostr-only | Geohash chat/presence both ways with iOS and Android in two cells; envelope compatibility; offline mailbox; daemon survives TUI detach |
| G2 — public mesh | Golden codec corpus; strict parser limits; central+peripheral links; public chat with both phones; link-local sync; fuzz/property suites |
| G3 — private mesh | Noise counter/replay tests; authenticated peer state; DM/receipts; mesh-only favorite/QR; outbox and fallback |
| G4 — infrastructure | Courier v1/v2 with iOS; persisted quotas/spray/handover; two-hour gossip backfill; relay drop; current carrier/rendezvous bridge or narrower claim |
| G5 — release | Clean Omarchy 4.0.1 install; validated optional widget; linger docs; hardened service; panic crypto-erasure proof; AUR/man/security artifacts; 72-hour soak |

Merge, issue closure, and compatibility claims require the explicit
prerequisites in [`build-backlog.md`](build-backlog.md) to be closed. Hermetic
implementation may be prepared on an unmerged branch while a live prerequisite
is pending, provided the gated integration remains named and unclaimed. An open
G0 evidence item blocks its dependent integration rather than unrelated work:
OC-006 blocks BLE and G2 radio acceptance, OC-007 blocks production key-storage
acceptance, and OC-008 blocks production relay/Tor acceptance. No crypto, BLE,
gossip, or bridge PR is complete on self-generated Rust tests alone; committed
cross-implementation fixtures and the applicable live gate remain mandatory.
