# OmaChat 0.0.1 compatibility profile

Status: frozen for implementation

Profile ID: `bitchat-swift-v1.7.1`

Product version: `0.0.1`

Profile date: 2026-08-30

Tracks: [OC-001](https://github.com/tcballard/OmaChat/issues/2)

## Purpose

This document is the source and licensing contract for OmaChat 0.0.1. It
defines which upstream code is normative, which peers are compatibility
targets, which immutable revisions may be consulted, and what every OmaChat
binary must report at runtime.

Protocol behavior is not inferred from an unpinned `main` branch. A future pin
change requires its own pull request, source-drift review, updated fixtures, and
an explicit compatibility-profile decision.

## 0.0.1 compatibility boundary

OC-001 through OC-064 preserve the original compatibility-led G0–G5 release
train. [ADR 0002](adr/0002-account-registry-and-text-collaboration.md)
changes the immediate product direction to persistent text collaboration and
adds OC-065 for the account/registry foundation and OC-066 for the installed
binary-size guard. Bluetooth G2 through G4 are retained but substantially
deferred; this profile remains authoritative for those compatibility surfaces
whenever they are shipped.

Version 0.0.1 remains a development version. The revised release gate must be
made explicit before any tag or distribution; completing one issue or the local
account slice does not imply that a partially built product is ready to ship.

## Authority order

When sources disagree, use this order:

1. The pinned Swift source is normative for wire format and behavior.
2. The pinned whitepaper explains intent only where it agrees with Swift.
3. The pinned Android source is a feature-level compatibility reference only.
4. Prior Linux ports may inform BlueZ integration, but not protocol or crypto.

No source outside the immutable revisions below may silently change 0.0.1
behavior.

## Frozen source set

| Role | Repository | Release | Immutable revision | Policy |
|---|---|---|---|---|
| Canonical protocol | [`permissionlesstech/bitchat`](https://github.com/permissionlesstech/bitchat) | `v1.7.1` | [`9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa`](https://github.com/permissionlesstech/bitchat/commit/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa) | Normative |
| Partial compatibility peer | [`permissionlesstech/bitchat-android`](https://github.com/permissionlesstech/bitchat-android) | `v2.0.1` | [`93e9594bad3e537b4ec6fd096c0fde7533f22e74`](https://github.com/permissionlesstech/bitchat-android/commit/93e9594bad3e537b4ec6fd096c0fde7533f22e74) | Behavior and live-peer testing only |
| Desktop integration target | [`basecamp/omarchy`](https://github.com/basecamp/omarchy) | `v4.0.1` | [`13f18b2cb7286fb54f87daf571a031aa6af3d8f0`](https://github.com/basecamp/omarchy/commit/13f18b2cb7286fb54f87daf571a031aa6af3d8f0) | Packaging and lifecycle acceptance |
| Linux Bluetooth API reference | [`bluez/bluer`](https://github.com/bluez/bluer) | snapshot | [`57ec704503417a6476bca5d3bb01122686583709`](https://github.com/bluez/bluer/tree/57ec704503417a6476bca5d3bb01122686583709) | API feasibility reference |
| BlueZ policy/API reference | [`bluez/bluez`](https://github.com/bluez/bluez) | snapshot | [`e8141342284be2a52e16565b96b513ebe1297d84`](https://github.com/bluez/bluez/tree/e8141342284be2a52e16565b96b513ebe1297d84) | D-Bus policy and interface reference |

The Swift v1.7.1 whitepaper is version 2.0 dated 2026-07-06:

- source: [`WHITEPAPER.md`](https://github.com/permissionlesstech/bitchat/blob/9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa/WHITEPAPER.md)
- Git blob: `75e346fbad391984accfa6b91555aeece53103ec`
- raw SHA-256: `c81e1cb55ce33ec8daa0cabec4db6623b10f5d2eb7cbe2d7d47e565fa209b6e0`

The whitepaper predates its containing release and is not authoritative when
the tagged Swift implementation differs.

## Compatibility claims

| Surface | 0.0.1 policy |
|---|---|
| Swift v1.7.1 | Canonical emit behavior and required acceptance peer |
| Android v2.0.1 | Accept supported released variants; do not claim courier, prekey, RSR, or current bridge parity |
| Standard Nostr clients | No interoperability claim for private envelopes |
| Upstream `main` | Drift and security monitoring only; never a runtime specification |
| Omarchy v4.0.1 | Primary packaged desktop acceptance target |
| Other Arch Linux systems | Best effort until separately tested and documented |

Feature-specific acceptance peers remain defined by
[`upstream-validation.md`](upstream-validation.md). Passing a self-generated
Rust round trip is not sufficient evidence of wire compatibility.

## License and clean-room policy

OmaChat original source is licensed under the
[`0BSD`](https://spdx.org/licenses/0BSD.html) license in the repository
[`LICENSE`](../LICENSE) file.

Upstream use is constrained as follows:

- Swift v1.7.1 ships the Unlicense. Its code may be consulted and ported, with
  source provenance retained in implementation notes and fixtures.
- Android v2.0.1 is legally inconsistent: its README says public domain while
  its bundled `LICENSE.md` contains GPL-3.0. Until upstream clarifies that
  conflict, Android is a black-box/live-peer and clean-room behavioral
  reference. Do not copy, translate line by line, or derive implementation
  code from Kotlin.
- Prior Linux ports are examples of system integration only. Do not copy their
  protocol or cryptographic implementations.
- Dependencies keep their own licenses and must pass the dependency-policy
  checks introduced with the workspace.

The source/license classification is part of the compatibility profile. A
change requires an explicit pull request; it is not a dependency update.

## Binary version contract

The `omachat`, `omachatd`, and `omachat-ctl` binaries must each implement
`--version` using exactly one UTF-8 line terminated by `\n`:

```text
<binary> 0.0.1 (profile=bitchat-swift-v1.7.1; swift=9edb7c26ef7bdcf3bb29e7907b38997f8d5cd0fa; android=93e9594bad3e537b4ec6fd096c0fde7533f22e74; omarchy=13f18b2cb7286fb54f87daf571a031aa6af3d8f0)
```

`<binary>` is exactly one of `omachat`, `omachatd`, or `omachat-ctl`. The
command must not access the network, Bluetooth adapter, configuration, keyring,
or data directory. It exits zero after writing the line to standard output.

The product version comes from the repository [`VERSION`](../VERSION) file.
The full commit IDs are deliberately included so bug reports identify the
actual interoperability profile rather than an ambiguous release name.

## Name status

“OmaChat” is a provisional project name. The earlier low-effort collision
search is not legal or trademark clearance. No release or packaging text may
claim that the name is cleared until a separate adoption-grade review records
that conclusion.

## Changing this profile

A profile-change pull request must:

1. name every old and new immutable revision;
2. include the upstream source/whitepaper diff and license review;
3. regenerate all affected cross-implementation fixtures;
4. update the compatibility matrix and acceptance peers;
5. update `VERSION` when the change affects an already released product; and
6. keep the prior profile available for reproducing old bug reports.

Release tags and branch names alone are insufficient evidence; full commit IDs
and content hashes remain mandatory.
