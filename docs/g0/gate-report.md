# G0 source and feasibility gate report

Status: **open — live hardware and Omarchy evidence remains**

Report date: 2026-08-30

This report gathers evidence for OC-001 through OC-008 and replaces the
original 225–350 hour whole-project draft with a spike-informed estimate. It
does not close G0: the named Bluetooth-controller matrix, Omarchy lifecycle
matrix, and live Tor observations remain required.

## Evidence map

| Issue | Evidence | Result |
|---|---|---|
| OC-001 | [`compatibility-profile.md`](../compatibility-profile.md) | Green: immutable pins, authority order, clean-room policy, license, and version contract. |
| OC-002 | Workspace, CI, `deny.toml`, [`development.md`](../development.md) | Green: format, Clippy, tests, docs, builds, version and dependency policies pass. |
| OC-003 | [`conformance/README.md`](../../conformance/README.md), manifest and loader | Green: public/test-only inputs and provenance are machine checked. |
| OC-004 | Content-addressed fixtures and capture harnesses | Green: pinned Swift/Android evidence includes NIP-13 and the 33-byte shared point. |
| OC-005 | [ADR 0001](../adr/0001-georelay-compatibility-policy.md), snapshots and oracle tests | Green: exact directories, distant cells, ties, bounded union, replacement and cadence are frozen. |
| OC-006 | [`bluer-dual-role-probe.md`](bluer-dual-role-probe.md) | Pending: named internal and USB 30-minute captures and EATT observations. |
| OC-007 | [`storage-service-lifecycle-probe.md`](storage-service-lifecycle-probe.md), user unit and file-mode test | Pending: six-row Omarchy v4.0.1 lifecycle matrix. |
| OC-008 | [`proxy-tor-probe.md`](proxy-tor-probe.md), hermetic test and Arti probe | Pending: live system-DNS observation and Arti bootstrap/shutdown capture. |

## Retained risks

1. Run the BlueR probe reciprocally for 30 minutes on the target internal and
   one named USB controller, recording controller and stack versions, MTUs,
   traffic, advertising capacity, and EATT observation or trace denial.
2. Run every OC-007 lifecycle row on Omarchy v4.0.1 and record numeric modes
   without key bytes.
3. Capture system DNS traffic through Omarchy's Tor listener and complete the
   Arti bootstrap, connection, stream drop, and client shutdown run.
4. If either controller cannot sustain simultaneous roles, revisit BLE scope;
   do not compensate with root, broad custom policy, extended advertising, or
   a schedule waiver.

## Spike-informed estimate

The original 225–350 hours is retired. It omitted 64 acceptance issues, two
pinned mobile peers, two Bluetooth controllers, separate storage lifecycles,
system-Tor and Arti, courier/bridge infrastructure, packaging, and final soak.

| Work | Remaining effort |
|---|---:|
| Finish G0 qualification and review | 20–40 h |
| G1 Nostr-only product, OC-010–OC-026 | 220–340 h |
| G2 public BLE mesh, OC-027–OC-041 | 260–400 h |
| G3 private mesh/fallback, OC-042–OC-049 | 150–240 h |
| G4 courier/bridge, OC-050–OC-057 | 190–310 h |
| G5 packaging/release, OC-058–OC-064 | 130–220 h |
| **Total remaining engineering effort** | **970–1,550 h** |

This is approximately 24–39 engineer-weeks at 40 hours/week, excluding
review/procurement/calendar delay and the unattended 72-hour G5 soak.

## Gate decision

**G0 remains open.** Compatibility-critical product implementation remains
blocked by [`upstream-validation.md`](../upstream-validation.md) until the live
evidence sets above are reviewed.
