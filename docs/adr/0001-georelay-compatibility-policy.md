# ADR 0001: Pin and combine the mobile georelay directories

Status: proposed

Date: 2026-08-30

## Context

The pinned Swift v1.7.1 and Android v2.0.1 clients each ship a different
georelay CSV and select the nearest five entries. Swift breaks equal-distance
ties by host. Android uses a stable distance sort, so equal-distance rows retain
CSV order. Both releases can refresh from a mutable branch at runtime. That
behavior is unsuitable as OmaChat's compatibility authority because an
unreviewed upstream mutation could redirect location-tagged traffic.

## Decision

OmaChat will ship the exact relay-directory bytes from the two pinned release
commits. Their SHA-256 digests are part of the compatibility profile and their
full digests appear in their artifact paths.

For a geohash, the compatibility oracle will:

1. Decode the standard geohash cell center.
2. Select five relays from the Swift snapshot using Swift's distance/host order.
3. Select five relays from the Android snapshot using Android's stable distance/input order.
4. Produce a Swift-first, order-preserving union, removing exact normalized URL duplicates.
5. Cap the result at ten simultaneous geo relays.

OmaChat will not fetch relay-directory data at runtime. The snapshot pair is an
atomic compatibility-profile input. It is reviewed monthly and whenever a
pinned upstream security release changes relay trust. Replacement requires a
pull request containing the new immutable upstream commit, content hashes,
regenerated distant-cell and tie fixtures, and an explicit compatibility
review. An incomplete replacement leaves the prior pair active.

## Consequences

- Relay selection is reproducible and cannot be changed by mutable `main`.
- A room overlaps the nearest-five choices of either pinned mobile release.
- A cell may use up to ten WebSocket connections instead of five.
- Private-mail relays remain outside this cap.
- Production selection remains deferred to OC-017.

## Evidence

- `conformance/georelays/manifest.json`
- `conformance/georelays/cases.json`
- `crates/omachat-nostr/tests/georelay_oracles.rs`
