# ADR 0004: Grain relay bootstrap candidate

- Status: Proposed, implementation probe added
- Date: 2026-08-31
- Depends on: ADR 0003, PRs #85 through #88
- Related retention issue: #79

## Context

OmaChat needs an operated bootstrap relay without turning that relay into
identity or protocol authority. The initial relay must persist offline direct
messages, support NIP-42, constrain kind `1059` reads to the authenticated
recipient, bound abusive resource use, and remain replaceable by any compatible
relay.

NIP-59 recommends AUTH-gated, recipient-only kind `1059` serving. NIP-42 proves
the key controlling a connection but does not define authorization policy. A
relay advertising NIP-42 without recipient filtering is therefore insufficient.

## Candidate evaluation

### Grain v0.7.1

Grain is the current bootstrap candidate, pinned to commit
`c0709db6e59d57620ba2053c7078b1e07942d38c`.

Evidence available before this decision:

- tagged MIT release with official multi-platform binaries and GitHub digests;
- embedded persistent nostrdb/LMDB storage;
- NIP-42 authentication;
- unconditional recipient-only kind `1059` filtering across historical reads,
  live subscriptions, and counts;
- bounded connections, subscriptions, message rates, event rates, query rates,
  event sizes, CPU, heap, and memory targets;
- IP connection throttling and escalation to temporary/permanent IP blocks;
- structured logs, health endpoint, hot configuration, NIP-86 administration,
  event expiration, and configurable purging;
- source build of the pinned storage dependency succeeded on Apple Silicon;
- pinned Grain configuration and AUTH/DM-privacy unit suites passed locally.

The repository black-box probe adds independent evidence for AUTH, signature
rejection, recipient isolation, count isolation, storage, and restart behavior.

### nostr-rs-relay

`nostr-rs-relay` is mature, persistent, resource-bounded, and NIP-42 capable,
but no verified recipient-only kind `1059` query policy was found. NIP-42 alone
does not meet the private-inbox requirement.

### strfry

`strfry` is mature and supports NIP-42 plus write-policy/router plugins. Its
documented plugin surfaces did not establish per-subscriber recipient-only
historical and live kind `1059` reads. A write policy cannot safely substitute
for a read authorization policy.

### nogringo/nostr-relay

This Khatru-based implementation has explicit authenticated publication,
recipient-only reads, live filtering, and recipient deletion for gift wraps.
Its implementation is useful reference evidence, but at evaluation time it had
33 commits, no tagged releases, three stars, and no independent operational
track record. It is not selected over Grain for the first production relay.

### Custom Khatru relay

Khatru exposes the exact filter and AUTH hooks required to implement OmaChat's
policy. Building a custom relay now would make OmaChat own storage, protocol,
upgrade, and abuse-control correctness unnecessarily. It remains a fallback
only if upstream relay hardening cannot close the measured Grain gaps.

## Decision

Use Grain `v0.7.1` as the pinned bootstrap deployment candidate, not as protocol
authority and not yet as a production-approved service.

Require NIP-42 globally in the initial profile. Grain protects kind `1059`
reads regardless of the global setting, but global AUTH is required in
`v0.7.1` to reject unauthenticated gift-wrap writes and make connection-level
traffic attributable to a stable participant key rather than the wrapper's
one-time key.

Keep the client N-relay capable. Kind `10050` remains recipient-authored routing
metadata, the exact source event remains part of the publication plan, and
normal Nostr event IDs deduplicate deliveries. The OmaChat-operated relay is
only one configured route.

Do not deploy from this ADR. Deployment needs a separate approved change with
the actual domain, owner key, TLS, monitoring, retention decision, backup and
restore drill, public policy documents, and target-host evidence.

Grain v0.7.1 only accepts `server.port` in `:PORT` form and therefore binds all
interfaces in its network namespace. The candidate deployment must place Grain
on an internal, un-published network and expose only a TLS reverse proxy. A
host-published plaintext Grain port is a deployment failure.

## Known gap: authenticated-pubkey abuse accounting

Grain `v0.7.1` rate limits events per connection and connection attempts per IP.
An agent can open several authenticated connections with one key and multiply
its effective publish budget. Global AUTH improves attribution but does not
provide an aggregate per-pubkey token bucket.

Production readiness therefore requires one of:

1. an upstream Grain policy that aggregates event and connection budgets by
   authenticated pubkey;
2. a narrowly audited policy layer with equivalent semantics;
3. a different mature relay that passes the same black-box and operational
   gates.

This gap must not be hidden behind UI limits. Agent-to-agent loop protection
also needs a client/daemon budget and relay-side kill switch where enforceable.

## Retention

The checked-in profile disables purging to avoid silently losing offline
mailboxes. That is a reversible bootstrap safeguard, not a decision that
OmaChat promises indefinite retention. Issue #79 owns the product policy.

The production decision must define at least delivery window, deletion,
new-device behavior, backups, restore exposure, and user-visible expectations.

## Interoperability boundary

The probe establishes relay compatibility with ordinary signed Nostr events,
NIP-42 authentication, and NIP-59 routing metadata. Existing Rust tests own the
actual NIP-44/NIP-59 envelope and prove that an externally created Nostr key is
not replaced by an OmaChat identity.

This does not establish Buzz workspace access or cross-Buzz direct messaging.
Buzz relay membership and event semantics remain a separate access-control and
application-compatibility boundary under ADR 0003.

## Threat implications

- Relay receipt never overrides event signature validation.
- The authenticated sender key is transport provenance; the one-time wrapper
  key remains the kind `1059` event author and the sealed participant remains
  the message author.
- A relay operator can observe IPs, authentication keys, recipient tags,
  timing, sizes, and traffic volume even though message content is encrypted.
- Compromise or rollback of the relay can delete, delay, replay, or selectively
  serve events. Multi-relay publication reduces availability dependence but
  does not make any relay trustworthy.
- TLS is required in production; the local `ws://` probe is loopback-only.
- Backups increase availability and privacy exposure and must be encrypted,
  access-controlled, retained deliberately, and restore-tested.

## References

- NIP-42: <https://github.com/nostr-protocol/nips/blob/master/42.md>
- NIP-59: <https://github.com/nostr-protocol/nips/blob/master/59.md>
- Grain: <https://github.com/0ceanSlim/grain>
- Grain v0.7.1: <https://github.com/0ceanSlim/grain/releases/tag/v0.7.1>
- Grain recipient privacy issue: <https://github.com/0ceanSlim/grain/issues/73>
- nostr-rs-relay: <https://github.com/scsibug/nostr-rs-relay>
- strfry: <https://github.com/hoytech/strfry>
- Khatru: <https://github.com/fiatjaf/khatru>
- recipient-focused reference relay: <https://github.com/nogringo/nostr-relay>
