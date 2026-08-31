# ADR 0003: Agent identities, relay bootstrap, and Nostr interoperability

- Status: proposed
- Date: 2026-08-31
- Depends on: ADR 0002 and the OC-065 registry foundation
- Scope: architecture only; no live relay or cross-application compatibility claim

## Context

OmaChat needs humans, devices, and agents to be distinct cryptographic
principals. An agent must author Nostr events with its own secp256k1 key. An
account root may authorize that agent, but authorization is provenance and
policy evidence, not an authorship override.

This design must preserve two existing properties:

1. The account and recovery roots remain cryptographically separate from each
   other and from device and Nostr signing keys.
2. Nostr event identity remains the canonical NIP-01 event ID and author
   pubkey, independent of the relay that delivered the event.

The current implementation already has useful foundations:

- an Ed25519 account root and distinct Ed25519 recovery root;
- a root-signed local binding containing device Ed25519, X25519, and Nostr
  secp256k1 public keys;
- strict NIP-01 event ID and signature verification;
- an N-relay pool with acknowledgement thresholds and event-ID
  deduplication;
- sealed restart-safe account, outbox, and registry state;
- atomic global handle uniqueness and verified registry receipts.

It also has two material gaps:

- The account has no account-wide human Nostr principal. The current stable
  mailbox identity is a device Nostr key. Rebranding that device key as a
  human/account key would silently collapse two principals.
- The v1 handle registry models one account-bound handle and per-account CAS.
  It cannot represent separately addressable agents without a versioned
  subject model.

The existing private envelope uses kinds 14, 13, and 1059 but follows captured
mobile compatibility cryptography rather than standard NIP-44, NIP-17, and
NIP-59. Equal kind numbers do not establish wire compatibility.

## Decision

### 1. Principal and authority model

OmaChat will model four related concepts without conflating them.

| Concept | Stable identifier | Key family | Purpose |
| --- | --- | --- | --- |
| Account authority | `AccountId` derived from account root | Ed25519 | Recovery-independent control-plane authority |
| Human Nostr principal | Nostr pubkey | secp256k1/BIP-340 | Portable human event authorship |
| Device principal | Existing `DeviceId` and bound keys | Ed25519, X25519, secp256k1 | Device authentication, transport, and explicit device-originated activity |
| Agent principal | Nostr pubkey | secp256k1/BIP-340 | Portable agent event authorship |

The account root is not a Nostr author key. The recovery root is not an
account signing fallback. Device and agent keys are not derived from either
root.

A future human-Nostr binding must be a separate versioned, account-root-signed
object. It must not mutate the v1 local device/profile binding or silently
reinterpret `device_nostr_identity()` as the human identity. Human key custody,
multi-device signing, and migration from existing device-authored history need
a separate reviewed design before implementation.

An external Nostr pubkey is a valid external participant without an OmaChat
account, handle, or regenerated key. Its principal type is unknown until
supported signed evidence establishes more. UI labels such as `Agent` or
`Authorised by` must never be inferred from a relay, display name, kind, or
unsigned profile field.

### 2. Agent authorization

The v1 device/profile binding remains device-specific. Agent authorization is
a separate domain-separated object because it has different keys, lifecycle,
privacy, and revocation semantics.

The first object should cover at least:

```text
AgentAuthorizationV1
  version
  authorization_id
  account_id
  account_root_public_key
  agent_nostr_public_key
  principal_type = agent
  optional bounded label
  authorized_at
  account_authorization_revision
  signature_by_account_root
```

Creation must require proof that the agent key is controlled by the enrolling
party. A narrow challenge signed by the agent key prevents an account from
registering an unrelated public key as its agent. The account-root signature
then establishes the owner relationship. Neither proof signs ordinary agent
messages.

The account root API must expose only a domain-separated authorization
operation, not a general-purpose signing oracle.

An agent event is accepted in this order:

1. Verify the NIP-01 event ID and BIP-340 signature against `event.pubkey`.
2. Treat `event.pubkey` as the author regardless of provenance metadata.
3. If owner provenance is needed, verify the authorization object and exact
   agent pubkey binding.
4. If current owner-authorized policy is needed, verify non-revocation using a
   sufficiently fresh control-plane view.

An external agent may omit OmaChat authorization and still participate as its
Nostr pubkey, subject to relay and room policy. It simply does not receive an
OmaChat-verified owner label.

### 3. Revocation and historical evidence

Revocation is an append-only, account-root-signed transition, not mutation or
deletion of the original authorization.

```text
AgentRevocationV1
  version
  authorization_id
  authorization_hash
  account_id
  agent_nostr_public_key
  revoked_at
  account_authorization_revision
  signature_by_account_root
```

The authoritative control plane must serialize authorization revisions and
bind accepted transitions to its signed receipt chains. Sealed clients must
detect rollback or mismatch and fail closed for current authorization checks.

Revocation has prospective policy effect:

- old events remain authored by the agent;
- historical authorization evidence remains inspectable;
- new actions requiring current owner authorization fail;
- relay or room policy may reject later activity;
- the owner account and unrelated agents do not rotate.

An event's self-declared `created_at` is not sufficient to bypass revocation.
Current authorization decisions use trusted control-plane sequence/freshness,
not agent-controlled timestamps.

### 4. Handles and OC-065 mapping

The v1 registry invariants remain valid and must not be changed inside the
agent identity implementation:

- atomic global uniqueness;
- exact claim-to-receipt binding;
- idempotent commands;
- signed global and account receipt chains;
- fail-closed persistence and lookup;
- rename, reuse, and dispute policy remain deferred.

Separately addressable agents require a future versioned handle subject. A
candidate model is:

```text
HandleSubjectV2
  Account(AccountId)
  Agent {
    owner_account_id,
    agent_nostr_public_key,
    authorization_id
  }
```

An agent claim must prove both current account authorization and control of the
agent key. CAS must be defined per handle subject while preserving account
authorization ordering. Existing v1 account claims remain readable.

This is an explicit registry invariant extension, not an implementation detail.
It requires its own protocol version, persistence vectors, and migration tests.
Until that lands, an external or owned agent remains addressable by its Nostr
pubkey/npub and may have ordinary signed Nostr profile metadata, but it does not
have an OmaChat globally verified handle.

The central handle registry enriches a Nostr principal; it never replaces or
obscures the underlying pubkey.

### 5. Relay bootstrap and multi-relay behavior

OmaChat will initially operate one production relay at the eventual configured
hostname:

```text
wss://relay.omachat.<domain>
```

The hostname remains a deployment placeholder until the domain is selected.
The relay is a default bootstrap endpoint, not protocol authority. Relay
receipt does not validate an event, identity, authorization, or registry
claim.

The client continues to model a bounded set of relays:

```text
participant
  -> OmaChat bootstrap relay
  -> optional community relay
  -> optional personal relay
  -> optional application-specific relay
```

Outgoing events are published according to event purpose and configured relay
policy, with a configurable acknowledgement threshold. Incoming events are
verified and deduplicated by NIP-01 event ID across every relay path. An event
with an invalid signature is rejected even when received from an
OmaChat-operated relay.

A second OmaChat-operated relay is an availability decision triggered by
measured service objectives, failure domains, and recovery evidence. It is not
needed merely because the network approaches roughly 1,000 ordinary users.

### 6. Relay discovery and reachability

Identity and reachability are separate:

- the Nostr pubkey identifies the participant;
- relay metadata supplies signed but potentially stale reachability hints;
- relay authentication and membership decide access;
- successful publication does not prove delivery or authorization.

Use existing standards before inventing metadata:

- NIP-65 kind 10002 for general read/write relay preferences;
- NIP-17 kind 10050 for private-message inbox relays;
- the relay hint and group ID carried by NIP-29 group references for
  relay-local rooms.

Discovery records are verified as Nostr events, bounded to a small relay set,
restricted to supported secure URL schemes, and cached with explicit age. They
do not establish an account relationship or an agent type.

For an external agent, either the same process subscribes to both Buzz and
OmaChat relays, or OmaChat uses an advertised external relay when access policy
allows it. A pubkey alone never grants access to a Buzz community.

### 7. Messaging and room standards

OmaChat must keep the captured mobile-compatibility envelope and a future
standards-compatible Nostr DM path as distinct codecs and capability labels.
No decoder may guess based only on kinds 14, 13, and 1059.

The interoperability target is:

| Use | Standard or contract | Current state |
| --- | --- | --- |
| Event identity and signatures | NIP-01 | Implemented |
| Relay information | NIP-11 | Deployment requirement, not yet proven live |
| Relay authentication | NIP-42 | Client authentication and explicit restricted outcomes implemented; no production relay probe yet |
| General relay discovery | NIP-65 kind 10002 | Signature-verified, bounded discovery implemented |
| Private inbox discovery | NIP-17 kind 10050 | Signature-verified, bounded discovery implemented |
| Interoperable private messages | NIP-17 + NIP-44 + NIP-59 | Standard codec and hermetic two-relay NIP-42 delivery probe implemented alongside the proprietary envelope; external relay and cross-application probes remain |
| Relay-local rooms | NIP-29 | Not implemented in OmaChat |
| Owner-to-agent provenance | No adopted general standard | OmaChat object proposed; Buzz NIP-OA adapter is later work |

Room membership is a policy decision made by the room's authoritative relay,
not by the global identity or handle registry. NIP-29 group state may migrate
or fork; a group relay's authority is scoped to that group and does not become
identity authority.

### 8. Buzz compatibility boundary

The analysis baseline is Buzz commit
[`3ed623bb217bf9697b0ce4562529254977e0ea04`](https://github.com/block/buzz/tree/3ed623bb217bf9697b0ce4562529254977e0ea04)
and Nostr NIPs commit
[`24b2ae9fdfeb4e5c0d3be854df5977b81afe1983`](https://github.com/nostr-protocol/nips/tree/24b2ae9fdfeb4e5c0d3be854df5977b81afe1983),
both inspected on 2026-08-31.

Buzz documents NIP-29 rooms, NIP-42 authentication, NIP-17 gift-wrapped DMs,
relay/community-local membership, and a draft
[`NIP-OA`](https://github.com/block/buzz/blob/3ed623bb217bf9697b0ce4562529254977e0ea04/docs/nips/NIP-OA.md)
owner attestation. NIP-OA preserves the agent's event pubkey as author.

| Boundary | Result at this ADR | Required evidence before claiming compatibility |
| --- | --- | --- |
| Identity | Structurally compatible: both use the agent Nostr pubkey | Same external key imported without regeneration and signatures verified |
| Relay authentication | Not compatible yet | OmaChat NIP-42 client authenticates to a Buzz relay and handles restricted outcomes |
| Direct messages | Not compatible yet | Standard NIP-17/44/59 vectors plus a concrete cross-relay or Buzz probe |
| Rooms/channels | Not compatible yet | NIP-29 event support and explicit Buzz membership/admission |
| Owner/delegation | Semantics align, credentials do not | Explicit adapter and vectors, or a documented decision not to map them |

Buzz NIP-OA uses a BIP-340 Nostr owner key and a reusable event `auth` tag.
OmaChat's account root is Ed25519. OmaChat must not claim that an account-root
authorization is a NIP-OA credential, and must not replace the account root with
a Nostr key merely to make the formats match.

OmaChat may later verify NIP-OA as external provenance. Mapping a Buzz owner key
to an OmaChat account requires a separately verified binding. Core agent
authorization must not depend on a Buzz-specific draft tag.

### 9. Agent permissions and abuse controls

Machine-speed principals require enforcement below the UI.

The production relay configuration must support bounded:

- event bytes and tag counts;
- connections per IP and authenticated pubkey;
- concurrent subscriptions and filter complexity;
- publishes per IP and authenticated pubkey;
- stored bytes and events per principal/window;
- room membership and moderation policy;
- authentication failures and reconnect attempts.

Gift wraps use one-time outer keys, so outer event pubkey rate limits are not
sufficient. NIP-42 session identity and IP/connection limits must also be used.

OmaChat clients and agent runtimes must additionally enforce:

- per-agent send budgets;
- bounded automation concurrency;
- explicit human pause/revoke controls;
- causation/run identifiers inside encrypted application payloads;
- a maximum autonomous hop count;
- duplicate causation suppression;
- circuit breaking when an agent-to-agent cycle is observed.

Relays cannot inspect encrypted causation metadata, so relay quotas and
application loop controls are complementary.

### 10. Relay operation and retention

OmaChat will evaluate maintained relay implementations before considering
custom relay software. The deployment spike must prove, rather than assume:

- TLS termination and certificate renewal;
- persistent storage, restore-tested backups, and bounded disk growth;
- NIP-11 information with an exact supported-NIP list;
- NIP-42 authentication and recipient-protected gift-wrap queries;
- configurable event, connection, subscription, and rate limits;
- health, latency, rejection, storage, and capacity monitoring;
- safe upgrade and rollback;
- documented operator and abuse-response procedures.

Relay retention is a separate product decision. No production relay may launch
with an accidental implementation-default policy for encrypted chat. A
separate decision must choose and test indefinite, fixed-window,
delivery-oriented, or user-controlled retention, including backup and new
device consequences.

### 11. Threat model changes

Agent support adds or sharpens these threats:

- forged owner provenance or self-attestation;
- compromised agent keys being mistaken for owner compromise;
- stale or rolled-back revocation state;
- an owner registering an agent key it does not control;
- relays asserting trust or principal type;
- malicious or stale relay discovery metadata;
- cross-relay replay and duplicate processing;
- privacy leakage from public owner-agent links;
- machine-speed spam and subscription exhaustion;
- autonomous response loops;
- ambiguous UI that visually attributes an agent event to its owner;
- proprietary envelope kinds being misclassified as standard NIP-17.

The principal mitigations are strict signature ordering, separate key roles,
dual proof for enrollment, append-only revocation, receipt-chain rollback
detection, explicit cache freshness, event-ID deduplication, relay-side quotas,
and unambiguous authorship UI.

### 12. Required test and probe gates

Before agent support ships, hermetic tests must prove:

1. An agent event verifies with the agent key and not the owner/account key.
2. A valid account-root authorization binds exactly agent X to account Y
   without changing event authorship.
3. Forged ownership, altered labels, altered keys, and self-attestation fail.
4. Revoked authorization fails current owner-authorized checks while old events
   remain attributable to the agent.
5. Two agents under one account remain distinct principals and receipt-chain
   subjects.
6. One agent key publishing through two relay paths remains one participant.
7. The same event arriving through multiple relays is delivered once.
8. Invalid signatures and ownership claims remain invalid when delivered by an
   OmaChat relay.
9. An externally generated Nostr key is accepted without replacement.
10. Registry persistence rejects corrupt, truncated, rolled-back, mismatched,
    or cross-subject agent state.
11. Agent loop budgets and circuit breakers terminate deterministic cycles.

Cross-Buzz claims additionally require a concrete probe using a pinned Buzz
revision and disposable keys. The probe must separately record NIP-42 login,
DM format, membership, event authorship, owner provenance, and relay paths.

## Sequenced implementation

Each item is a separate focused PR:

1. Account-root-signed agent authorization and revocation objects with
   independent agent proof-of-possession vectors.
2. A versioned registry subject/claim design for agent handles, preserving v1
   reads and all OC-065 receipt invariants.
3. NIP-42 client authentication and restricted relay outcome handling.
4. A standard NIP-44/17/59 codec alongside, not replacing, the captured legacy
   compatibility codec.
5. Bounded NIP-65 and NIP-17 inbox relay discovery with explicit freshness.
6. A mature-relay deployment spike and a separate retention decision.
7. A pinned external-agent and Buzz interoperability probe.
8. Onboarding and participant UI that separates author, principal type,
   verified owner provenance, handle, npub, and relay reachability.

The human account-wide Nostr principal and its multi-device custody design must
be resolved before presenting device-authored events as one portable human
Nostr identity.

## Consequences

- Agents remain portable Nostr identities rather than OmaChat bot records.
- OmaChat account recovery and handle UX enrich identity without replacing it.
- Existing account and registry formats are not silently changed.
- Agent handles require an explicit registry protocol extension.
- Current private messaging cannot be advertised as Buzz-compatible.
- The default OmaChat relay improves bootstrap reliability without becoming
  identity or protocol authority.
- Owner provenance is useful but privacy-sensitive and never overrides event
  authorship.
