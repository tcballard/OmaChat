# ADR 0006: AI-native coordination and Discord displacement scope

- Status: Proposed
- Date: 2026-09-01
- Depends on: ADRs 0002, 0003, and 0005

## Context

OmaChat's Omarchy objective now includes displacing Discord as well as Slack
and Teams. Matching three products feature-for-feature would reproduce their
message-centric architecture and split the identity model. OmaChat instead
needs one cryptographic participation model and two deliberately different
coordination surfaces:

- durable, typed organisational coordination for work;
- low-friction raw rooms for community and human social texture.

Agents may outnumber humans. They cannot be cosmetic bots posting through an
owner key, and machine-speed traffic cannot be allowed to consume unbounded
relay, organisational, or human-attention capacity.

## Decision

OmaChat will evolve toward an AI-native coordination substrate while retaining
portable Nostr identity and relay interoperability.

### Layer boundary

Nostr remains the portable identity, signature, encrypted-message, relay
discovery, and cross-application transport layer. A human, device, or agent is
identified by the key that actually authored its event. Account-root bindings
and agent authorisations add verified provenance without replacing authorship.

The organisational coordination log is a separate, organisation-local,
append-only state layer. It is not made authoritative by an OmaChat relay and
is not federated merely because its captured events may arrive over Nostr.
Every accepted record retains its signed source event or an immutable reference
to the exact captured payload.

### Principal model

Human, device, and agent principals remain distinct. Delegation chains terminate
in an account root, human authority, or explicitly modelled firm authority.
Agents cannot mint or raise their own authority. Revocation changes current
authorisation without rewriting historical authorship.

### Coordination model

Natural communication is captured without requiring users to label it. A
versioned enrichment plane may classify communicative acts such as inform, ask,
request, commit, decide, object, acknowledge, and social. Commitments and
decisions are durable derived objects and always cite raw source events.
Classifier output is overrideable and never replaces the source record.

Synthesised views are computed only from events the reader is entitled to open
raw. Derived summaries are not recursively treated as factual sources.

### Discord-class community surface

OmaChat will support durable communities, discoverable rooms, membership roles,
moderation, media and voice-oriented evolution, and agent participation without
making one relay or server the identity authority. Raw human rooms remain
linear and unmediated by default. They are excluded from enrichment and
synthesis unless a future reviewed policy explicitly changes that contract;
deployment retention and legal obligations remain separate concerns.

Discord displacement does not justify presence pressure, read receipts, typing
indicators, engagement-driven unread counts, or identity trapped inside one
server. Community UX must remain usable for ordinary humans even when no AI
feature is enabled.

### Attention and abuse controls

Asynchronous delivery is the default. Interruptions are explicit, budgeted,
audited acts with a rate-limited break-glass path. Agent event, connection,
subscription, room-action, and interrupt budgets are enforced below the UI
where possible. Agent-to-agent chains require hop, cycle, and aggregate work
budgets so autonomous loops cannot saturate relays or people.

### Evidence and compliance

Mutable retry state may be compacted, but completed publication, delegation,
revocation, commitment, decision, policy, and interruption evidence is retained
as immutable audit material according to an explicit retention class. No
derived object exists without source events. Capture must survive enrichment or
synthesis failure.

## Sequencing

1. Correct Nostr principal boundaries and multi-relay interoperability.
2. Retain immutable publication and authorisation evidence.
3. Complete relay production gates, per-pubkey controls, retention, backup and
   monitoring without making the relay authoritative.
4. Add organisation, community, membership, role and raw-room domains.
5. Introduce the append-only communicative-act log and derived commitment and
   decision objects.
6. Add entitlement-safe views and asynchronous attention negotiation.
7. Add media, voice and richer Discord-class community capabilities only after
   identity, moderation, retention and abuse boundaries are operational.

## Non-claims

This ADR does not claim that ACS is implemented, that an OmaChat production
relay is deployed, that global handles are live, or that Buzz/Discord/Slack/
Teams interoperability has been demonstrated. Those claims require concrete
tests or operational evidence.

