# ADR 0005: Proof-bearing Nostr principal bindings

- Status: Proposed
- Date: 2026-09-01
- Related: ADR 0003, OC-065

## Context

The v1 handle registry proves that an account root authorised an exact handle
binding and that the authoritative registry accepted it under its uniqueness,
compare-and-swap, idempotency, and receipt-chain rules.

The binding can contain a Nostr public key. That field is an assertion by the
account root. It is not proof that the claimant controlled the corresponding
Nostr private key when the registry command was accepted.

Treating the v1 field as proof of key control would permit an account to bind
someone else's public key and would make a `pubkey -> handle` reverse lookup
cryptographically misleading. Relay origin cannot repair this gap: relays are
transport and availability infrastructure, not identity authorities.

OmaChat also has distinct account roots, recovery roots, device keys, and agent
keys. A proof extension must preserve those separations and must not silently
turn a device key into a human account identity.

## Decision

OmaChat will add a versioned Nostr principal-control proof alongside, rather
than inside the meaning of, the existing v1 handle claim.

A proof-bearing registry update establishes two independent facts:

1. The account root authorised the exact registry claim.
2. The Nostr principal signed a proof bound to that exact claim.

Neither signature substitutes for the other. The registry accepts the update
only when both signatures and the relevant current authorisation are valid.

### Canonical proof payload

The first proof version will be a deterministic canonical object containing at
least:

```text
domain:                 omachat-nostr-principal-control-v1
proof_version:          1
claim_hash:             hash of the exact canonical registry claim
command_id:             exact registry command identifier
expected_revision:      exact compare-and-swap revision
account_id:             owner account identifier
handle:                 exact canonical candidate handle
principal_type:         device | agent | account
nostr_public_key:        32-byte x-only Nostr public key
authorisation_hash:      hash of the root-signed principal binding
created_at:              proof creation time
```

The Nostr principal signs this object with a BIP-340 Schnorr signature. The
domain separator prevents the signature from being interpreted as a Nostr
event or as another OmaChat authorisation.

The proof is bound to the complete claim hash, command identifier, and expected
revision. A proof cannot be transplanted to another handle, account, revision,
or command. Any change produces a different command and requires a new proof.

The proof does not include a relay URL. Identity remains independent of relay
reachability and relay operators.

### Principal types

`device` means the signing key is the Nostr key in a current, valid root-signed
device binding. Revocation of that device prevents new proof-bearing updates
from satisfying current authorisation checks.

`agent` means the signing key is the agent's independent Nostr key and the
authorisation hash identifies a current root-signed agent authorisation. The
existing dual-signed `AgentHandleClaim` semantics should be integrated rather
than translated into owner-authored agent activity. Agent events remain signed
and authored by the agent key.

`account` is reserved for an explicitly defined account-wide human Nostr
principal binding. A current device Nostr key must not be re-labelled as this
principal. Introducing an account-wide principal requires a separate reviewed
key-lifecycle decision.

An external Nostr participant may exist in OmaChat by public key without an
OmaChat account, handle, or owner authorisation. OmaChat must not manufacture a
replacement key for that participant.

### Authoritative acceptance

The authoritative registry state transition must atomically:

1. Verify the existing account-root claim signature and v1 invariants.
2. Verify the principal-control proof signature against the claimed Nostr key.
3. Recompute and compare every proof binding, including the claim hash.
4. Verify that the referenced device or agent authorisation is current and is
   owned by the claiming account.
5. Reject an active conflicting proof-bearing association for the same Nostr
   public key.
6. Persist the claim, proof, reverse index, and receipt-chain update in one
   crash-safe transaction.

The receipt must bind the exact accepted proof or its canonical hash. A cache
must be able to verify that binding independently using the pinned registry
verification key.

The reverse index is derived only from accepted proof-bearing records. A v1
record without this proof never enters the reverse index.

One Nostr public key arriving through several relays is still one principal.
Relay fan-out does not create additional registry records, and normal Nostr
event identifiers remain the event deduplication key.

### V1 compatibility and migration

Existing v1 claims and receipts remain valid evidence of account/handle
uniqueness. Their cryptographic meaning does not change.

V1 responses continue to report:

```text
nostr_public_key_provenance = account-root-asserted
nostr_key_control_verified  = false
```

No existing record is retroactively upgraded. A current owner can add a proof
by submitting a new compare-and-swap update, even if the visible handle and key
are unchanged. That update uses a new command identifier and revision and is
recorded in the receipt chain.

Persistence migration must preserve every historical v1 receipt and chain
hash. A node that cannot interpret a proof-bearing state version fails closed;
it must not silently discard the proof or rebuild a weaker reverse index.

### Lookup semantics

Handle-to-record lookup can continue to return v1 evidence with its explicit
provenance fields.

Nostr-public-key-to-handle lookup is permitted only for an independently
verified, current, proof-bearing record. Its response must distinguish:

- proof of Nostr key control;
- current owner authorisation;
- registry receipt freshness;
- online or offline-cache provenance;
- current usability under revocation and clock-rollback rules.

Proof of key control is not proof of current reachability, relay membership,
room membership, profile accuracy, or message authorship by an owner.

### Revocation and history

Revocation changes current authorisation, not historical authorship.

After device or agent revocation:

- old principal signatures remain attributable to that principal;
- old receipts remain historical evidence of what was accepted at the time;
- new owner-authorised operations using that binding are rejected;
- current lookup must not describe the revoked binding as currently
  owner-authorised.

The registry must not rewrite old agent events or make them appear owner
authored.

Handle rename, reuse, and tombstone policy remain separate decisions. This ADR
does not introduce permanent tombstones.

## Security consequences

This design prevents an account-root signature alone from claiming control of
an arbitrary Nostr key. Exact claim binding also prevents a valid principal
signature from being replayed for a different handle or registry mutation.

The design does not protect a principal whose Nostr private key is compromised.
Current owner authorisation and registry abuse policy remain independent checks.

The registry remains a potential source of censorship, stale state, and
equivocation. Signed receipt chains and independently pinned cache verification
make accepted state auditable, but broader transparency and equivocation
publication remain future work.

Receipt freshness is not identity trust. A stale receipt can remain valid
historical evidence while being unusable for a current-authorisation decision.

Publishing a proof-bearing handle intentionally correlates an account, handle,
and Nostr public key. The signed exact claim supplies cryptographic consent for
that registry operation; UI must still make the public correlation clear.

## Required implementation tests

Before reverse lookup ships, deterministic tests must cover:

- a valid root claim plus matching principal signature;
- rejection when the root signature is forged;
- rejection when the principal signature is forged or uses another key;
- rejection when any bound claim field is changed after signing;
- rejection of a proof replayed at another revision or command identifier;
- rejection of duplicate active public-key associations;
- exact idempotent replay of an already accepted proof-bearing command;
- atomic persistence and recovery across restart and interrupted writes;
- corrupt, truncated, rolled-back, and version-mismatched state failing closed;
- receipt verification binding the exact proof hash;
- v1 records remaining explicitly unverified for key control;
- device and agent revocation removing current owner-authorised status;
- two agents under one account remaining distinct principals;
- one principal received through multiple relays resolving once;
- an externally generated Nostr key being accepted without key replacement;
- invalid evidence remaining invalid when received from an OmaChat relay.

Independent reference vectors must cover the canonical payload, claim hash,
principal signature, receipt binding, and adversarial mutations before the
format is considered stable.

## Implementation sequence

The implementation should remain split into focused stacked changes:

1. Canonical proof type, signing, verification, and independent vectors.
2. Atomic state-machine and durable-storage integration with reverse-index
   invariants.
3. Versioned host transport and independently verified cache support.
4. Strict daemon and CLI lookup surfaces with explicit provenance.
5. Agent-claim integration without changing agent event authorship.

No step deploys a relay or registry, establishes a retention policy, or proves
Buzz channel compatibility. Those require separate operational evidence.

## Rejected alternatives

### Treat the account-root assertion as proof of Nostr key control

Rejected because an account can name any public key without possessing its
private key.

### Let the registry attest to key control without a principal signature

Rejected because the registry is not the Nostr identity authority and must not
manufacture identity trust.

### Replace v1 receipts in place

Rejected because it would change historical semantics, break chain evidence,
and risk protocol incompatibility.

### Use a relay-authentication event as the registry proof

Rejected because relay authentication is scoped to relay access and does not
bind the exact registry claim, CAS revision, and owner authorisation.

### Reuse a device Nostr key as the human account principal

Rejected because it weakens the established separation between account roots,
recovery roots, devices, and portable Nostr principals.
