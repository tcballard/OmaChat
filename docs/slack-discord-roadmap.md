# OmaChat: Slack and Discord replacement

Owner-confirmed target, 7 October 2026. The goal is a native Omarchy team and
community app with a self-hostable service. A successful demo is not replacement
readiness. The comparison is user workflows, not a promise of complete API,
enterprise or ecosystem parity.

## Current foundation

The hosted stack supplies device-key accounts, server handles, workspaces,
public-to-workspace channels, DMs, ordered history, receipts, send idempotency,
reconnects, sealed local drafts, and a themed Quickshell desktop. Its server
operator can read messages. It remains a development preview with no production
deployment or release evidence.

The October hardening adds byte-bounded history and conversation paging, bounded
roster previews with a paged server roster API, aggregate peer receipts, and a
correct first-install secret-ownership procedure. This does not add message
search: the current desktop search only filters conversations.

## Delivery order and exit criteria

| Milestone | Scope | Evidence needed before completion |
|---|---|---|
| 1. Trust the foundation | Integrate the hosted stack through PRs; fix wire budgets and deployment; validate TLS, reconnects, recovery of drafts, restart durability and backup/restore | Real server/two-client tests with long Unicode/escaped messages, paged histories and large rosters; named TLS endpoint used from two machines; restore rehearsal; physical XPS install/update/rollback; review findings resolved |
| 2. Recoverable identity | Stable accounts with enrolled and revocable devices, account recovery, safe invitation onboarding and profile management | Losing one device does not lose the account; revoked devices cannot read new messages; wrong or replayed enrollment/recovery proofs rejected; restart and failure tests; clear trust decision |
| 3. Everyday team text | Threads/replies, reactions, edit/delete rules, mentions, permission-aware message search, attachments/images and reliable notifications | A small team uses it for a working week without a second app for routine text/files; reconnects do not duplicate sends or lose drafts; search respects membership; uploads have size/type/quota limits and deletion rules |
| 4. Community administration | Private channels, roles, remove/ban/mute/report flows, invite expiry, moderation/audit trails, retention/deletion/export and abuse controls | Outsiders and removed members cannot access protected history or files; ordinary moderators can handle a disruptive user; audit and deletion semantics tested across backups and clients |
| 5. Live communication and reach | Voice channels/calls, then video and screen sharing; multiple-device consistency; phone and non-Omarchy access | Agreed media architecture, device selection, join/leave/reconnect and permission tests; measured call quality on realistic networks; daily users can stay reachable away from the Omarchy desktop |
| 6. Migration and operation | Import/export with explicit fidelity limits, scoped integrations, accessibility/IME, performance, monitoring, quotas and deployment upgrades | Named pilot users migrate real permitted data; load and soak evidence meets published capacity; backup recovery works; keyboard, mouse, IME and assistive-technology checks; repeatable packaging and upgrade validation |

## Capacity and reliability gates

The preview desktop still retains at most 128 conversations and 128 workspaces.
It must explicitly report reaching these limits. Paging fixes frame correctness;
it does not remove these product limits. Before a larger team/community pilot,
replace the fixed session limits with measured navigation/cache behavior and
exercise thousands of channels, large memberships and long histories.

Current roster summaries include eight members and a truthful total. The full
server roster is pageable; a desktop roster browser is still future work.
Delivery labels mean at least one other member, with full-roster aggregate
receipts preserved independently of the preview.

Channel lists are live keyset pages, not an immutable snapshot. New entries
created before an already traversed cursor appear on a fresh refresh. Membership
is checked on every page. Background/client pagination has caps; reaching a cap
must produce an incomplete status, not imply the whole account was loaded.

No physical Omarchy, public TLS, load/soak or independent security result can be
inferred from unit tests or green CI. Record each separately with exact source,
platform and result. Do not cut a release to imply these gaps are closed.

## Decisions to make as implementation starts

- Account recovery and enrollment authority, including operator powers.
- Retention, edits/deletes, exports, backups and audit visibility.
- Channel and community role model, removal history and moderation powers.
- Search and attachment storage with authorization and resource quotas.
- Media topology, privacy and operating costs; phone/web/native client order.
- A representative pilot group and measured reliability/performance budgets.

The [hosted delivery plan](hosted-server-plan.md) remains the implementation
inventory; ADR 0009 and this roadmap define the product target. AI coordination
is optional after the human product works.
