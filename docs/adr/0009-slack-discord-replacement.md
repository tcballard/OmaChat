# ADR 0009: replace everyday Slack and Discord workflows

- Status: Accepted product direction; implementation is staged
- Date: 2026-10-07
- Authority: owner instruction to address the hosted review findings and target a Slack/Discord replacement
- Builds on: ADR 0007 and ADR 0008

OmaChat's target is an independent, self-hostable team and community communication
product with a native Omarchy client. It must cover routine work and community
use well enough that users can leave Slack or Discord. It is not a client for
those services, and basic text messaging alone does not satisfy this goal.

Retain the hosted Rust server, local Rust daemon and native desktop. Keep server
authorization authoritative. The operator can read messages; encryption at rest
is not end-to-end encryption. Adopt no clean-room marketing claim without a
separate provenance assessment; record source material for future compatibility
specifications. No Slack or Discord implementation source is required.

Priority is complete human workflows: dependable conversations, recoverable
accounts, usable permissions, moderation, search, attachments and notifications.
Voice, video and screen sharing are required for the Discord replacement target,
with a separate media architecture and measurable quality gates. Multiple
devices and access from phones and non-Omarchy computers are adoption needs;
client delivery order is a decision, not permission to ignore them.

The earlier proposed AI coordination work in ADR 0006 stays optional and must
not delay a usable team/community product. Its Nostr assumptions are superseded
by ADR 0008. Agents use scoped identities and permissions rather than bypassing
human controls. Feature-specific decisions remain necessary for identity,
recovery, retention, permissions, search and media.

No release, deployment or merge is authorized by this direction alone. The
current deliverable is development work through reviewable PRs. See the
[replacement roadmap](../slack-discord-roadmap.md) for acceptance criteria and
explicit current gaps.
