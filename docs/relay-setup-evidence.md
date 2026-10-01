> Historical document. Nostr and its compatibility/relay workflows are retired by [ADR 0008](adr/0008-hosted-only.md). See [the hosted plan](hosted-server-plan.md) for current work.

# Guided relay configuration development evidence

The desktop now reads and edits only DM and room relay lists, preserving other
JSON fields. The helper uses a private advisory lock, snapshot revision check,
private original backup, same-directory temporary file, fsync and atomic rename.
Symlink paths, duplicate keys, invalid/nonstandard JSON, oversized files,
unowned files and group/world-writable config directories are refused. Existing
unrelated settings are preserved, not semantically validated by this helper.
Noncooperating external editors are checked again before replacement; they do
not participate in the advisory lock and can still race that final check.

Seven portable Python tests exercise first-run/reopen, permissions, backup and
preservation, stale editors, simulated replacement failure, bad files/symlinks,
relay policy and XDG fallback. Qt interaction tests cover the production relay
dialog with a fixture setup backend. Actual Quickshell Process launch, custom
daemon configuration paths and restart/relay reachability require live testing.

No relay recommendation, network probe, credentials, daemon restart, or claim
of a working hosted service is included. The operator supplies authorized
relay URLs and chooses the config used by their daemon. A saved configuration
is not an active connection. The helper has a five-second process deadline;
an interrupted operation must be reread before retrying because it may have
committed already. Backup files remain private and are retained on uninstall.
