#!/usr/bin/env bash
# Exercise the documented root-directory/service-owned-secret boundary without
# touching /etc, creating accounts, or starting a system service.
set -euo pipefail
if [[ $(id -u) != 0 ]]; then
  echo 'Run this test as root (uses the existing nobody account in a temporary directory).' >&2
  exit 1
fi
binary=$(realpath "${1:-target/debug/omachat-serverd}")
owner=nobody
group=$(id -gn "$owner")
trial=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n $server_pid ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$trial"
}
trap cleanup EXIT
chmod 0755 "$trial"
install -m 0755 "$binary" "$trial/omachat-serverd"
install -d -m 0750 -o root -g "$group" "$trial/config"
install -d -m 0700 -o "$owner" -g "$group" "$trial/state"
for name in server.key storage.key invites; do
  "$trial/omachat-serverd" --generate-secret "$trial/config/$name" >/dev/null 2>&1
  test "$(stat -c %a "$trial/config/$name")" = 600
  if "$trial/omachat-serverd" --generate-secret "$trial/config/$name" >/dev/null 2>&1; then
    echo 'Generator overwrote an existing secret' >&2; exit 1
  fi
  chown "$owner:$group" "$trial/config/$name"
  runuser -u "$owner" -- test -r "$trial/config/$name"
done
if runuser -u "$owner" -- test -w "$trial/config"; then
  echo 'Runtime user can replace secret directory entries' >&2; exit 1
fi
runuser -u "$owner" -- "$trial/omachat-serverd" \
  --data-dir "$trial/state" --server-key-file "$trial/config/server.key" \
  --storage-key-file "$trial/config/storage.key" --registration invite \
  --invite-code-file "$trial/config/invites" --listen 127.0.0.1:0 \
  >"$trial/server.log" 2>&1 &
server_pid=$!
for ((attempt=0; attempt<50; attempt++)); do
  if grep -q 'listening on' "$trial/server.log"; then
    echo 'PASS: service reads owner-only secrets, cannot replace directory entries, and starts in invite mode'
    exit 0
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$trial/server.log" >&2; exit 1
  fi
  sleep 0.1
done
echo 'Server failed to start within five seconds' >&2
exit 1
