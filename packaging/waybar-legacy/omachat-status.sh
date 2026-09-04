#!/bin/sh
set -eu
if output=$(/usr/bin/timeout 1s /usr/bin/omachat-ctl status --json 2>/dev/null); then
  joined=$(printf '%s\n' "$output" | /usr/bin/jq -r '.joined_geohashes | length')
  pending=$(printf '%s\n' "$output" | /usr/bin/jq -r '.outbox_pending')
  printf '{"text":"OC %s ·%s","class":"online"}\n' "$joined" "$pending"
else
  printf '{"text":"OC —","class":"offline"}\n'
fi
