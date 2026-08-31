#!/bin/sh
set -eu
if output=$(timeout 1s omachat-ctl status --json 2>/dev/null); then
  joined=$(printf '%s\n' "$output" | jq -r '.joined_geohashes | length')
  pending=$(printf '%s\n' "$output" | jq -r '.outbox_pending')
  printf '{"text":"OC %s ·%s","class":"online"}\n' "$joined" "$pending"
else
  printf '{"text":"OC —","class":"offline"}\n'
fi
