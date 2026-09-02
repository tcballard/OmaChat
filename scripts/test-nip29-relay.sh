#!/bin/sh
# Black-box NIP-29 interoperability: build the pinned relay29 harness, drive
# one group through its lifecycle with the stdlib probe, then replay the
# captured evidence through OmaChat's room reducers.
set -eu

PORT="${OMACHAT_NIP29_PORT:-29290}"
RELAY_URL="ws://127.0.0.1:${PORT}"
TMP="${OMACHAT_NIP29_TMP:-$(mktemp -d)}"
HARNESS_DIR="conformance/relay/relay29"
CAPTURE="${TMP}/nip29-capture.json"
# Fixed relay key so the run is reproducible; a fixture, never a deployment.
RELAY_SECRET="${OMACHAT_NIP29_RELAY_SECRET:-5555555555555555555555555555555555555555555555555555555555555555}"

cleanup() {
  if [ -n "${RELAY_PID:-}" ]; then
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "building pinned relay29 harness"
(cd "$HARNESS_DIR" && GOFLAGS=-mod=mod go build -o "$TMP/relay29-harness" .)

RELAY29_PORT="$PORT" RELAY29_SECRET="$RELAY_SECRET" "$TMP/relay29-harness" >"$TMP/relay29.log" 2>&1 &
RELAY_PID=$!

python3 conformance/relay/nip29_probe.py wait --url "$RELAY_URL"
python3 conformance/relay/nip29_probe.py run --url "$RELAY_URL" --capture "$CAPTURE"

echo "replaying captured relay evidence through the Rust room reducers"
OMACHAT_NIP29_CAPTURE="$CAPTURE" cargo test -p omachat-nostr --locked --test nip29_capture_replay -- --nocapture
echo "nip29 relay interoperability: ok"
