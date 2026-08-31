#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=v0.7.1
PORT=${OMACHAT_GRAIN_PORT:-18181}
RELAY_URL="ws://127.0.0.1:${PORT}"
TMP=${OMACHAT_GRAIN_TMP:-"$(mktemp -d /tmp/omachat-grain.XXXXXX)"}
DATA="$TMP/data"
LOG="$TMP/grain.log"
STATE="$TMP/probe-state.json"
PID=

stop_relay() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -INT "$PID"
        wait "$PID"
    fi
    PID=
}

on_exit() {
    status=$?
    stop_relay || true
    if [ "$status" -ne 0 ] && [ -f "$LOG" ]; then
        printf '%s\n' '--- Grain relay log ---' >&2
        tail -n 120 "$LOG" >&2
    fi
    printf 'Grain probe artifacts: %s\n' "$TMP"
    exit "$status"
}
trap on_exit EXIT HUP INT TERM

mkdir -p "$DATA"
cp "$ROOT/ops/relay/grain/config.yml" "$DATA/config.yml"
cp "$ROOT/ops/relay/grain/relay_metadata.json" "$DATA/relay_metadata.json"
cp "$ROOT/ops/relay/grain/whitelist.yml" "$DATA/whitelist.yml"
cp "$ROOT/ops/relay/grain/blacklist.yml" "$DATA/blacklist.yml"

sed -i.bak \
    -e "s|port: :8181|port: :${PORT}|" \
    -e "s|wss://relay.omachat.invalid|${RELAY_URL}|" \
    "$DATA/config.yml"

if [ -n "${GRAIN_BIN:-}" ]; then
    BIN=$GRAIN_BIN
else
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)
            ASSET=grain-linux-amd64.tar.gz
            SHA256=e000dad4c35669a32284a66876b6171e23fee2a12bfbfcce7824ebc3316a602d
            ;;
        Linux-aarch64|Linux-arm64)
            ASSET=grain-linux-arm64.tar.gz
            SHA256=80afc9a808ed8cde16c8e0ded349cba0801337ff0fd8a119842909fe085a6622
            ;;
        Darwin-arm64)
            ASSET=grain-darwin-arm64.tar.gz
            SHA256=a73d79c7ed5b14b314804067307d0f336f6255639084be6c6fe478be1a8ded90
            ;;
        Darwin-x86_64)
            ASSET=grain-darwin-amd64.tar.gz
            SHA256=3f7dee5531426dbc0b8c982a473e3ab16b0f8ace6e9604a368525cc2e931dbb6
            ;;
        *)
            printf 'unsupported Grain probe platform: %s-%s\n' "$(uname -s)" "$(uname -m)" >&2
            exit 1
            ;;
    esac

    ARCHIVE="$TMP/$ASSET"
    curl --fail --location --proto '=https' --tlsv1.2 \
        "https://github.com/0ceanSlim/grain/releases/download/${VERSION}/${ASSET}" \
        --output "$ARCHIVE"
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$ARCHIVE" | awk '{print $1}')
    else
        ACTUAL=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
    fi
    if [ "$ACTUAL" != "$SHA256" ]; then
        printf 'Grain archive checksum mismatch: expected %s, got %s\n' "$SHA256" "$ACTUAL" >&2
        exit 1
    fi
    tar -xzf "$ARCHIVE" -C "$TMP"
    BIN="$TMP/${ASSET%.tar.gz}/grain"
fi

"$BIN" --version

start_relay() {
    "$BIN" --data-dir "$DATA" >>"$LOG" 2>&1 &
    PID=$!
    python3 "$ROOT/conformance/relay/grain_probe.py" wait --url "$RELAY_URL"
}

start_relay
python3 "$ROOT/conformance/relay/grain_probe.py" seed \
    --url "$RELAY_URL" --state "$STATE"
stop_relay

start_relay
python3 "$ROOT/conformance/relay/grain_probe.py" verify \
    --url "$RELAY_URL" --state "$STATE"
stop_relay

printf '%s\n' 'Grain v0.7.1 AUTH, recipient isolation, signature rejection, and restart persistence passed.'
