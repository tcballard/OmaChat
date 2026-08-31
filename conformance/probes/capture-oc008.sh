#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
usage: capture-oc008.sh \
  --url wss://relay.example/path \
  --target-host relay.example \
  --socks5 127.0.0.1:9050 \
  --output evidence/oc008-YYYYMMDDTHHMMSSZ

Captures direct and system-Tor WebSocket reconnects, a syscall-level DNS-leak
observation, and the standalone Arti bootstrap/connect/shutdown result.
EOF
}

url=""
target_host=""
socks5=""
output=""
while (($#)); do
    case "$1" in
        --url) url=${2-}; shift 2 ;;
        --target-host) target_host=${2-}; shift 2 ;;
        --socks5) socks5=${2-}; shift 2 ;;
        --output) output=${2-}; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z $url || -z $target_host || -z $socks5 || -z $output ]]; then
    usage >&2
    exit 2
fi
if [[ ! $target_host =~ ^[A-Za-z0-9.-]+$ ]]; then
    printf 'target host must be a plain DNS hostname\n' >&2
    exit 2
fi
if [[ $url != wss://"$target_host"/* &&
      $url != wss://"$target_host" &&
      $url != wss://"$target_host":* ]]; then
    printf 'target host must exactly match the wss URL host\n' >&2
    exit 2
fi
if [[ -e $output ]]; then
    printf 'output path already exists: %s\n' "$output" >&2
    exit 2
fi

for command in cargo git jq rustc sha256sum strace tor uname; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 2
    fi
done

repo_root=$(git rev-parse --show-toplevel)
if [[ $(pwd -P) != "$repo_root" ]]; then
    printf 'run this capture from the OmaChat repository root\n' >&2
    exit 2
fi
if [[ -n $(git status --porcelain) ]]; then
    printf 'capture requires a clean worktree\n' >&2
    exit 2
fi

parent=$(dirname "$output")
mkdir -p "$parent"
staging=$(mktemp -d "$parent/.oc008-capture.XXXXXX")
chmod 700 "$staging"
cleanup() { rm -rf -- "$staging"; }
trap cleanup EXIT

cargo build --locked -p omachat-nostr --example transport_probe
probe=target/debug/examples/transport_probe

"$probe" --url "$url" --attempts 2 --handshake-only >"$staging/direct.json"
strace -f -qq -s 512 -e trace=network,write \
    -o "$staging/system-tor.strace" \
    "$probe" --url "$url" --socks5 "$socks5" --attempts 2 --handshake-only \
    >"$staging/system-tor.json"

if grep -Eq 'sin_port=htons\((53|853)\)' "$staging/system-tor.strace"; then
    printf 'system-Tor capture observed a DNS socket from the probe process\n' >&2
    exit 1
fi
if ! grep -Fq "$target_host" "$staging/system-tor.strace"; then
    printf 'SOCKS trace does not contain the unresolved target hostname\n' >&2
    exit 1
fi

jq -e '
  .route == "direct" and .attempts >= 2 and
  .interaction == "handshake-only" and .reconnect == "passed"
' "$staging/direct.json" >/dev/null
jq -e '
  .route == "socks5" and .attempts >= 2 and .remote_dns == true and
  .interaction == "handshake-only" and .reconnect == "passed"
' "$staging/system-tor.json" >/dev/null

cargo run --quiet --locked \
    --manifest-path conformance/probes/arti/Cargo.toml -- \
    --host "$target_host" --port 443 --timeout-seconds 180 \
    >"$staging/arti.json"
jq -e '
  .bootstrap == "passed" and .connect == "passed" and
  .dns_owner == "arti" and .shutdown == "streams-and-client-dropped"
' "$staging/arti.json" >/dev/null

os_release=$(if [[ -f /etc/os-release ]]; then cat /etc/os-release; fi)
jq -n \
    --arg captured_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg commit "$(git rev-parse HEAD)" \
    --arg url "$url" \
    --arg target_host "$target_host" \
    --arg socks5 "$socks5" \
    --arg kernel "$(uname -srmo)" \
    --arg os_release "$os_release" \
    --arg tor_version "$(tor --version | head -n 1)" \
    --arg rustc_version "$(rustc --version)" \
    --arg cargo_version "$(cargo --version)" \
    --arg strace_version "$(strace --version | head -n 1)" \
    '{
      schema_version: 1,
      captured_at: $captured_at,
      commit: $commit,
      url: $url,
      target_host: $target_host,
      socks5: $socks5,
      kernel: $kernel,
      os_release: $os_release,
      tor_version: $tor_version,
      rustc_version: $rustc_version,
      cargo_version: $cargo_version,
      strace_version: $strace_version
    }' >"$staging/metadata.json"

(
    cd "$staging"
    sha256sum arti.json direct.json metadata.json system-tor.json system-tor.strace \
        >SHA256SUMS
    sha256sum --check SHA256SUMS >/dev/null
)

chmod 600 "$staging"/*
mv "$staging" "$output"
trap - EXIT
printf 'OC-008 capture complete: %s\n' "$output"
