#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPS=$ROOT/ops/relay/grain
COMPOSE=$OPS/compose.yml
ENTRYPOINT=$OPS/container-entrypoint.sh
TMP=$(mktemp -d /tmp/omachat-grain-deployment.XXXXXX)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

sh -n "$ENTRYPOINT"

for digest in \
    e000dad4c35669a32284a66876b6171e23fee2a12bfbfcce7824ebc3316a602d \
    80afc9a808ed8cde16c8e0ded349cba0801337ff0fd8a119842909fe085a6622
do
    grep -F "$digest" "$OPS/Dockerfile" >/dev/null
    grep -F "$digest" "$ROOT/scripts/test-grain-relay.sh" >/dev/null
done
grep -F 'sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132' \
    "$OPS/Dockerfile" >/dev/null
grep -F 'sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648' \
    "$COMPOSE" >/dev/null

mkdir "$TMP/state"
env \
    OMACHAT_RELAY_DEPLOYMENT_APPROVED=reviewed-deployment-pr \
    OMACHAT_RELAY_RETENTION_POLICY_ID=test-policy \
    OMACHAT_RELAY_DOMAIN=relay.example.test \
    OMACHAT_RELAY_OWNER_PUBKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    OMACHAT_RELAY_CONTACT=mailto:relay@example.test \
    OMACHAT_RELAY_PRIVACY_URL=https://example.test/privacy \
    OMACHAT_RELAY_TERMS_URL=https://example.test/terms \
    OMACHAT_RELAY_POSTING_URL=https://example.test/posting \
    OMACHAT_GRAIN_TEMPLATE_DIR="$OPS" \
    OMACHAT_GRAIN_STATE_DIR="$TMP/state" \
    GRAIN_BIN=/usr/bin/true \
    sh "$ENTRYPOINT"

grep -F 'relay_url: "wss://relay.example.test"' "$TMP/state/config.yml" >/dev/null
if grep -F 'relay.omachat.invalid' "$TMP/state/config.yml" >/dev/null; then
    printf '%s\n' 'rendered Grain config retained invalid relay URL' >&2
    exit 1
fi
grep -F '"pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"' \
    "$TMP/state/relay_metadata.json" >/dev/null
grep -F '"privacy_policy": "https://example.test/privacy"' \
    "$TMP/state/relay_metadata.json" >/dev/null

if env \
    OMACHAT_RELAY_RETENTION_POLICY_ID=test-policy \
    OMACHAT_RELAY_DOMAIN=relay.example.test \
    OMACHAT_RELAY_OWNER_PUBKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    OMACHAT_RELAY_CONTACT=mailto:relay@example.test \
    OMACHAT_RELAY_PRIVACY_URL=https://example.test/privacy \
    OMACHAT_RELAY_TERMS_URL=https://example.test/terms \
    OMACHAT_RELAY_POSTING_URL=https://example.test/posting \
    OMACHAT_GRAIN_TEMPLATE_DIR="$OPS" \
    OMACHAT_GRAIN_STATE_DIR="$TMP/refused" \
    GRAIN_BIN=/usr/bin/true \
    sh "$ENTRYPOINT" >/dev/null 2>&1
then
    printf '%s\n' 'Grain entrypoint accepted missing deployment approval' >&2
    exit 1
fi

command -v docker >/dev/null 2>&1 || {
    printf '%s\n' 'docker is required to validate the relay Compose contract' >&2
    exit 1
}
OMACHAT_RELAY_DEPLOYMENT_APPROVED=reviewed-deployment-pr \
OMACHAT_RELAY_RETENTION_POLICY_ID=test-policy \
OMACHAT_RELAY_DOMAIN=relay.example.test \
OMACHAT_RELAY_OWNER_PUBKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
OMACHAT_RELAY_CONTACT=mailto:relay@example.test \
OMACHAT_RELAY_PRIVACY_URL=https://example.test/privacy \
OMACHAT_RELAY_TERMS_URL=https://example.test/terms \
OMACHAT_RELAY_POSTING_URL=https://example.test/posting \
OMACHAT_ACME_EMAIL=relay@example.test \
    docker compose --profile candidate --file "$COMPOSE" config --format json >"$TMP/compose.json"

python3 - "$TMP/compose.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    compose = json.load(handle)

grain = compose["services"]["grain"]
caddy = compose["services"]["caddy"]
assert "ports" not in grain, "Grain must not publish a host port"
assert set(grain["networks"]) == {"relay_private"}
assert compose["networks"]["relay_private"]["internal"] is True
assert set(caddy["networks"]) == {"relay_private", "relay_public"}
assert caddy["image"].endswith(
    "@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
)
assert grain["read_only"] is True
assert caddy["read_only"] is True
assert "ALL" in grain["cap_drop"]
assert "no-new-privileges:true" in grain["security_opt"]
PY

printf '%s\n' 'Grain candidate deployment contract passed; no relay was started.'
