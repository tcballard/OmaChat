#!/bin/sh
set -eu

fail() {
    printf 'OmaChat Grain startup refused: %s\n' "$1" >&2
    exit 64
}

require_https_url() {
    name=$1
    value=$2
    case "$value" in
        https://*) ;;
        *) fail "$name must be an https:// URL" ;;
    esac
    case "$value" in
        *[[:space:]\|]*) fail "$name contains unsafe characters" ;;
    esac
}

escape_sed() {
    printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

[ "${OMACHAT_RELAY_DEPLOYMENT_APPROVED:-}" = "reviewed-deployment-pr" ] ||
    fail "set OMACHAT_RELAY_DEPLOYMENT_APPROVED only from an explicitly approved deployment"
[ -n "${OMACHAT_RELAY_RETENTION_POLICY_ID:-}" ] ||
    fail "OMACHAT_RELAY_RETENTION_POLICY_ID is required after issue #79 is decided"

domain=${OMACHAT_RELAY_DOMAIN:-}
case "$domain" in
    ""|.*|*.|*..*|*[!a-z0-9.-]*) fail "OMACHAT_RELAY_DOMAIN must be a lowercase DNS name" ;;
esac

owner=${OMACHAT_RELAY_OWNER_PUBKEY:-}
[ "${#owner}" -eq 64 ] || fail "OMACHAT_RELAY_OWNER_PUBKEY must be 64 lowercase hex characters"
case "$owner" in
    *[!0-9a-f]*) fail "OMACHAT_RELAY_OWNER_PUBKEY must be 64 lowercase hex characters" ;;
esac

contact=${OMACHAT_RELAY_CONTACT:-}
case "$contact" in
    https://*|mailto:*) ;;
    *) fail "OMACHAT_RELAY_CONTACT must be an https:// or mailto: URI" ;;
esac
case "$contact" in
    *[[:space:]\|]*) fail "OMACHAT_RELAY_CONTACT contains unsafe characters" ;;
esac

require_https_url OMACHAT_RELAY_PRIVACY_URL "${OMACHAT_RELAY_PRIVACY_URL:-}"
require_https_url OMACHAT_RELAY_TERMS_URL "${OMACHAT_RELAY_TERMS_URL:-}"
require_https_url OMACHAT_RELAY_POSTING_URL "${OMACHAT_RELAY_POSTING_URL:-}"

template_dir=${OMACHAT_GRAIN_TEMPLATE_DIR:-/etc/omachat-grain}
state_dir=${OMACHAT_GRAIN_STATE_DIR:-/var/lib/grain}
grain_bin=${GRAIN_BIN:-/usr/local/bin/grain}
[ -x "$grain_bin" ] || fail "Grain binary is not executable"
for file in config.yml relay_metadata.json whitelist.yml blacklist.yml; do
    [ -f "$template_dir/$file" ] || fail "missing template $file"
done
mkdir -p "$state_dir"
umask 077

domain_sed=$(escape_sed "$domain")
owner_sed=$(escape_sed "$owner")
contact_sed=$(escape_sed "$contact")
privacy_sed=$(escape_sed "$OMACHAT_RELAY_PRIVACY_URL")
terms_sed=$(escape_sed "$OMACHAT_RELAY_TERMS_URL")
posting_sed=$(escape_sed "$OMACHAT_RELAY_POSTING_URL")

sed "s|wss://relay.omachat.invalid|wss://${domain_sed}|g" \
    "$template_dir/config.yml" >"$state_dir/config.yml.tmp"
mv "$state_dir/config.yml.tmp" "$state_dir/config.yml"

sed \
    -e "s|\"pubkey\": \"\"|\"pubkey\": \"${owner_sed}\"|" \
    -e "s|\"contact\": \"\"|\"contact\": \"${contact_sed}\"|" \
    -e "s|\"privacy_policy\": \"\"|\"privacy_policy\": \"${privacy_sed}\"|" \
    -e "s|\"terms_of_service\": \"\"|\"terms_of_service\": \"${terms_sed}\"|" \
    -e "s|\"posting_policy\": \"\"|\"posting_policy\": \"${posting_sed}\"|" \
    "$template_dir/relay_metadata.json" >"$state_dir/relay_metadata.json.tmp"
mv "$state_dir/relay_metadata.json.tmp" "$state_dir/relay_metadata.json"

cp "$template_dir/whitelist.yml" "$state_dir/whitelist.yml.tmp"
mv "$state_dir/whitelist.yml.tmp" "$state_dir/whitelist.yml"
cp "$template_dir/blacklist.yml" "$state_dir/blacklist.yml.tmp"
mv "$state_dir/blacklist.yml.tmp" "$state_dir/blacklist.yml"

export GRAIN_OWNER_PUBKEY=$owner
exec "$grain_bin" --data-dir "$state_dir" "$@"
