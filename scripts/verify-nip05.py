#!/usr/bin/env python3
"""Verify a deployed NIP-05 handle against an independently obtained public key."""
import argparse
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 65536


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoint(handle, base_url=None):
    parts = handle.lower().split('@')
    if len(parts) != 2 or not re.fullmatch(r'[a-z0-9_.-]+', parts[0]):
        raise ValueError('use name@domain for the handle')
    name, domain = parts
    labels = domain.split('.')
    if len(labels) < 2 or len(domain) > 253 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels
    ):
        raise ValueError('use a DNS domain without a URL, port or path')
    base = f'https://{domain}'
    if base_url is not None:
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme != 'http' or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                parsed.path not in ('', '/') or parsed.query or parsed.fragment or
                not ipaddress.ip_address(parsed.hostname).is_loopback):
            raise ValueError('--test-base-url must be numeric loopback HTTP')
        base = base_url.rstrip('/')
    return name, f'{base}/.well-known/nostr.json?{urllib.parse.urlencode({"name": name})}'


def verify(handle, expected_key, base_url=None):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_key):
        raise ValueError('expected public key must be 64 lowercase hexadecimal characters')
    name, url = endpoint(handle, base_url)
    opener = urllib.request.build_opener(NoRedirects(), urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={'Accept': 'application/json', 'Origin': 'https://omachat.test'})
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise ValueError(f'expected HTTP 200, received {response.status}')
        if response.headers.get_content_type() != 'application/json':
            raise ValueError('NIP-05 endpoint must return application/json')
        if response.headers.get('Access-Control-Allow-Origin') != '*':
            raise ValueError('NIP-05 endpoint must allow cross-origin clients with Access-Control-Allow-Origin: *')
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError('NIP-05 response exceeds 64 KiB')
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get('names'), dict):
        raise ValueError('NIP-05 response must contain a names object')
    if data['names'].get(name) != expected_key:
        raise ValueError('handle does not resolve to the expected public key')
    return url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('handle')
    parser.add_argument('public_key', help='pubkey field from omachat-ctl identity show; never an nsec')
    parser.add_argument('--test-base-url', help='explicit numeric-loopback HTTP endpoint for local testing')
    args = parser.parse_args()
    try:
        url = verify(args.handle, args.public_key, args.test_base_url)
    except (ValueError, OSError, urllib.error.URLError) as error:
        print(f'NIP-05 verification failed: {error}', file=sys.stderr)
        return 1
    print(f'PASS: {args.handle.lower()} resolves to the expected public key; JSON and CORS verified at {url}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
