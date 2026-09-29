#!/usr/bin/env python3
"""Explicit, local relay-config editor. No network, credentials, or service control."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import stat
import tempfile
from urllib.parse import urlsplit, urlunsplit
import uuid

LIMIT = 65536


def default_path():
    root = os.environ.get("XDG_CONFIG_HOME", "")
    if not os.path.isabs(root):
        root = str(Path.home() / ".config")
    return Path(root) / "omachat/config.json"


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("Configuration contains duplicate JSON keys; resolve them first.")
        result[key] = value
    return result


def invalid_constant(_):
    raise ValueError("Configuration must use standard JSON numbers.")


def read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, {}
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Configuration must be a regular file owned by this user.")
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Configuration exceeds the 64 KiB editing limit.")
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a JSON object.")
    return raw, value


def revision(raw):
    return "missing" if raw is None else hashlib.sha256(raw).hexdigest()


def relays(values):
    if not isinstance(values, list) or len(values) > 16:
        raise ValueError("Enter at most 16 relay URLs per transport.")
    result = []
    for value in values:
        if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
            raise ValueError("Invalid relay URL.")
        url = urlsplit(value)
        host = url.hostname
        try:
            loopback = ipaddress.ip_address(host or "").is_loopback
        except ValueError:
            loopback = False
        if not host or url.username is not None or url.password is not None or "?" in value or "#" in value or (url.scheme != "wss" and not (url.scheme == "ws" and loopback)):
            raise ValueError("Use wss:// relays, or ws:// numeric loopback; no credentials, query or fragment.")
        port = url.port
        if port == 0:
            raise ValueError("Relay port must be between 1 and 65535.")
        host = host.encode("idna").decode("ascii").lower()
        if ":" in host:
            if "%" in host:
                raise ValueError("Scoped IPv6 relay addresses are not supported.")
            ipaddress.IPv6Address(host)
            host = "[" + host + "]"
        elif not re.fullmatch(r"[a-z0-9.-]+", host) or len(host) > 253 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.rstrip(".").split(".")):
            raise ValueError("Invalid relay hostname.")
        authority = host + (":" + str(port) if port is not None and port != (443 if url.scheme == "wss" else 80) else "")
        canonical = urlunsplit((url.scheme, authority, url.path or "/", "", ""))
        if canonical in result:
            raise ValueError("Duplicate relay URL.")
        result.append(canonical)
    return result


def safe_path(path):
    path = Path(os.path.abspath(path))
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise ValueError("Choose a configuration path without symlinks.")
    return path


def snapshot(path):
    path = safe_path(path)
    raw, value = read(path)
    rooms = value.get("rooms")
    if rooms is None:
        rooms = {}
    if not isinstance(rooms, dict):
        raise ValueError("Existing rooms configuration must be an object.")
    return {"path": str(path), "revision": revision(raw), "exists": raw is not None,
            "dm_relays": relays(value.get("dm_relays", [])),
            "room_relays": relays(rooms.get("relays", []))}


def apply(path, request):
    path = safe_path(path)
    dm, room = relays(request.get("dm_relays")), relays(request.get("room_relays"))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_uid != os.getuid() or path.parent.stat().st_mode & 0o022:
        raise ValueError("Configuration directory must be owned by this user and not writable by other users.")
    lock = os.open(path.with_name(path.name + ".omachat.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(lock, "rb+") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Unsafe configuration lock.")
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw, value = read(path)
        if request.get("revision") != revision(raw):
            raise ValueError("Configuration changed. Reload it before saving; your entries have not been applied.")
        rooms = value.get("rooms")
        if rooms is not None and not isinstance(rooms, dict):
            raise ValueError("Existing rooms configuration must be an object.")
        value["dm_relays"] = dm
        if room or rooms is not None:
            value["rooms"] = {**(rooms or {}), "relays": room}
        encoded = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
        if len(encoded) > LIMIT:
            raise ValueError("Updated configuration exceeds the editing limit.")
        backup = ""
        if raw is not None:
            backup = str(path.with_name(path.name + ".backup-" + uuid.uuid4().hex))
            with os.fdopen(os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
        fd, temporary = tempfile.mkstemp(prefix=".omachat-config-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(encoded); output.flush(); os.fsync(output.fileno())
            if revision(read(path)[0]) != revision(raw):
                raise ValueError("Configuration changed during save. Reload before trying again.")
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return {**snapshot(path), "backup": backup, "restart_required": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.environ.get("OMACHAT_CONFIG") or str(default_path()))
    parser.add_argument("--request", required=True)
    args = parser.parse_args()
    try:
        if len(args.request.encode()) > LIMIT:
            raise ValueError("Request exceeds editing limit.")
        request = json.loads(args.request)
        if request.get("method") == "read":
            result = snapshot(args.config)
        elif request.get("method") == "apply":
            result = apply(args.config, request)
        else:
            raise ValueError("Unknown setup operation.")
        print(json.dumps({"ok": True, "data": result}, ensure_ascii=False))
    except (ValueError, OSError, TypeError, AttributeError) as error:
        print(json.dumps({"ok": False, "error": str(error)[:512]}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
