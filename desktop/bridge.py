#!/usr/bin/env python3
"""Bounded, same-user IPC v3 adapter. No keys, network, disk cache or retries.

Quickshell owns this process; EOF on stdin closes the subscription. A broken
session exits so the UI can reconnect and obtain a fresh snapshot. In-flight
sends are never replayed: their outcome may be unknown.
"""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import struct
import sys
import time
import tomllib

VERSION = 3
LIMIT = 65536
TOPICS = ["status", "conversations", "messages", "delivery"]
ALLOWED = {"send", "status", "list-drafts", "get-draft", "save-draft", "hosted-conversations", "hosted-conversations-page", "hosted-history", "hosted-mark-read", "hosted-open-dm", "hosted-claim-handle", "hosted-resolve-handle", "hosted-create-workspace", "hosted-create-channel", "hosted-add-member"}
# Hosted network requests take longer than local storage or status requests.
DEADLINES = {"send": 30}
MAX_EXPIRED = 64


def encode(value):
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if len(data) > LIMIT:
        raise ValueError("Request exceeds IPC size limit")
    return data + b"\n"


class Lines:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        result = []
        while b"\n" in self.buffer:
            end = self.buffer.index(b"\n")
            if end > LIMIT:
                raise ValueError("IPC line exceeds size limit")
            value = json.loads(self.buffer[:end])
            del self.buffer[:end + 1]
            if not isinstance(value, dict):
                raise ValueError("IPC frame must be an object")
            result.append(value)
        if len(self.buffer) > LIMIT:
            raise ValueError("IPC line exceeds size limit")
        return result


def private_peer(path):
    metadata = os.stat(path, follow_symlinks=False)
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError("Daemon socket must belong to this user")
    if metadata.st_mode & 0o077:
        raise ValueError("Daemon socket must have private permissions")
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(2)
        stream.connect(path)
        _, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid():
            raise ValueError("Daemon peer must belong to this user")
        stream.setblocking(False)
        return stream
    except BaseException:
        stream.close()
        raise


class Session:
    def __init__(self, emit, timeout=5):
        self.emit = emit
        self.timeout = timeout
        self.pending = {}
        self.serial = 0
        self.output = bytearray()
        self.ready = False
        self.events = []
        self.sequence = -1
        self.expired = {}
        self.request("hello", {"minimum_version": VERSION, "maximum_version": VERSION}, "hello")

    def request(self, method, params=None, target=None, deadline=None):
        if len(self.pending) >= 32:
            raise ValueError("Too many pending requests")
        self.serial += 1
        identity = str(self.serial)
        value = {"version": VERSION, "id": identity, "method": method}
        if params is not None:
            value["params"] = params
        data = encode(value)
        if len(self.output) + len(data) > LIMIT * 2:
            raise ValueError("IPC write queue is full")
        self.pending[identity] = (target, time.monotonic() + (self.timeout if deadline is None else deadline))
        self.output.extend(data)

    def command(self, value):
        identity = value.get("id")
        if not isinstance(identity, str) or not identity.startswith("ui-") or len(identity) > 64:
            raise ValueError("Invalid UI request ID")
        method = value.get("method")
        if not self.ready or method not in ALLOWED:
            self.emit({"kind": "response", "id": identity, "ok": False, "error": "Daemon is not ready or command is unsupported"})
            return
        self.request(method, value.get("params"), identity, 30 if method.startswith("hosted-") else DEADLINES.get(method))

    def receive(self, value):
        if value.get("version") != VERSION:
            raise ValueError("Incompatible daemon: desktop requires IPC v3 (PR #230)")
        if "topic" in value:
            if value["topic"] not in TOPICS or not isinstance(value.get("payload"), dict):
                raise ValueError("Invalid daemon event")
            seq = value.get("sequence")
            if type(seq) is not int or seq <= self.sequence:
                raise ValueError("Invalid daemon event ordering")
            self.sequence = seq
            if self.ready:
                self.emit({"kind": "event", "data": value})
            else:
                if len(self.events) >= 64:
                    raise ValueError("Snapshot event buffer overflow")
                self.events.append(value)
            return
        identity = value.get("id")
        if value.get("status") not in ("ok", "error"):
            raise ValueError("Uncorrelated or malformed daemon response")
        if identity in self.expired:
            # The UI already treats this request as unknown; a resulting
            # message or delivery change reaches it through the subscription.
            del self.expired[identity]
            return
        if identity not in self.pending:
            raise ValueError("Uncorrelated or malformed daemon response")
        target, _ = self.pending.pop(identity)
        ok = value["status"] == "ok"
        result = value.get("result")
        error = value.get("error", {}).get("message", "Daemon rejected the request")
        if target == "hello":
            if not ok:
                raise ValueError(error)
            self.request("subscribe", {"topics": TOPICS}, "snapshot")
        elif target == "snapshot":
            if not ok or not isinstance(result, dict) or not isinstance(result.get("messages"), list):
                raise ValueError("Daemon did not provide a chat snapshot")
            self.emit({"kind": "snapshot", "data": result})
            self.ready = True
            for event in self.events:
                self.emit({"kind": "event", "data": event})
            self.events.clear()
            if result.get("status", {}).get("hosted", {}).get("state") == "connected":
                self.request("hosted-conversations", target="hosted-list", deadline=30)
        elif target == "hosted-list":
            self.emit({"kind": "hosted-list", "ok": ok, "data": result, "error": error if not ok else ""})
        else:
            self.emit({"kind": "response", "id": target, "ok": ok, "data": result, "error": error if not ok else ""})

    def check_deadlines(self):
        now = time.monotonic()
        for identity, (target, deadline) in list(self.pending.items()):
            if deadline > now:
                continue
            if target in ("hello", "snapshot"):
                raise TimeoutError("Daemon request timed out; pending delivery may be unknown")
            if len(self.expired) >= MAX_EXPIRED:
                raise TimeoutError("Daemon stopped answering; pending delivery may be unknown")
            del self.pending[identity]
            self.expired[identity] = target
            if target == "hosted-list":
                continue
            self.emit({"kind": "response", "id": target, "ok": False, "unknown": True,
                       "error": "The daemon did not answer in time. The outcome is unknown; check before repeating it."})


def read_theme(path):
    """Read data only; reject malformed/oversized palettes without losing the last valid one."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            return None
        values = tomllib.loads(raw.decode())
        return {key: value for key, value in values.items()
                if key in ("background", "foreground", "accent", "color1", "color3")
                and isinstance(value, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", value)}
    except (OSError, UnicodeError, ValueError):
        return None


class ThemeWatcher:
    def __init__(self, path):
        self.path = path
        self.current = None
        self.next_check = 0

    def poll(self, emit, now):
        if now < self.next_check:
            return
        self.next_check = now + 1
        palette = read_theme(self.path)
        if palette is None:
            palette = self.current if self.current is not None else {}
        if palette != self.current:
            self.current = palette
            emit({"kind": "theme", "data": palette})


def run(path):
    def emit(value):
        # One bounded frame at a time. Pipe backpressure stops socket reads,
        # rather than accumulating an unbounded queue of plaintext messages.
        sys.stdout.buffer.write(encode(value))
        sys.stdout.buffer.flush()

    try:
        theme_path = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "omarchy/current/theme/colors.toml"
        theme = ThemeWatcher(theme_path)
        theme.poll(emit, time.monotonic())
        with private_peer(path) as stream, selectors.DefaultSelector() as poll:
            session = Session(emit)
            incoming, commands = Lines(), Lines()
            poll.register(stream, selectors.EVENT_READ | selectors.EVENT_WRITE, "daemon")
            poll.register(sys.stdin, selectors.EVENT_READ, "ui")
            while True:
                theme.poll(emit, time.monotonic())
                session.check_deadlines()
                poll.modify(stream, selectors.EVENT_READ | (selectors.EVENT_WRITE if session.output else 0), "daemon")
                for key, flags in poll.select(0.1):
                    if key.data == "ui":
                        data = os.read(sys.stdin.fileno(), 8192)
                        if not data:
                            return 0
                        for value in commands.feed(data):
                            session.command(value)
                    else:
                        if flags & selectors.EVENT_WRITE and session.output:
                            try:
                                count = stream.send(session.output)
                                del session.output[:count]
                            except BlockingIOError:
                                pass
                        if flags & selectors.EVENT_READ:
                            data = stream.recv(8192)
                            if not data:
                                raise ConnectionError("Daemon disconnected")
                            for value in incoming.feed(data):
                                session.receive(value)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        try:
            emit({"kind": "disconnected", "error": str(error)[:512]})
        except (BrokenPipeError, OSError):
            pass
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    raise SystemExit(run(parser.parse_args().socket))
