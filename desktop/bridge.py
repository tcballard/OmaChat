#!/usr/bin/env python3
"""Bounded, same-user IPC v2 adapter. No keys, network, disk cache or retries.

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

VERSION = 2
LIMIT = 65536
TOPICS = ["status", "conversations", "messages", "delivery"]
ALLOWED = {"send", "status", "list-rooms", "join-room", "leave-room", "room-members", "list-drafts", "get-draft", "save-draft"}


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
        self.request("hello", {"minimum_version": VERSION, "maximum_version": VERSION}, "hello")

    def request(self, method, params=None, target=None):
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
        self.pending[identity] = (target, time.monotonic() + self.timeout)
        self.output.extend(data)

    def command(self, value):
        identity = value.get("id")
        if not isinstance(identity, str) or not identity.startswith("ui-") or len(identity) > 64:
            raise ValueError("Invalid UI request ID")
        method = value.get("method")
        if not self.ready or method not in ALLOWED:
            self.emit({"kind": "response", "id": identity, "ok": False, "error": "Daemon is not ready or command is unsupported"})
            return
        self.request(method, value.get("params"), identity)

    def receive(self, value):
        if value.get("version") != VERSION:
            raise ValueError("Incompatible daemon: desktop requires IPC v2 (PR #230)")
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
        if identity not in self.pending or value.get("status") not in ("ok", "error"):
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
            self.request("list-rooms", target="rooms")
        elif target == "rooms":
            if ok:
                self.emit({"kind": "rooms", "data": result})
        else:
            self.emit({"kind": "response", "id": target, "ok": ok, "data": result, "error": error if not ok else ""})

    def check_deadlines(self):
        if any(deadline <= time.monotonic() for _, deadline in self.pending.values()):
            raise TimeoutError("Daemon request timed out; pending delivery may be unknown")


def run(path):
    def emit(value):
        # One bounded frame at a time. Pipe backpressure stops socket reads,
        # rather than accumulating an unbounded queue of plaintext messages.
        sys.stdout.buffer.write(encode(value))
        sys.stdout.buffer.flush()

    try:
        # Read only the bounded, current desktop palette. Never parse executable
        # theme files and never persist messages or keys in this adapter.
        theme_path = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "omarchy/current/theme/colors.toml"
        try:
            with theme_path.open("rb") as theme_file:
                raw = theme_file.read(16385)
            theme = tomllib.loads(raw.decode()) if len(raw) <= 16384 else {}
            colors = {k: v for k, v in theme.items() if k in ("background", "foreground", "accent") and isinstance(v, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", v)}
            emit({"kind": "theme", "data": colors})
        except (OSError, UnicodeError, ValueError):
            pass
        with private_peer(path) as stream, selectors.DefaultSelector() as poll:
            session = Session(emit)
            incoming, commands = Lines(), Lines()
            poll.register(stream, selectors.EVENT_READ | selectors.EVENT_WRITE, "daemon")
            poll.register(sys.stdin, selectors.EVENT_READ, "ui")
            while True:
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
