#!/usr/bin/env python3
"""The real release daemon serves desktop/bridge.py: drafts, conflicts, restart.

Runs against an isolated temporary state directory and socket with the file
key provider; it never touches the account's real identity, configuration,
history or drafts. It proves the adapter/daemon IPC contract on this machine,
not a Quickshell window, relay reachability or message delivery.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
DAEMON = Path(os.environ.get("OMACHAT_DAEMON", ROOT / "target/release/omachatd"))
BRIDGE = ROOT / "desktop/bridge.py"
PEER = "dm:" + "a" * 64


class Bridge:
    def __init__(self, socket_path, env):
        self.process = subprocess.Popen([sys.executable, str(BRIDGE), "--socket", str(socket_path)], env=env,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.serial = 0
        self.frames = []
        while True:
            frame = self.read()
            assert frame is not None, "bridge produced no snapshot"
            if frame.get("kind") == "disconnected":
                raise SystemExit(f"bridge could not connect: {frame['error']}")
            if frame.get("kind") == "snapshot":
                break

    def read(self, timeout=8):
        ready, _, _ = select.select([self.process.stdout], [], [], timeout)
        if not ready:
            return None
        line = self.process.stdout.readline()
        frame = json.loads(line) if line else {"kind": "eof"}
        self.frames.append(frame)
        return frame

    def call(self, method, params=None):
        self.serial += 1
        identity = f"ui-{self.serial}"
        request = {"id": identity, "method": method}
        if params is not None:
            request["params"] = params
        self.process.stdin.write((json.dumps(request) + "\n").encode())
        self.process.stdin.flush()
        while True:
            frame = self.read()
            assert frame is not None, f"no reply to {method}"
            if frame.get("kind") == "response" and frame.get("id") == identity:
                return frame

    def close(self):
        self.process.stdin.close()
        code = self.process.wait(timeout=5)
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()
        return code


def start_daemon(socket_path, state, env):
    process = subprocess.Popen([str(DAEMON), "--file-key", "--state", str(state), "--socket", str(socket_path)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(400):
        if socket_path.exists():
            return process
        if process.poll() is not None:
            raise SystemExit("daemon exited: " + process.stderr.read().decode()[-800:])
        time.sleep(0.05)
    raise SystemExit("daemon did not publish its socket")


def main():
    if not DAEMON.exists():
        raise SystemExit(f"build the daemon first: {DAEMON} is missing")
    with tempfile.TemporaryDirectory(prefix="omachat-desktop-bridge-") as temporary:
        root = Path(temporary)
        runtime, state = root / "run", root / "state"
        runtime.mkdir(mode=0o700)
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_CONFIG_HOME=str(root / "config"),
                   XDG_STATE_HOME=str(root / "statehome"), HOME=str(root))
        socket_path = runtime / "omachat/omachat.sock"
        daemon = start_daemon(socket_path, state, env)
        try:
            assert os.stat(socket_path).st_mode & 0o777 == 0o600, "socket must be private"
            first = Bridge(socket_path, env)
            status = first.call("status")
            assert status["ok"] and status["data"]["drafts_version"] == 1, status
            assert len(status["data"]["nostr_public_key"]) == 64
            assert first.call("list-drafts")["data"] == {"drafts": []}
            saved = first.call("save-draft", {"conversation": PEER, "text": "written by the first window", "expected_revision": 0})
            assert saved["ok"] and saved["data"]["saved"] is True, saved
            revision = saved["data"]["revision"]
            second = Bridge(socket_path, env)
            seen = second.call("get-draft", {"conversation": PEER})["data"]
            assert seen["text"] == "written by the first window" and seen["revision"] == revision
            stale = second.call("save-draft", {"conversation": PEER, "text": "stale", "expected_revision": 0})["data"]
            assert stale["saved"] is False and stale["text"] == "written by the first window", stale
            fresh = second.call("save-draft", {"conversation": PEER, "text": "second window wins", "expected_revision": revision})["data"]
            assert fresh["saved"] is True and fresh["revision"] > revision
            late = first.call("save-draft", {"conversation": PEER, "text": "first window, late", "expected_revision": revision})["data"]
            assert late["saved"] is False and late["text"] == "second window wins", late
            refused = first.call("save-draft", {"conversation": PEER, "text": "x" * 4097, "expected_revision": fresh["revision"]})
            assert not refused["ok"], refused
            blocked = first.call("panic", {"confirmation": "ERASE"})
            assert not blocked["ok"], blocked
            rejected = first.call("send", {"conversation": "room:not-a-room", "text": "hi"})
            assert not rejected["ok"], rejected
            daemon.terminate()
            assert daemon.wait(timeout=15) == 0, "daemon did not stop cleanly"
            notice = first.read()
            assert notice and notice["kind"] == "disconnected", notice
            assert first.close() == 1 and second.close() == 1
            daemon = start_daemon(socket_path, state, env)
            third = Bridge(socket_path, env)
            listed = third.call("list-drafts")["data"]["drafts"]
            assert listed == [{"conversation": PEER, "revision": fresh["revision"]}], listed
            restored = third.call("get-draft", {"conversation": PEER})["data"]
            assert restored["text"] == "second window wins", restored
            cleared = third.call("save-draft", {"conversation": PEER, "text": "", "expected_revision": restored["revision"]})["data"]
            assert cleared["saved"] is True and third.call("list-drafts")["data"]["drafts"] == []
            assert third.close() == 0, "bridge must exit 0 on stdin EOF"
            for record in (state / "records").iterdir():
                assert b"second window wins" not in record.read_bytes(), "draft text must be sealed"
        finally:
            if daemon.poll() is None:
                daemon.terminate()
                daemon.wait(timeout=15)
            daemon.stderr.close()
    print("PASS: real daemon through desktop/bridge.py — private socket, drafts, two-client conflicts, restart persistence, sealed storage, clean exit")


if __name__ == "__main__":
    main()
