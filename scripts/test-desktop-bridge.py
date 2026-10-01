#!/usr/bin/env python3
"""Production adapter test helper used by test-hosted-desktop.py."""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "desktop/bridge.py"

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
