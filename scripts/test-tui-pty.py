#!/usr/bin/env python3
"""Exercise the actual binaries, terminal state, live IPC and daemon reattach."""
import argparse
import codecs
import re
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import termios
import time


_screens = {}

class Screen:
    """Small VT screen model for the cursor-addressed ANSI output under test."""
    def __init__(self):
        self.rows = [[" "] * 80 for _ in range(24)]
        self.x = self.y = 0
        self.pending = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def feed(self, data):
        self.pending += self.decoder.decode(data)
        while self.pending:
            if self.pending.startswith("\x1b"):
                match = re.match(r"\x1b\[([0-9;?]*)([@-~])", self.pending)
                if not match:
                    return
                params, command = match.groups()
                values = [int(v or 0) for v in params.lstrip("?").split(";")]
                if command in ("H", "f"):
                    self.y = max(0, (values[0] or 1) - 1)
                    self.x = max(0, ((values[1] if len(values) > 1 else 1) or 1) - 1)
                elif command == "J" and values[0] == 2:
                    self.rows = [[" "] * 80 for _ in range(24)]
                self.pending = self.pending[match.end():]
            else:
                char, self.pending = self.pending[0], self.pending[1:]
                if char == "\r": self.x = 0
                elif char == "\n": self.y += 1
                elif char.isprintable():
                    if self.y < 24 and self.x < 80: self.rows[self.y][self.x] = char
                    self.x += 1

    def text(self):
        return "\n".join("".join(row) for row in self.rows)


def read_until(fd, needle, seconds=10):
    screen = _screens.setdefault(fd, Screen())
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if select.select([fd], [], [], 0.1)[0]:
            try: screen.feed(os.read(fd, 65536))
            except OSError: break
            if needle.decode() in screen.text(): return screen.text()
    raise AssertionError(f"terminal never displayed {needle!r}: {screen.text()!r}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, default=Path("target/release"))
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    with tempfile.TemporaryDirectory(prefix="omachat-pty-") as directory:
        root = Path(directory)
        socket = root / "ipc" / "omachat.sock"
        config = root / "config.json"
        config.write_text(json.dumps({"storage_provider": "file", "joined_geohashes": ["gcpvj"]}))
        log = open(root / "daemon.log", "wb")
        daemon = None
        client = None

        def start_daemon():
            process = subprocess.Popen([str(binaries / "omachatd"), "--config", str(config), "--state", str(root / "state"), "--socket", str(socket)], stdout=log, stderr=log)
            for _ in range(100):
                if socket.exists():
                    return process
                if process.poll() is not None:
                    raise AssertionError("daemon failed to start")
                time.sleep(0.05)
            process.terminate()
            raise AssertionError("daemon socket not ready")

        def ctl(*command):
            return subprocess.check_output([str(binaries / "omachat-ctl"), "--socket", str(socket), *command], timeout=10)

        try:
            daemon = start_daemon()
            for ending in ["detach", "SIGINT", "SIGTERM"]:
                master, slave = pty.openpty()
                _screens.pop(master, None)
                fcntl.ioctl(slave, termios.TIOCSWINSZ, b'\x18\x00\x50\x00\x00\x00\x00\x00')
                before = termios.tcgetattr(slave)

                def terminal_session():
                    os.setsid()
                    fcntl.ioctl(0, termios.TIOCSCTTY, 0)

                client = subprocess.Popen([str(binaries / "omachat"), "--socket", str(socket)], stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal_session)
                read_until(master, b"connected")
                assert not termios.tcgetattr(slave)[3] & termios.ICANON
                marker = f"external-{ending}"
                ctl("send", "#gcpvj", marker)
                read_until(master, marker.encode())
                if ending == "detach":
                    daemon.terminate()
                    daemon.wait(timeout=10)
                    read_until(master, b"disconnected")
                    daemon = start_daemon()
                    read_until(master, b"connected", 15)
                    ctl("send", "#gcpvj", "after-reconnect")
                    read_until(master, b"after-reconnect")
                    os.write(master, b"/detach\r")
                else:
                    client.send_signal(getattr(signal, ending))
                assert client.wait(timeout=10) == 0
                assert termios.tcgetattr(slave) == before, "terminal flags were not restored"
                assert daemon.poll() is None, "TUI exit stopped daemon"
                os.close(master)
                os.close(slave)
                client = None
            print("PASS: live messages, restart/reattach, detach, SIGINT/SIGTERM and terminal restoration")
        finally:
            if client and client.poll() is None:
                client.kill()
                client.wait()
            if daemon and daemon.poll() is None:
                daemon.terminate()
                daemon.wait(timeout=10)
            log.close()


if __name__ == "__main__":
    main()
