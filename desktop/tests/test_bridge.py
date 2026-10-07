import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "bridge.py"
spec = importlib.util.spec_from_file_location("bridge", SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class ThemeTests(unittest.TestCase):
    def test_live_symlink_switch_and_partial_write_retains_last_good_theme(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dark = root / "dark.toml"; light = root / "light.toml"
            dark.write_text('background = "#1a1b26"\nforeground = "#c0caf5"\n')
            light.write_text('background = "#eff1f5"\nforeground = "#4c4f69"\n')
            current = root / "colors.toml"; current.symlink_to(dark)
            watcher = bridge.ThemeWatcher(current); frames = []
            watcher.poll(frames.append, 0)
            watcher.poll(frames.append, .5)
            self.assertEqual(len(frames), 1)
            current.unlink(); current.symlink_to(light)
            watcher.poll(frames.append, 1)
            self.assertEqual(frames[-1]["data"]["background"], "#eff1f5")
            light.write_text('background = "')
            watcher.poll(frames.append, 2)
            self.assertEqual(len(frames), 2)
            light.write_text('background = "#282828"')
            watcher.poll(frames.append, 3)
            self.assertEqual(frames[-1]["data"]["background"], "#282828")

    def test_theme_inputs_are_bounded_and_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "colors.toml"
            frames = []; bridge.ThemeWatcher(path).poll(frames.append, 0)
            self.assertEqual(frames, [{"kind":"theme", "data":{}}])
            path.write_text('accent = "#abc123"\nbackground = "red"\ncommand = "ignored"\n')
            self.assertEqual(bridge.read_theme(path), {"accent":"#abc123"})
            path.write_text(" " * 16385)
            self.assertIsNone(bridge.read_theme(path))


class ProtocolTests(unittest.TestCase):
    def ready_session(self):
        frames = []
        session = bridge.Session(frames.append)
        session.output.clear()
        session.receive({"version": 3, "id": "1", "status": "ok", "result": {}})
        session.output.clear()
        session.receive({"version": 3, "id": "2", "status": "ok", "result": {"status": {}, "messages": []}})
        session.output.clear()
        return session, frames

    def test_fragmented_unicode_and_multiple_frames(self):
        lines = bridge.Lines()
        data = bridge.encode({"text": "🍵\nhello"})
        self.assertEqual(lines.feed(data[:12]), [])
        self.assertEqual(lines.feed(data[12:] + b'{}\n'), [{"text": "🍵\nhello"}, {}])

    def test_malformed_and_oversized_lines(self):
        for data in [b"[]\n", b"broken\n", b"x" * (bridge.LIMIT + 1), b"x" * (bridge.LIMIT + 1) + b"\n"]:
            with self.assertRaises(ValueError): bridge.Lines().feed(data)

    def test_snapshot_precedes_buffered_event(self):
        frames = []
        session = bridge.Session(frames.append)
        session.receive({"version": 3, "id": "1", "status": "ok", "result": {}})
        event = {"version": 3, "sequence": 1, "topic": "messages", "payload": {"text": "live"}}
        session.receive(event)
        self.assertEqual(frames, [])
        session.receive({"version": 3, "id": "2", "status": "ok", "result": {"messages": []}})
        self.assertEqual([v["kind"] for v in frames], ["snapshot", "event"])

    def test_rejects_old_version_and_wrong_correlation(self):
        for frame in [{"version": 1}, {"version": 3, "id": "alien", "status": "ok"}]:
            session, _ = self.ready_session()
            with self.assertRaises(ValueError): session.receive(frame)

    def test_no_destructive_commands(self):
        session, frames = self.ready_session()
        session.command({"id": "ui-1", "method": "panic", "params": {"confirmation": "ERASE"}})
        self.assertFalse(frames[-1]["ok"])
        self.assertFalse(session.output)

    def test_response_correlation_and_timeout(self):
        session, frames = self.ready_session()
        session.command({"id": "ui-7", "method": "send", "params": {"conversation": "dm:key", "text": "hello"}})
        request = json.loads(session.output)
        session.receive({"version": 3, "id": request["id"], "status": "error", "error": {"message": "refused"}})
        self.assertEqual(frames[-1]["id"], "ui-7")
        self.assertFalse(frames[-1]["ok"])
        session.pending["timeout"] = ("snapshot", time.monotonic() - 1)
        with self.assertRaises(TimeoutError): session.check_deadlines()
        session, frames = self.ready_session()
        session.pending["hosted-late"] = ("hosted-list", time.monotonic() - 1)
        count = len(frames)
        session.check_deadlines()  # a slow startup room listing is dropped, not fatal
        self.assertEqual(len(frames), count)
        self.assertEqual(session.expired, {"hosted-late": "hosted-list"})

    def test_slow_ui_request_becomes_unknown_without_ending_session(self):
        session, frames = self.ready_session()
        session.command({"id": "ui-7", "method": "send", "params": {"conversation": "dm:key", "text": "hello"}})
        request = json.loads(session.output)
        target, deadline = session.pending[request["id"]]
        self.assertEqual(target, "ui-7")
        self.assertGreater(deadline, time.monotonic() + 20)
        session.pending[request["id"]] = (target, time.monotonic() - 1)
        session.check_deadlines()
        self.assertEqual(frames[-1], {"kind": "response", "id": "ui-7", "ok": False, "unknown": True, "error": frames[-1]["error"]})
        self.assertNotIn(request["id"], session.pending)
        # The late daemon reply is discarded; a following event still flows.
        session.receive({"version": 3, "id": request["id"], "status": "ok", "result": {"id": "e", "delivery": "stored"}})
        session.receive({"version": 3, "sequence": 1, "topic": "delivery", "payload": {"id": "e", "delivery": "stored"}})
        self.assertEqual(frames[-1]["kind"], "event")
        self.assertEqual(session.expired, {})
        with self.assertRaises(ValueError): session.receive({"version": 3, "id": request["id"], "status": "ok"})
        session.output.clear()
        session.command({"id": "ui-8", "method": "get-draft", "params": {"conversation": "dm:key"}})
        _, deadline = session.pending[json.loads(session.output)["id"]]
        self.assertLess(deadline, time.monotonic() + 6)

    def test_daemon_that_never_answers_ends_session(self):
        session, frames = self.ready_session()
        for i in range(bridge.MAX_EXPIRED):
            session.expired[str(1000 + i)] = f"ui-{i}"
        session.command({"id": "ui-x", "method": "status"})
        request = json.loads(session.output)
        session.pending[request["id"]] = ("ui-x", time.monotonic() - 1)
        with self.assertRaises(TimeoutError): session.check_deadlines()

    def test_backpressure_and_event_bounds(self):
        session, _ = self.ready_session()
        with self.assertRaises(ValueError):
            for i in range(40): session.command({"id": f"ui-{i}", "method": "status"})
        session = bridge.Session(lambda value: None)
        with self.assertRaises(ValueError):
            for i in range(65): session.receive({"version": 3, "sequence": i, "topic": "messages", "payload": {}})

    def test_private_socket_permissions(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as server:
            path = str(Path(directory) / "ipc.sock")
            server.bind(path)
            os.chmod(path, 0o666)
            with self.assertRaises(ValueError): bridge.private_peer(path)

    def test_real_process_lifecycle_and_events(self):
        # Exercises actual stdin/stdout and Unix socket framing; this is a fake
        # daemon contract test, not a Matrix/Nostr or live Omarchy claim.
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as server:
            path = str(Path(directory) / "ipc.sock")
            server.bind(path); os.chmod(path, 0o600); server.listen(); server.settimeout(3)
            process = subprocess.Popen([sys.executable, str(SOURCE), "--socket", path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(3)
                    reader = conn.makefile("rb")
                    def reply(result):
                        request = json.loads(reader.readline())
                        conn.sendall(bridge.encode({"version": 3, "id": request["id"], "status": "ok", "result": result}))
                        return request
                    self.assertEqual(reply({})["method"], "hello")
                    self.assertEqual(reply({"status": {}, "messages": []})["method"], "subscribe")
                    process.stdin.write(bridge.encode({"id": "ui-9", "method": "send", "params": {"conversation": "dm:" + "a" * 64, "text": "hello"}})); process.stdin.flush()
                    self.assertEqual(reply({"id": "event-1", "delivery": "queued"})["method"], "send")
                    conn.sendall(bridge.encode({"version": 3, "topic": "messages", "sequence": 1, "payload": {"id": "event-2", "text": "reply"}}))
                    reader.close()
                process.wait(timeout=3)
                frames = [json.loads(line) for line in process.stdout.read().splitlines()]
                self.assertTrue(any(f.get("id") == "ui-9" and f.get("ok") for f in frames))
                self.assertTrue(any(f["kind"] == "event" for f in frames))
                self.assertEqual(frames[-1]["kind"], "disconnected")
                self.assertEqual(process.returncode, 1)
            finally:
                if process.poll() is None: process.kill(); process.wait()
                for stream in [process.stdin, process.stdout, process.stderr]: stream.close()


if __name__ == "__main__": unittest.main()
