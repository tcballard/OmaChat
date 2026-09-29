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


class ProtocolTests(unittest.TestCase):
    def ready_session(self):
        frames = []
        session = bridge.Session(frames.append)
        session.output.clear()
        session.receive({"version": 2, "id": "1", "status": "ok", "result": {}})
        session.output.clear()
        session.receive({"version": 2, "id": "2", "status": "ok", "result": {"status": {}, "messages": []}})
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
        session.receive({"version": 2, "id": "1", "status": "ok", "result": {}})
        event = {"version": 2, "sequence": 1, "topic": "messages", "payload": {"text": "live"}}
        session.receive(event)
        self.assertEqual(frames, [])
        session.receive({"version": 2, "id": "2", "status": "ok", "result": {"messages": []}})
        self.assertEqual([v["kind"] for v in frames], ["snapshot", "event"])

    def test_rejects_old_version_and_wrong_correlation(self):
        for frame in [{"version": 1}, {"version": 2, "id": "alien", "status": "ok"}]:
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
        session.receive({"version": 2, "id": request["id"], "status": "error", "error": {"message": "refused"}})
        self.assertEqual(frames[-1]["id"], "ui-7")
        self.assertFalse(frames[-1]["ok"])
        session.pending["timeout"] = ("ui-8", time.monotonic() - 1)
        with self.assertRaises(TimeoutError): session.check_deadlines()

    def test_backpressure_and_event_bounds(self):
        session, _ = self.ready_session()
        with self.assertRaises(ValueError):
            for i in range(40): session.command({"id": f"ui-{i}", "method": "status"})
        session = bridge.Session(lambda value: None)
        with self.assertRaises(ValueError):
            for i in range(65): session.receive({"version": 2, "sequence": i, "topic": "messages", "payload": {}})

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
                        conn.sendall(bridge.encode({"version": 2, "id": request["id"], "status": "ok", "result": result}))
                        return request
                    self.assertEqual(reply({})["method"], "hello")
                    self.assertEqual(reply({"status": {}, "messages": []})["method"], "subscribe")
                    self.assertEqual(reply({"relays": []})["method"], "list-rooms")
                    process.stdin.write(bridge.encode({"id": "ui-9", "method": "send", "params": {"conversation": "dm:" + "a" * 64, "text": "hello"}})); process.stdin.flush()
                    self.assertEqual(reply({"id": "event-1", "delivery": "queued"})["method"], "send")
                    conn.sendall(bridge.encode({"version": 2, "topic": "messages", "sequence": 1, "payload": {"id": "event-2", "text": "reply"}}))
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
