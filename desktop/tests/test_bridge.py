import importlib.util
import json
import time
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "bridge.py"
spec = importlib.util.spec_from_file_location("bridge", SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class ProtocolTests(unittest.TestCase):
    def ready(self):
        frames = []
        session = bridge.Session(frames.append)
        session.output.clear()
        session.receive({"version": 4, "id": "1", "status": "ok", "result": {}})
        session.output.clear()
        session.receive({
            "version": 4,
            "id": "2",
            "status": "ok",
            "result": {"status": {}, "messages": [], "contacts": [], "relays": []},
        })
        session.output.clear()
        return session, frames

    def test_fragmented_frames(self):
        lines = bridge.Lines()
        data = bridge.encode({"text": "hello"})
        self.assertEqual(lines.feed(data[:4]), [])
        self.assertEqual(lines.feed(data[4:]), [{"text": "hello"}])

    def test_rejects_secrets_and_old_workspace_commands(self):
        session, frames = self.ready()
        session.command({"id": "ui-1", "method": "identity-export"})
        session.command({"id": "ui-2", "method": "panic", "params": {"confirmation": "ERASE"}})
        session.command({"id": "ui-3", "method": "hosted-create-channel", "params": {"name": "general"}})
        responses = [frame for frame in frames if frame["kind"] == "response"]
        self.assertEqual(len(responses), 3)
        self.assertTrue(all(frame["ok"] is False for frame in responses))
        self.assertFalse(session.output)

    def test_snapshot_precedes_buffered_events_and_prepares_identity(self):
        frames = []
        session = bridge.Session(frames.append)
        session.receive({"version": 4, "id": "1", "status": "ok", "result": {}})
        event = {"version": 4, "sequence": 1, "topic": "messages", "payload": {"text": "live"}}
        session.receive(event)
        self.assertEqual(frames, [])
        session.receive({"version": 4, "id": "2", "status": "ok", "result": {"messages": []}})
        self.assertEqual([frame["kind"] for frame in frames], ["snapshot", "event"])
        request = json.loads(bytes(session.output).splitlines()[-1])
        self.assertEqual(request["method"], "chat-prepare")

    def test_send_is_correlated(self):
        session, frames = self.ready()
        session.command({"id": "ui-7", "method": "send", "params": {"peer": "npub1example", "text": "hello"}})
        request = json.loads(bytes(session.output).splitlines()[-1])
        self.assertEqual(request["method"], "send")
        self.assertEqual(request["version"], 4)
        session.receive({"version": 4, "id": request["id"], "status": "ok", "result": {"message": {"text": "hello"}}})
        self.assertEqual(frames[-1]["id"], "ui-7")
        self.assertTrue(frames[-1]["ok"])

    def test_timeout_does_not_drop_the_session_marker(self):
        session, frames = self.ready()
        session.pending["late"] = ("ui-9", time.monotonic() - 1)
        session.check_deadlines()
        self.assertFalse(frames[-1]["ok"])
        self.assertTrue(frames[-1]["unknown"])
        self.assertTrue(session.ready)


if __name__ == "__main__":
    unittest.main()
