import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("setup", Path(__file__).resolve().parents[1] / "setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "config.json"

    def request(self, token="missing"):
        return {"revision": token, "dm_relays": ["wss://relay.test"], "room_relays": []}

    def test_first_run_reopen_and_private_permissions(self):
        self.assertFalse(setup.snapshot(self.path)["exists"])
        result = setup.apply(self.path, self.request())
        self.assertTrue(result["restart_required"])
        self.assertEqual(setup.snapshot(self.path)["dm_relays"], ["wss://relay.test/"])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_preserve_unrelated_fields_and_original_backup(self):
        original = b'{"nickname":"Tom","future":{"do_not_lose":true},"rooms":{"relays":[],"anchor_provider":"secret-service"}}'
        self.path.write_bytes(original)
        result = setup.apply(self.path, self.request(setup.snapshot(self.path)["revision"]))
        value = json.loads(self.path.read_text())
        self.assertEqual(value["future"], {"do_not_lose": True})
        self.assertEqual(value["rooms"]["anchor_provider"], "secret-service")
        backup = Path(result["backup"])
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        # No nickname or unrelated values in the helper response.
        self.assertNotIn("nickname", result)

    def test_stale_editor_cannot_overwrite_newer_file(self):
        token = setup.snapshot(self.path)["revision"]
        setup.apply(self.path, self.request(token))
        saved = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "changed"):
            setup.apply(self.path, self.request(token))
        self.assertEqual(self.path.read_bytes(), saved)

    def test_replace_failure_preserves_original_and_cleans_temporary(self):
        self.path.write_text('{"nickname":"keep"}')
        original = self.path.read_bytes()
        request = self.request(setup.snapshot(self.path)["revision"])
        with patch.object(setup.os, "replace", side_effect=OSError("disk error")):
            with self.assertRaises(OSError): setup.apply(self.path, request)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(list(self.path.parent.glob(".omachat-config-*")))

    def test_reject_malformed_duplicate_nonstandard_and_symlink(self):
        for raw in [b"broken", b"[]", b'{"x":1,"x":2}', b'{"x":NaN}']:
            self.path.write_bytes(raw)
            with self.assertRaises(ValueError): setup.apply(self.path, self.request())
            self.assertEqual(self.path.read_bytes(), raw)
        target = self.path.with_name("target.json")
        target.write_text("{}")
        self.path.unlink(); self.path.symlink_to(target)
        with self.assertRaises(ValueError): setup.snapshot(self.path)
        self.assertEqual(target.read_text(), "{}")

    def test_relay_policy_and_duplicates(self):
        for value in ["https://relay.test", "ws://relay.test", "wss://user:pass@relay.test", "wss://relay.test?q=x", "wss://relay.test#x", "wss://relay.test:99999", "wss://relay.test:0", "wss://relay.test/path with space"]:
            with self.assertRaises(ValueError, msg=value): setup.relays([value])
        with self.assertRaises(ValueError): setup.relays(["wss://RELAY.test:443", "wss://relay.test/"])
        self.assertEqual(setup.relays(["ws://127.0.0.1:8080", "ws://[::1]:8081"]), ["ws://127.0.0.1:8080/", "ws://[::1]:8081/"])
        with self.assertRaises(ValueError): setup.relays(["wss://relay.test"] * 17)

    def test_relative_xdg_is_ignored(self):
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "relative"}):
            self.assertEqual(setup.default_path(), Path.home() / ".config/omachat/config.json")


if __name__ == "__main__": unittest.main()
