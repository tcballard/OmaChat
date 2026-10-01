#!/usr/bin/env python3
"""Real hosted server, two daemons and production desktop IPC adapters.

Uses temporary generated identities and loopback only. --serve retains the
fixture until interrupted for a headless desktop run; no real accounts touched.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("desktop_smoke", ROOT / "scripts/test-desktop-bridge.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target/debug")
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    bins = args.bin_dir.resolve()
    processes, bridges, logs = [], [], []
    with tempfile.TemporaryDirectory(prefix="oh-") as directory:
        root = Path(directory)
        def launch(command, env=None, name="process"):
            log = (root / (name + ".log")).open("w+"); logs.append(log)
            process = subprocess.Popen([str(v) for v in command], env=env, stdout=log, stderr=log)
            processes.append(process)
            return process
        try:
            for name in ("server-key", "storage-key"):
                subprocess.run([bins / "omachat-serverd", "--generate-secret", root / name], check=True, capture_output=True)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
            server = launch([bins / "omachat-serverd", "--data-dir", root / "server", "--server-key-file", root / "server-key", "--storage-key-file", root / "storage-key", "--registration", "open", "--listen", f"127.0.0.1:{port}"], name="server")
            pin = None
            for _ in range(100):
                match = re.search(r"server public key ([0-9a-f]{64})", (root / "server.log").read_text())
                if match: pin = match[1]; break
                assert server.poll() is None, (root / "server.log").read_text()
                time.sleep(.05)
            assert pin, "server did not start"
            for name in ("alice", "bob"):
                runtime = root / name; runtime.mkdir(mode=0o700)
                config = root / (name + ".json")
                config.write_text(json.dumps({"storage_provider":"file", "hosted":{"url":f"ws://127.0.0.1:{port}", "pinned_server_public_key":pin, "display_name":name}}))
                env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime))
                path = runtime / "omachat.sock"
                daemon = launch([bins / "omachatd", "--config", config, "--state", root / (name + "-state"), "--socket", path], env, name)
                for _ in range(200):
                    assert daemon.poll() is None, (root / (name + ".log")).read_text()
                    result = subprocess.run([bins / "omachat-ctl", "--socket", path, "status", "--json"], capture_output=True, text=True)
                    if result.returncode == 0 and json.loads(result.stdout).get("hosted", {}).get("state") == "connected": break
                    time.sleep(.05)
                else: raise AssertionError("hosted daemon did not connect")
                bridge = smoke.Bridge(path, env); bridges.append(bridge)
                assert bridge.call("hosted-claim-handle", {"handle":name})["ok"]
            alice, bob = bridges
            def call(bridge, method, params=None):
                value = bridge.call(method, params)
                assert value["ok"], value
                return value["data"]
            workspace = call(alice, "hosted-create-workspace", {"name":"Desktop team"})["workspace_id"]
            listing = call(alice, "hosted-conversations")
            assert any(w["workspace_id"] == workspace and w["role"] == "owner" for w in listing["workspaces"]), listing
            assert not call(bob, "hosted-conversations")["workspaces"]
            call(alice, "hosted-add-member", {"workspace_id":workspace, "handle":"bob"})
            assert any(w["role"] == "member" for w in call(bob, "hosted-conversations")["workspaces"])
            denied = bob.call("hosted-create-channel", {"workspace_id":workspace,"name":"forbidden"})
            assert not denied["ok"], "non-owner created a channel"
            channel = call(alice, "hosted-create-channel", {"workspace_id":workspace,"name":"general"})["conversation"]
            conversation = call(alice, "hosted-open-dm", {"handle":"bob"})["conversation"]
            draft = call(alice, "get-draft", {"conversation":conversation})
            saved = call(alice, "save-draft", {"conversation":conversation,"text":"hosted draft", "expected_revision":draft["revision"]})
            assert saved["saved"]
            sent = call(alice, "send", {"conversation":conversation,"text":"Hello from the hosted desktop"})
            assert sent["sequence"] > 0, sent
            history = call(bob, "hosted-history", {"conversation":conversation,"limit":50})
            assert any(m["text"] == "Hello from the hosted desktop" and not m["outgoing"] for m in history["messages"]), history
            receipt = call(bob,"hosted-mark-read",{"conversation":conversation,"sequence":sent["sequence"]})
            assert receipt["read_sequence"] == sent["sequence"]
            summaries = call(alice, "hosted-conversations")["conversations"]
            summary = next(c for c in summaries if c["conversation"] == conversation)
            assert any(r["read_sequence"] == sent["sequence"] for r in summary["receipts"]), summary
            call(bob,"send",{"conversation":conversation,"text":"Read it — hello back"})
            call(alice,"send",{"conversation":channel,"text":"Welcome to Desktop team"})
            assert call(bob,"hosted-history",{"conversation":channel,"limit":50})["messages"]
            page = call(alice,"hosted-history",{"conversation":conversation,"before_sequence":sent["sequence"] + 1,"limit":1})
            assert len(page["messages"]) == 1 and page["messages"][0]["sequence"] == sent["sequence"]
            print("PASS: two real hosted daemons/adapters, handles, owner/member permissions, empty workspace listing, channels, DMs, history paging, receipts and sealed drafts", flush=True)
            if args.serve:
                print("FIXTURE=" + str(root), flush=True)
                while True: time.sleep(1)
        finally:
            for bridge in bridges:
                if bridge.process.poll() is None: bridge.close()
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
            for log in logs: log.close()


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: pass
