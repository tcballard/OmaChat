#!/usr/bin/env python3
"""Two real release daemons exchange NIP-17 DMs through a local Grain relay."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

BIN = Path(__file__).resolve().parents[1] / "target/release"


def main():
    processes = []
    with tempfile.TemporaryDirectory(prefix="omachat-dm-") as temporary:
        root = Path(temporary)
        log = open(root / "daemons.log", "wb")
        try:
            sockets = []
            keys = []
            for name in ["alice", "bob"]:
                config = root / f"{name}.json"
                config.write_text(json.dumps({"storage_provider": "file", "dm_relays": ["ws://127.0.0.1:18181"]}))
                path = root / name / "ipc.sock"
                sockets.append(path)
                processes.append(subprocess.Popen([str(BIN / "omachatd"), "--config", str(config), "--state", str(root / f"{name}-state"), "--socket", str(path)], stdout=log, stderr=log))
                for _ in range(100):
                    if path.exists(): break
                    time.sleep(0.05)
                keys.append(json.loads(subprocess.check_output([str(BIN / "omachat-ctl"), "--socket", str(path), "status"], timeout=10))["nostr_public_key"])
            receivers = []
            for path in sockets:
                stream = socket.socket(socket.AF_UNIX)
                stream.settimeout(15)
                stream.connect(str(path))
                reader = stream.makefile("rb")
                for request in [dict(method="hello", params=dict(minimum_version=2, maximum_version=2)), dict(method="subscribe", params=dict(topics=["messages"]))]:
                    stream.sendall((json.dumps(dict(version=2, id="test", **request))+"\n").encode())
                    response = json.loads(reader.readline())
                    assert response["status"] == "ok", response
                receivers.append((stream, reader))
            for sender, receiver in [(0, 1), (1, 0)]:
                text = f"local encrypted roundtrip {sender} to {receiver}"
                sent = json.loads(subprocess.check_output([str(BIN / "omachat-ctl"), "--socket", str(sockets[sender]), "send", f"dm:{keys[receiver]}", text], timeout=15))
                assert sent["delivery"] in ["stored", "queued"], sent
                while True:
                    event = json.loads(receivers[receiver][1].readline())
                    if event.get("payload", {}).get("text") == text:
                        assert event["payload"]["delivery"] == "received"
                        break
            for stream, reader in receivers:
                reader.close()
                stream.close()
            print("PASS: two real daemons exchanged authenticated NIP-17 DMs through localhost Grain")
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)
            log.close()


if __name__ == "__main__":
    main()
