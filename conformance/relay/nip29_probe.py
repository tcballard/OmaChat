#!/usr/bin/env python3
"""Black-box NIP-29 probe against a pinned relay29 harness.

Reuses the stdlib-only Nostr primitives from ``grain_probe``. The probe drives
one group through creation, metadata edit, moderation, posting, deletion,
join, and leave, asserts the relay-visible contract after each step, and
writes every event it sent or received to a capture file so the Rust room
reducers can be replayed over the same evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import grain_probe as nostr  # noqa: E402

CREATOR_SECRET = 0x66
MEMBER_SECRET = 0x77
STRANGER_SECRET = 0x88
GROUP = "omarchy"


class Clock:
    """Strictly increasing timestamps so replaceable-event ordering is never
    ambiguous: each event gets a distinct created_at within the relay's
    accepted window."""

    def __init__(self):
        self.value = int(time.time()) - 5

    def next(self) -> int:
        self.value += 1
        return self.value


CLOCK = Clock()


def sign(secret: int, kind: int, tags, content: str = ""):
    return nostr.sign_event(secret, kind, tags, content, created_at=CLOCK.next())
# relay29 counts 39005 pin lists as a non-metadata kind; OmaChat subscribes
# to pins separately for the same reason.
STATE_KINDS = [39000, 39001, 39002, 39003]


class Session:
    """One websocket with a live room subscription and an event capture."""

    def __init__(self, url: str, capture: list):
        self.client = nostr.WebSocket(url, timeout=5)
        self.capture = capture
        # relay29 refuses a REQ that mixes 39xxx metadata kinds with other
        # kinds ("not allowed to mix metadata kinds with others"), so room
        # events and relay state are two subscriptions, as in the daemon.
        self.live = "live"
        self.client.send_json(
            [
                "REQ",
                self.live,
                {"kinds": [9, 9000, 9001, 9002, 9005, 9007, 9021, 9022], "#h": [GROUP]},
            ]
        )
        self.wait_eose(self.live)
        self.live_state = "live-state"
        self.client.send_json(["REQ", self.live_state, {"kinds": STATE_KINDS, "#d": [GROUP]}])
        self.wait_eose(self.live_state)

    def record(self, message):
        if message[0] == "EVENT":
            nostr.verify_event(message[2])
            self.capture.append(message[2])

    def wait_eose(self, subscription: str):
        for _ in range(64):
            message = self.client.recv_json()
            self.record(message)
            if message[0] == "EOSE" and message[1] == subscription:
                return
        raise AssertionError(f"no EOSE for {subscription}")

    def publish(self, event) -> tuple[bool, str]:
        self.client.send_json(["EVENT", event])
        for _ in range(64):
            message = self.client.recv_json()
            self.record(message)
            if message[0] == "OK" and message[1] == event["id"]:
                return bool(message[2]), (message[3] if len(message) > 3 else "")
        raise AssertionError(f"no OK for {event['id']}")

    def query(self, event_filter, subscription: str):
        self.client.send_json(["REQ", subscription, event_filter])
        events = []
        for _ in range(64):
            message = self.client.recv_json()
            self.record(message)
            if message[0] == "EVENT" and message[1] == subscription:
                events.append(message[2])
            elif message[0] == "EOSE" and message[1] == subscription:
                self.client.send_json(["CLOSE", subscription])
                return events
        raise AssertionError(f"query {subscription} did not reach EOSE")

    def state(self, kind: int):
        events = self.query({"kinds": [kind], "#d": [GROUP]}, f"state-{kind}")
        if not events:
            return None
        events.sort(key=lambda event: (event["created_at"], event["id"]))
        return events[-1]

    def drain(self, seconds: float = 0.4):
        deadline = time.monotonic() + seconds
        self.client.sock.settimeout(0.2)
        try:
            while time.monotonic() < deadline:
                try:
                    self.record(self.client.recv_json())
                except (TimeoutError, OSError):
                    continue
        finally:
            self.client.sock.settimeout(5)

    def close(self):
        self.client.close()


def tag_values(event, name: str):
    return [tag[1] for tag in event["tags"] if len(tag) > 1 and tag[0] == name]


def fetch_information(url: str):
    http_url = "http://" + url.split("://", 1)[1]
    request = urllib.request.Request(http_url, headers={"Accept": "application/nostr+json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def expect(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def run(url: str, capture_path: Path) -> None:
    information = fetch_information(url)
    expect(29 in information.get("supported_nips", []), "relay does not advertise NIP-29")
    relay_pubkey = information.get("pubkey")
    expect(isinstance(relay_pubkey, str) and len(relay_pubkey) == 64, "NIP-11 pubkey missing")
    identity_source = "self" if information.get("self") else "pubkey"

    capture: list = []
    creator = nostr.public_key(CREATOR_SECRET)
    member = nostr.public_key(MEMBER_SECRET)
    stranger = nostr.public_key(STRANGER_SECRET)
    session = Session(url, capture)
    member_session = Session(url, capture)
    stranger_session = Session(url, capture)
    checks = []

    def check(name: str, condition: bool, detail=None):
        checks.append({"check": name, "ok": bool(condition), "detail": detail})
        print(json.dumps(checks[-1]))
        expect(condition, name)

    # 1. Creation: relay publishes 39000/39001/39002/39003 signed by its key.
    create = sign(CREATOR_SECRET, 9007, [["h", GROUP]], "")
    accepted, reason = session.publish(create)
    check("create-group accepted", accepted, reason)
    time.sleep(0.3)
    metadata = session.state(39000)
    check("39000 published by relay key", metadata is not None and metadata["pubkey"] == relay_pubkey)
    admins = session.state(39001)
    check(
        "39001 lists creator as admin",
        admins is not None
        and admins["pubkey"] == relay_pubkey
        and any(tag[:2] == ["p", creator] and "admin" in tag[2:] for tag in admins["tags"]),
    )
    roles = session.state(39003)
    check("39003 declares roles", roles is not None and "admin" in tag_values(roles, "role"))

    # 2. Metadata edit by the admin is reflected in a newer 39000.
    edit = nostr.sign_event(
        CREATOR_SECRET, 9002, [["h", GROUP], ["name", "Omarchy"], ["about", "Linux talk"]], ""
    )
    accepted, reason = session.publish(edit)
    check("metadata edit accepted", accepted, reason)
    time.sleep(0.3)
    metadata = session.state(39000)
    check(
        "39000 reflects edit",
        metadata is not None
        and tag_values(metadata, "name") == ["Omarchy"]
        and tag_values(metadata, "about") == ["Linux talk"]
        and metadata["created_at"] >= create["created_at"],
    )

    # 3. Moderation: put-user adds a member; the roster snapshot follows.
    put = sign(CREATOR_SECRET, 9000, [["h", GROUP], ["p", member]], "")
    accepted, reason = session.publish(put)
    check("put-user accepted", accepted, reason)
    time.sleep(0.3)
    members = session.state(39002)
    check("39002 lists member", members is not None and member in tag_values(members, "p"))

    # 4. Posting: members post, non-members are blocked by relay policy.
    first = sign(MEMBER_SECRET, 9, [["h", GROUP]], "first")
    second = sign(MEMBER_SECRET, 9, [["h", GROUP]], "second")
    for event in (first, second):
        accepted, reason = member_session.publish(event)
        check(f"member message {event['content']} accepted", accepted, reason)
    intrusion = sign(STRANGER_SECRET, 9, [["h", GROUP]], "intrude")
    accepted, reason = stranger_session.publish(intrusion)
    check("non-member message rejected", not accepted, reason)

    # 5. Join request on an open group: the relay admits and republishes 39002.
    join = sign(STRANGER_SECRET, 9021, [["h", GROUP]], "")
    accepted, reason = stranger_session.publish(join)
    check("join request accepted", accepted, reason)
    time.sleep(0.3)
    members = session.state(39002)
    check("39002 lists joined user", members is not None and stranger in tag_values(members, "p"))
    after_join = sign(STRANGER_SECRET, 9, [["h", GROUP]], "now a member")
    accepted, reason = stranger_session.publish(after_join)
    check("joined user can post", accepted, reason)

    # 6. Deletion by the admin removes the target from queries.
    delete = sign(CREATOR_SECRET, 9005, [["h", GROUP], ["e", first["id"]]], "")
    accepted, reason = session.publish(delete)
    check("delete-event accepted", accepted, reason)
    time.sleep(0.5)
    messages = session.query({"kinds": [9], "#h": [GROUP]}, "messages")
    ids = {event["id"] for event in messages}
    check("deleted message no longer served", first["id"] not in ids and second["id"] in ids, sorted(ids))

    # 7. Remove-user and leave shrink the roster.
    remove = sign(CREATOR_SECRET, 9001, [["h", GROUP], ["p", stranger]], "")
    accepted, reason = session.publish(remove)
    check("remove-user accepted", accepted, reason)
    leave = sign(MEMBER_SECRET, 9022, [["h", GROUP]], "")
    accepted, reason = member_session.publish(leave)
    check("leave request accepted", accepted, reason)
    time.sleep(0.3)
    members = session.state(39002)
    listed = tag_values(members, "p") if members else []
    check("39002 excludes removed and departed users", stranger not in listed and member not in listed, listed)

    # 8. Forgery: a 39000 signed by a non-relay key is not relay state. The
    #    relay must not accept it as a room event either.
    forged = sign(STRANGER_SECRET, 39000, [["d", GROUP], ["name", "Forged"]], "")
    accepted, reason = stranger_session.publish(forged)
    check("forged 39000 rejected by relay", not accepted, reason)

    for live in (session, member_session, stranger_session):
        live.drain()
    final_metadata = session.state(39000)
    final_admins = session.state(39001)
    final_members = session.state(39002)
    for live in (session, member_session, stranger_session):
        live.close()

    # Preserve the relay's delivery order. relay29 content-addresses its
    # replaceable state, so a roster that returns to an earlier value is
    # re-delivered with that value's original id; moving a re-sighted id to
    # the end keeps the relay's own last-write-wins sequence, which the
    # reducers follow for same-second state.
    seen: dict = {}
    for event in capture:
        seen.pop(event["id"], None)
        seen[event["id"]] = event
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    capture_path.write_text(
        json.dumps(
            {
                "relay_url": url,
                "relay_pubkey": relay_pubkey,
                "identity_source": identity_source,
                "software": information.get("software"),
                "group_id": GROUP,
                "creator": creator,
                "member": member,
                "stranger": stranger,
                "deleted_ids": [first["id"]],
                "surviving_ids": [second["id"], after_join["id"]],
                "expected": {
                    "name": "Omarchy",
                    "about": "Linux talk",
                    "admins": tag_values(final_admins, "p") if final_admins else [],
                    "members": tag_values(final_members, "p") if final_members else [],
                    "metadata_event_id": final_metadata["id"] if final_metadata else None,
                },
                "checks": checks,
                "events": list(seen.values()),
            },
            indent=1,
        )
    )
    print(json.dumps({"phase": "capture", "events": len(seen), "path": str(capture_path), "ok": True}))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("wait", "run"))
    parser.add_argument("--url", required=True)
    parser.add_argument("--capture", type=Path)
    args = parser.parse_args()
    if args.phase == "wait":
        nostr.wait_for_relay(args.url)
    else:
        if args.capture is None:
            parser.error("run requires --capture")
        run(args.url, args.capture)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # concise CI boundary
        print(f"nip29 relay probe failed: {error}", file=sys.stderr)
        raise
