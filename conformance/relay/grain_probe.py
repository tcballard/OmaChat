#!/usr/bin/env python3
"""Independent black-box Nostr relay probe for OmaChat's Grain candidate.

The probe intentionally uses only Python's standard library. It does not test
NIP-44 encryption; the Rust conformance suite owns that boundary. It tests the
relay-visible contract around signed profile, relay-list, and kind 1059 events.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

SENDER_SECRET = 0x11
RECIPIENT_SECRET = 0x22
STRANGER_SECRET = 0x33
WRAPPER_SECRET = 0x44
PARTICIPANT_SECRET = 0x55


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % FIELD == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, FIELD - 2, FIELD)
    else:
        slope = (y2 - y1) * pow((x2 - x1) % FIELD, FIELD - 2, FIELD)
    slope %= FIELD
    x3 = (slope * slope - x1 - x2) % FIELD
    return x3, (slope * (x1 - x3) - y1) % FIELD


def scalar_mult(scalar: int, point=GENERATOR):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def public_key(secret: int) -> str:
    if not 1 <= secret < ORDER:
        raise ValueError("secret key outside secp256k1 order")
    point = scalar_mult(secret)
    return f"{point[0]:064x}"


def schnorr_sign(message: bytes, secret: int) -> bytes:
    if len(message) != 32:
        raise ValueError("BIP-340 messages must be 32 bytes")
    point = scalar_mult(secret)
    adjusted = secret if point[1] % 2 == 0 else ORDER - secret
    x_bytes = point[0].to_bytes(32, "big")
    aux = hashlib.sha256(b"OmaChat Grain relay probe" + message).digest()
    masked = bytes(
        left ^ right
        for left, right in zip(
            adjusted.to_bytes(32, "big"), tagged_hash("BIP0340/aux", aux)
        )
    )
    nonce = int.from_bytes(
        tagged_hash("BIP0340/nonce", masked + x_bytes + message), "big"
    ) % ORDER
    if nonce == 0:
        raise RuntimeError("deterministic BIP-340 nonce was zero")
    nonce_point = scalar_mult(nonce)
    if nonce_point[1] % 2:
        nonce = ORDER - nonce
        nonce_point = scalar_mult(nonce)
    challenge = int.from_bytes(
        tagged_hash(
            "BIP0340/challenge",
            nonce_point[0].to_bytes(32, "big") + x_bytes + message,
        ),
        "big",
    ) % ORDER
    signature = nonce_point[0].to_bytes(32, "big") + (
        (nonce + challenge * adjusted) % ORDER
    ).to_bytes(32, "big")
    if not schnorr_verify(message, x_bytes, signature):
        raise RuntimeError("self-generated BIP-340 signature did not verify")
    return signature


def schnorr_verify(message: bytes, public: bytes, signature: bytes) -> bool:
    if len(message) != 32 or len(public) != 32 or len(signature) != 64:
        return False
    x = int.from_bytes(public, "big")
    if x >= FIELD:
        return False
    y_squared = (pow(x, 3, FIELD) + 7) % FIELD
    y = pow(y_squared, (FIELD + 1) // 4, FIELD)
    if pow(y, 2, FIELD) != y_squared:
        return False
    if y % 2:
        y = FIELD - y
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= FIELD or s >= ORDER:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + public + message), "big"
    ) % ORDER
    candidate = point_add(scalar_mult(s), scalar_mult(ORDER - challenge, (x, y)))
    return candidate is not None and candidate[1] % 2 == 0 and candidate[0] == r


def sign_event(secret: int, kind: int, tags, content: str, created_at=None):
    timestamp = int(time.time()) if created_at is None else int(created_at)
    pubkey = public_key(secret)
    canonical = json.dumps(
        [0, pubkey, timestamp, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    event_id = hashlib.sha256(canonical).digest()
    return {
        "id": event_id.hex(),
        "pubkey": pubkey,
        "created_at": timestamp,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": schnorr_sign(event_id, secret).hex(),
    }


def verify_event(event) -> None:
    required = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
    if not isinstance(event, dict) or set(event) != required:
        raise AssertionError(f"relay returned a noncanonical event shape: {event!r}")
    try:
        public = bytes.fromhex(event["pubkey"])
        signature = bytes.fromhex(event["sig"])
        claimed_id = bytes.fromhex(event["id"])
    except (TypeError, ValueError) as error:
        raise AssertionError("relay returned malformed event hex") from error
    canonical = json.dumps(
        [
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    calculated_id = hashlib.sha256(canonical).digest()
    if claimed_id != calculated_id:
        raise AssertionError("relay returned an event with a mismatched ID")
    if not schnorr_verify(calculated_id, public, signature):
        raise AssertionError("relay returned an event with an invalid signature")


class WebSocket:
    def __init__(self, url: str, timeout: float = 5.0):
        parsed = urlparse(url)
        if parsed.scheme != "ws" or not parsed.hostname:
            raise ValueError("probe supports loopback ws:// URLs only")
        self.url = url
        self.sock = socket.create_connection(
            (parsed.hostname, parsed.port or 80), timeout=timeout
        )
        self.sock.settimeout(timeout)
        self.buffer = bytearray()
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host = parsed.hostname
        if parsed.port:
            host += f":{parsed.port}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        self.sock.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("relay closed during WebSocket handshake")
            response.extend(chunk)
        headers, remainder = bytes(response).split(b"\r\n\r\n", 1)
        if not headers.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(f"WebSocket upgrade failed: {headers!r}")
        expected = base64.b64encode(
            hashlib.sha1(
                key.encode("ascii")
                + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            ).digest()
        )
        if b"sec-websocket-accept: " + expected.lower() not in headers.lower():
            raise RuntimeError("relay returned an invalid WebSocket accept value")
        self.buffer.extend(remainder)

    def _read_exact(self, length: int) -> bytes:
        while len(self.buffer) < length:
            chunk = self.sock.recv(max(4096, length - len(self.buffer)))
            if not chunk:
                raise RuntimeError("relay closed the WebSocket")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes([0x80 | opcode, 0x80 | length])
        elif length <= 0xFFFF:
            header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", length)
        else:
            header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack("!Q", length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_json(self, value) -> None:
        self._send_frame(
            0x1,
            json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            ),
        )

    def recv_json(self):
        fragments = bytearray()
        while True:
            first, second = self._read_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(length)
            if masked:
                payload = bytes(
                    value ^ mask[index % 4] for index, value in enumerate(payload)
                )
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0x8:
                raise RuntimeError("relay closed the WebSocket")
            if opcode not in (0x0, 0x1):
                continue
            fragments.extend(payload)
            if final:
                return json.loads(fragments.decode("utf-8"))

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        self.sock.close()


def receive_until(client: WebSocket, predicate, context: str):
    seen = []
    for _ in range(32):
        message = client.recv_json()
        seen.append(message)
        if predicate(message):
            return message
    raise AssertionError(f"did not receive {context}; saw {seen!r}")


def authenticate(url: str, secret: int) -> WebSocket:
    client = WebSocket(url)
    challenge_message = receive_until(
        client,
        lambda message: len(message) >= 2 and message[0] == "AUTH",
        "NIP-42 challenge",
    )
    auth_event = sign_event(
        secret,
        22242,
        [["relay", url], ["challenge", challenge_message[1]]],
        "",
    )
    client.send_json(["AUTH", auth_event])
    response = receive_until(
        client,
        lambda message: len(message) >= 3
        and message[0] == "OK"
        and message[1] == auth_event["id"],
        "successful NIP-42 acknowledgement",
    )
    if response[2] is not True:
        raise AssertionError(f"relay rejected valid NIP-42 auth: {response!r}")
    return client


def expect_publish(client: WebSocket, event, accepted: bool, reason_prefix: str = ""):
    client.send_json(["EVENT", event])
    response = receive_until(
        client,
        lambda message: len(message) >= 3
        and message[0] == "OK"
        and message[1] == event["id"],
        f"publish acknowledgement for {event['id']}",
    )
    if response[2] is not accepted:
        raise AssertionError(f"unexpected publish result: {response!r}")
    reason = response[3] if len(response) > 3 else ""
    if reason_prefix and not reason.startswith(reason_prefix):
        raise AssertionError(f"unexpected publish reason: {response!r}")


def query_filter(client: WebSocket, event_filter, subscription: str):
    client.send_json(["REQ", subscription, event_filter])
    events = []
    for _ in range(32):
        message = client.recv_json()
        if message[0] == "EVENT" and message[1] == subscription:
            verify_event(message[2])
            events.append(message[2])
        elif message[0] == "EOSE" and message[1] == subscription:
            return events
        elif message[0] == "CLOSED" and message[1] == subscription:
            raise AssertionError(f"relay closed authenticated query: {message!r}")
    raise AssertionError("authenticated query did not reach EOSE")


def query(client: WebSocket, recipient: str, subscription: str):
    return query_filter(
        client,
        {"kinds": [1059], "#p": [recipient], "limit": 10},
        subscription,
    )


def query_author_kind(
    client: WebSocket, author: str, kind: int, subscription: str
):
    return query_filter(
        client,
        {"kinds": [kind], "authors": [author], "limit": 10},
        subscription,
    )


def count(client: WebSocket, recipient: str, subscription: str) -> int:
    client.send_json(
        ["COUNT", subscription, {"kinds": [1059], "#p": [recipient]}]
    )
    response = receive_until(
        client,
        lambda message: len(message) >= 3
        and message[0] == "COUNT"
        and message[1] == subscription,
        "NIP-45 count",
    )
    return int(response[2]["count"])


def assert_recipient_only(url: str, event_id: str) -> None:
    recipient = public_key(RECIPIENT_SECRET)
    recipient_client = authenticate(url, RECIPIENT_SECRET)
    try:
        events = query(recipient_client, recipient, "recipient-inbox")
        ids = [event["id"] for event in events]
        if ids != [event_id]:
            raise AssertionError(f"recipient saw unexpected event IDs: {ids!r}")
        if count(recipient_client, recipient, "recipient-count") != 1:
            raise AssertionError("recipient COUNT did not report exactly one gift wrap")
    finally:
        recipient_client.close()

    stranger_client = authenticate(url, STRANGER_SECRET)
    try:
        if query(stranger_client, recipient, "stranger-inbox"):
            raise AssertionError("authenticated stranger received recipient gift wrap")
        if count(stranger_client, recipient, "stranger-count") != 0:
            raise AssertionError("authenticated stranger learned recipient message count")
    finally:
        stranger_client.close()


def assert_participant_metadata(url: str, state) -> None:
    participant = public_key(PARTICIPANT_SECRET)
    if state["participant"] != participant:
        raise AssertionError("persisted probe state participant mismatch")
    client = authenticate(url, PARTICIPANT_SECRET)
    try:
        expectations = (
            (
                0,
                "profile",
                state["profile_event_id"],
                {
                    state["replaced_profile_event_id"],
                    state["profile_event_id"],
                },
            ),
            (
                10002,
                "nip65",
                state["relay_list_event_id"],
                {state["relay_list_event_id"]},
            ),
            (
                10050,
                "nip17-inbox",
                state["dm_relay_list_event_id"],
                {state["dm_relay_list_event_id"]},
            ),
        )
        for kind, label, expected_id, allowed_ids in expectations:
            events = query_author_kind(
                client, participant, kind, f"participant-{label}"
            )
            ids = [event["id"] for event in events]
            if len(ids) != len(set(ids)):
                raise AssertionError(
                    f"participant {label} query returned duplicate IDs: {ids!r}"
                )
            unexpected_ids = set(ids) - allowed_ids
            if expected_id not in ids or unexpected_ids:
                raise AssertionError(
                    "participant "
                    f"{label} query returned unexpected IDs: {ids!r}"
                )
            newest_created_at = max(event["created_at"] for event in events)
            newest_ids = {
                event["id"]
                for event in events
                if event["created_at"] == newest_created_at
            }
            if newest_ids != {expected_id}:
                raise AssertionError(
                    "participant "
                    f"{label} query did not resolve to {expected_id}: {ids!r}"
                )
    finally:
        client.close()


def seed(url: str, state_path: Path) -> None:
    recipient = public_key(RECIPIENT_SECRET)
    participant = public_key(PARTICIPANT_SECRET)
    base_time = int(time.time()) - 30
    event = sign_event(
        WRAPPER_SECRET,
        1059,
        [["p", recipient]],
        "OmaChat Grain relay interoperability probe",
        base_time,
    )
    old_profile = sign_event(
        PARTICIPANT_SECRET,
        0,
        [],
        json.dumps(
            {"display_name": "Old Relay Probe", "name": "old-relay-probe"},
            separators=(",", ":"),
            sort_keys=True,
        ),
        base_time - 2,
    )
    profile = sign_event(
        PARTICIPANT_SECRET,
        0,
        [],
        json.dumps(
            {"display_name": "Relay Probe", "name": "relay-probe"},
            separators=(",", ":"),
            sort_keys=True,
        ),
        base_time - 1,
    )
    relay_list = sign_event(
        PARTICIPANT_SECRET,
        10002,
        [
            ["r", "wss://read.example", "read"],
            ["r", "wss://write.example", "write"],
        ],
        "",
        base_time,
    )
    dm_relay_list = sign_event(
        PARTICIPANT_SECRET,
        10050,
        [["relay", "wss://inbox.example"]],
        "",
        base_time,
    )

    unauthenticated = WebSocket(url)
    try:
        expect_publish(unauthenticated, event, False, "auth-required:")
    finally:
        unauthenticated.close()

    sender = authenticate(url, SENDER_SECRET)
    try:
        forged = dict(event)
        forged["content"] += " forged"
        expect_publish(sender, forged, False, "invalid:")
        expect_publish(sender, event, True)
    finally:
        sender.close()

    participant_client = authenticate(url, PARTICIPANT_SECRET)
    try:
        expect_publish(participant_client, old_profile, True)
        expect_publish(participant_client, profile, True)
        expect_publish(participant_client, relay_list, True)
        expect_publish(participant_client, dm_relay_list, True)
    finally:
        participant_client.close()

    unauthenticated_reader = WebSocket(url)
    try:
        unauthenticated_reader.send_json(
            ["REQ", "unauthenticated", {"kinds": [1059]}]
        )
        closed = receive_until(
            unauthenticated_reader,
            lambda message: len(message) >= 3
            and message[0] == "CLOSED"
            and message[1] == "unauthenticated",
            "auth-required CLOSED response",
        )
        if not closed[2].startswith("auth-required:"):
            raise AssertionError(f"unexpected unauthenticated read result: {closed!r}")
    finally:
        unauthenticated_reader.close()

    assert_recipient_only(url, event["id"])
    state = {
        "event_id": event["id"],
        "recipient": recipient,
        "wrapper_pubkey": event["pubkey"],
        "authenticated_sender": public_key(SENDER_SECRET),
        "participant": participant,
        "replaced_profile_event_id": old_profile["id"],
        "profile_event_id": profile["id"],
        "relay_list_event_id": relay_list["id"],
        "dm_relay_list_event_id": dm_relay_list["id"],
    }
    assert_participant_metadata(url, state)
    state_path.write_text(
        json.dumps(state, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"phase": "seed", "event_id": event["id"], "ok": True}))


def verify(url: str, state_path: Path) -> None:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state["recipient"] != public_key(RECIPIENT_SECRET):
        raise AssertionError("persisted probe state recipient mismatch")
    assert_recipient_only(url, state["event_id"])
    assert_participant_metadata(url, state)
    print(
        json.dumps(
            {"phase": "restart", "event_id": state["event_id"], "ok": True}
        )
    )


def wait_for_relay(url: str) -> None:
    deadline = time.monotonic() + 20
    last_error = None
    while time.monotonic() < deadline:
        try:
            client = WebSocket(url, timeout=1)
            client.close()
            print(json.dumps({"phase": "ready", "url": url, "ok": True}))
            return
        except (OSError, RuntimeError, ValueError) as error:
            last_error = error
            time.sleep(0.2)
    raise RuntimeError(f"relay did not become ready: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("wait", "seed", "verify"))
    parser.add_argument("--url", required=True)
    parser.add_argument("--state", type=Path)
    args = parser.parse_args()

    if args.phase == "wait":
        wait_for_relay(args.url)
    elif args.phase == "seed":
        if args.state is None:
            parser.error("seed requires --state")
        seed(args.url, args.state)
    else:
        if args.state is None:
            parser.error("verify requires --state")
        verify(args.url, args.state)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # concise CI boundary
        print(f"grain relay probe failed: {error}", file=sys.stderr)
        raise
