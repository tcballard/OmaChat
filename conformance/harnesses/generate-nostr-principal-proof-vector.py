#!/usr/bin/env python3
"""Generate OmaChat Nostr principal-control proof v1 transcripts.

This is an independent synthetic oracle. It deliberately does not import,
execute, or parse output from OmaChat's Rust implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
DOMAIN = b"omachat.nostr-principal-control.v1\0"
VERSION = 1
PRINCIPAL_TYPES = {"device": 1, "agent": 2, "account": 3}


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def tagged_hash(tag: str, value: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + value)


def point_add(left: tuple[int, int] | None, right: tuple[int, int] | None):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def point_mul(scalar: int, point: tuple[int, int] = G):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def bytes32(value: int) -> bytes:
    return value.to_bytes(32, "big")


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def push_u32(value: bytes) -> bytes:
    return u32(len(value)) + value


def public_key(secret: bytes) -> bytes:
    point = point_mul(int.from_bytes(secret, "big"))
    assert point is not None
    return bytes32(point[0])


def sign_bip340_zero_aux(secret: bytes, message: bytes) -> bytes:
    secret_scalar = int.from_bytes(secret, "big")
    assert 0 < secret_scalar < N
    public_point = point_mul(secret_scalar)
    assert public_point is not None
    adjusted_secret = N - secret_scalar if public_point[1] & 1 else secret_scalar
    public_x = bytes32(public_point[0])
    aux_hash = tagged_hash("BIP0340/aux", bytes(32))
    masked = bytes(a ^ b for a, b in zip(bytes32(adjusted_secret), aux_hash))
    nonce = int.from_bytes(
        tagged_hash("BIP0340/nonce", masked + public_x + message), "big"
    ) % N
    assert nonce != 0
    nonce_point = point_mul(nonce)
    assert nonce_point is not None
    adjusted_nonce = N - nonce if nonce_point[1] & 1 else nonce
    nonce_x = bytes32(nonce_point[0])
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", nonce_x + public_x + message), "big"
    ) % N
    signature = nonce_x + bytes32((adjusted_nonce + challenge * adjusted_secret) % N)
    assert verify_bip340(public_x, message, signature)
    return signature


def lift_x(encoded: bytes):
    x = int.from_bytes(encoded, "big")
    if x >= P:
        return None
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if pow(y, 2, P) != y_squared:
        return None
    return x, P - y if y & 1 else y


def verify_bip340(public_x: bytes, message: bytes, signature: bytes) -> bool:
    public_point = lift_x(public_x)
    if public_point is None or len(message) != 32 or len(signature) != 64:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= P or s >= N:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + public_x + message), "big"
    ) % N
    candidate = point_add(point_mul(s), point_mul(N - challenge, public_point))
    return candidate is not None and candidate[1] % 2 == 0 and candidate[0] == r


def fixed_inputs():
    return {
        "schema_version": 1,
        "nostr_secret_hex": (b"\x15" * 32).hex(),
        "claim_hash_hex": (b"\x31" * 32).hex(),
        "command_id_hex": (b"\x41" * 32).hex(),
        "expected_registry_revision": 7,
        "account_id": "oa1_a645d3afb4000fa6b55597b1290226fda6de04a2d2563259c5420931431ebc10",
        "handle": "codextom",
        "principal_type": "device",
        "authorisation_hash_hex": (b"\x51" * 32).hex(),
        "created_at": 1788000201,
    }


def generate():
    inputs = fixed_inputs()
    secret = bytes.fromhex(inputs["nostr_secret_hex"])
    nostr_public_key = public_key(secret)
    transcript = b"".join(
        (
            DOMAIN,
            u16(VERSION),
            bytes.fromhex(inputs["claim_hash_hex"]),
            bytes.fromhex(inputs["command_id_hex"]),
            u64(inputs["expected_registry_revision"]),
            push_u32(inputs["account_id"].encode("ascii")),
            push_u32(inputs["handle"].encode("ascii")),
            bytes((PRINCIPAL_TYPES[inputs["principal_type"]],)),
            nostr_public_key,
            bytes.fromhex(inputs["authorisation_hash_hex"]),
            u64(inputs["created_at"]),
        )
    )
    digest = sha256(transcript)
    signature = sign_bip340_zero_aux(secret, digest)
    intermediates = {
        "schema_version": 1,
        "signing_bytes_hex": transcript.hex(),
        "proof_digest_hex": digest.hex(),
        "aux_rand_hex": bytes(32).hex(),
    }
    outputs = {
        "schema_version": 1,
        "proof_version": VERSION,
        "nostr_public_key_hex": nostr_public_key.hex(),
        "signature_hex": signature.hex(),
    }
    return inputs, intermediates, outputs


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    for name, value in zip(
        ("inputs.json", "intermediates.json", "outputs.json"), generate()
    ):
        write_json(arguments.output_dir / name, value)


if __name__ == "__main__":
    main()
