#!/usr/bin/env python3
"""Generate OmaChat principal proof-receipt v1 conformance transcripts.

This independent synthetic oracle uses a standalone RFC 8032 calculation. It
does not import, execute, or parse output from OmaChat's Rust implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)
RECEIPT_DOMAIN = b"omachat.registry.principal-proof-receipt.v1\0"
RECEIPT_HASH_DOMAIN = b"omachat.registry.principal-proof-receipt-hash.v1\0"
VERSION = 1


def sha512(value: bytes) -> bytes:
    return hashlib.sha512(value).digest()


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = x * I % Q
    if x & 1:
        x = Q - x
    return x


B_Y = 4 * pow(5, Q - 2, Q) % Q
B = (x_recover(B_Y), B_Y)


def point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = D * x1 * x2 * y1 * y2 % Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + product, Q - 2, Q) % Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, Q - 2, Q) % Q
    return x3, y3


def point_mul(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def decode_point(encoded: bytes) -> tuple[int, int]:
    assert len(encoded) == 32
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    assert y < Q
    x = x_recover(y)
    if (x & 1) != (encoded[31] >> 7):
        x = Q - x
    assert (-x * x + y * y - 1 - D * x * x * y * y) % Q == 0
    return x, y


def secret_scalar(seed: bytes) -> tuple[int, bytes]:
    hashed = sha512(seed)
    clamped = bytearray(hashed[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    return int.from_bytes(clamped, "little"), hashed[32:]


def public_key(seed: bytes) -> bytes:
    scalar, _ = secret_scalar(seed)
    return encode_point(point_mul(B, scalar))


def sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = secret_scalar(seed)
    public = public_key(seed)
    nonce = int.from_bytes(sha512(prefix + message), "little") % L
    encoded_nonce = encode_point(point_mul(B, nonce))
    challenge = int.from_bytes(sha512(encoded_nonce + public + message), "little") % L
    signature = encoded_nonce + ((nonce + challenge * scalar) % L).to_bytes(32, "little")
    assert verify(public, message, signature)
    return signature


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    encoded_nonce = signature[:32]
    response = int.from_bytes(signature[32:], "little")
    if response >= L:
        return False
    public_point = decode_point(public)
    nonce_point = decode_point(encoded_nonce)
    challenge = int.from_bytes(sha512(encoded_nonce + public + message), "little") % L
    return point_mul(B, response) == point_add(nonce_point, point_mul(public_point, challenge))


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def push_u32(value: bytes) -> bytes:
    return u32(len(value)) + value


def fixed_inputs():
    return {
        "schema_version": 1,
        "registry_signing_seed_hex": (b"\x77" * 32).hex(),
        "sequence": 1,
        "command_id_hex": (b"\xa1" * 32).hex(),
        "account_id": "oa1_a645d3afb4000fa6b55597b1290226fda6de04a2d2563259c5420931431ebc10",
        "handle": "alice",
        "account_revision": 1,
        "claim_receipt_hash_hex": "9656e2be45f7c1f225ca7dae6d0bd873cbb9a0e1e3f656a35ddd45723509523f",
        "principal_proof_hash_hex": (b"\x62" * 32).hex(),
        "nostr_public_key_hex": "d793631af7aa0e709439dd47fc001acd0b0727670b6670ea528ac83cb0127f4a",
        "previous_proof_receipt_hash_hex": bytes(32).hex(),
        "previous_account_proof_receipt_hash_hex": bytes(32).hex(),
        "accepted_at": 1788000101,
    }


def generate():
    inputs = fixed_inputs()
    signing_bytes = b"".join(
        (
            RECEIPT_DOMAIN,
            u16(VERSION),
            u64(inputs["sequence"]),
            bytes.fromhex(inputs["command_id_hex"]),
            push_u32(inputs["account_id"].encode("ascii")),
            push_u32(inputs["handle"].encode("ascii")),
            u64(inputs["account_revision"]),
            bytes.fromhex(inputs["claim_receipt_hash_hex"]),
            bytes.fromhex(inputs["principal_proof_hash_hex"]),
            bytes.fromhex(inputs["nostr_public_key_hex"]),
            bytes.fromhex(inputs["previous_proof_receipt_hash_hex"]),
            bytes.fromhex(inputs["previous_account_proof_receipt_hash_hex"]),
            u64(inputs["accepted_at"]),
        )
    )
    seed = bytes.fromhex(inputs["registry_signing_seed_hex"])
    signature = sign(seed, signing_bytes)
    intermediates = {
        "schema_version": 1,
        "receipt_signing_bytes_hex": signing_bytes.hex(),
        "receipt_hash_preimage_hex": (RECEIPT_HASH_DOMAIN + signing_bytes + signature).hex(),
    }
    outputs = {
        "encoded_receipt_hex": (signing_bytes + signature).hex(),
        "schema_version": 1,
        "receipt_version": VERSION,
        "registry_public_key_hex": public_key(seed).hex(),
        "signature_hex": signature.hex(),
        "receipt_hash_hex": sha256(RECEIPT_HASH_DOMAIN + signing_bytes + signature).hex(),
    }
    return inputs, intermediates, outputs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    output_dir = parser.parse_args().output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, value in zip(("inputs.json", "intermediates.json", "outputs.json"), generate()):
        (output_dir / name).write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
