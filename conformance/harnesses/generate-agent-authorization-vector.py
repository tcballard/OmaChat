#!/usr/bin/env python3
"""Generate independent agent authorization and revocation vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
VERSION = 1
ACCOUNT_ID_DOMAIN = b"omachat.account.v1\0"
AUTHORIZATION_ID_DOMAIN = b"omachat.agent-authorization-id.v1\0"
REQUEST_DOMAIN = b"omachat.agent-authorization-request.v1\0"
AUTHORIZATION_DOMAIN = b"omachat.agent-authorization.v1\0"
AUTHORIZATION_HASH_DOMAIN = b"omachat.agent-authorization-hash.v1\0"
REVOCATION_DOMAIN = b"omachat.agent-revocation.v1\0"


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def tagged_hash(tag: str, value: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + value)


def inverse(value: int) -> int:
    return pow(value, P - 2, P)


def point_add(left: tuple[int, int] | None, right: tuple[int, int] | None):
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and left[1] != right[1]:
        return None
    if left == right:
        slope = (3 * left[0] * left[0]) * inverse(2 * left[1] % P) % P
    else:
        slope = (right[1] - left[1]) * inverse((right[0] - left[0]) % P) % P
    x = (slope * slope - left[0] - right[0]) % P
    y = (slope * (left[0] - x) - left[1]) % P
    return x, y


def point_mul(scalar: int, point=G):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def bip340_sign(secret: bytes, message: bytes, auxiliary_randomness: bytes) -> tuple[bytes, bytes]:
    secret_value = int.from_bytes(secret, "big")
    if not 1 <= secret_value < N:
        raise ValueError("invalid secp256k1 secret")
    public = point_mul(secret_value)
    assert public is not None
    adjusted_secret = secret_value if public[1] % 2 == 0 else N - secret_value
    public_x = public[0].to_bytes(32, "big")
    masked = bytes(
        left ^ right
        for left, right in zip(
            adjusted_secret.to_bytes(32, "big"),
            tagged_hash("BIP0340/aux", auxiliary_randomness),
            strict=True,
        )
    )
    nonce = int.from_bytes(
        tagged_hash("BIP0340/nonce", masked + public_x + message), "big"
    ) % N
    if nonce == 0:
        raise ValueError("invalid BIP-340 nonce")
    nonce_point = point_mul(nonce)
    assert nonce_point is not None
    adjusted_nonce = nonce if nonce_point[1] % 2 == 0 else N - nonce
    nonce_x = nonce_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", nonce_x + public_x + message), "big"
    ) % N
    signature = nonce_x + ((adjusted_nonce + challenge * adjusted_secret) % N).to_bytes(32, "big")
    return public_x, signature


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def push(value: bytes) -> bytes:
    return u32(len(value)) + value


def raw_public(private_key: Any) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def fixed_inputs() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "account_root_seed_hex": (b"\x11" * 32).hex(),
        "recovery_seed_hex": (b"\x12" * 32).hex(),
        "agent_secret_key_hex": (b"\x31" * 32).hex(),
        "agent_auxiliary_randomness_hex": (b"\x42" * 32).hex(),
        "label": "External Agent",
        "requested_at": 1_788_100_000,
        "authorization_revision": 1,
        "authorized_at": 1_788_100_001,
        "revocation_revision": 2,
        "revoked_at": 1_788_100_100,
    }


def generate() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    inputs = fixed_inputs()
    root_private = ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(inputs["account_root_seed_hex"])
    )
    root_public = raw_public(root_private)
    account_id = "oa1_" + sha256(ACCOUNT_ID_DOMAIN + root_public).hex()
    agent_secret = bytes.fromhex(inputs["agent_secret_key_hex"])
    auxiliary_randomness = bytes.fromhex(inputs["agent_auxiliary_randomness_hex"])
    label = inputs["label"].encode("utf-8")
    agent_public, _ = bip340_sign(agent_secret, bytes(32), auxiliary_randomness)
    request_signing_bytes = b"".join(
        (
            REQUEST_DOMAIN,
            u16(VERSION),
            push(account_id.encode("ascii")),
            agent_public,
            b"\x01",
            b"\x01" + push(label),
            u64(inputs["requested_at"]),
        )
    )
    request_digest = sha256(request_signing_bytes)
    _, agent_proof = bip340_sign(agent_secret, request_digest, auxiliary_randomness)
    authorization_id = "oag1_" + sha256(
        AUTHORIZATION_ID_DOMAIN + account_id.encode("ascii") + agent_public
    ).hex()
    authorization_signing_bytes = b"".join(
        (
            AUTHORIZATION_DOMAIN,
            u16(VERSION),
            push(authorization_id.encode("ascii")),
            push(account_id.encode("ascii")),
            root_public,
            push(request_signing_bytes),
            agent_proof,
            u64(inputs["authorization_revision"]),
            u64(inputs["authorized_at"]),
        )
    )
    authorization_signature = root_private.sign(authorization_signing_bytes)
    authorization_hash = sha256(
        AUTHORIZATION_HASH_DOMAIN
        + push(authorization_signing_bytes)
        + authorization_signature
    )
    revocation_signing_bytes = b"".join(
        (
            REVOCATION_DOMAIN,
            u16(VERSION),
            push(authorization_id.encode("ascii")),
            push(account_id.encode("ascii")),
            root_public,
            agent_public,
            authorization_hash,
            u64(inputs["authorization_revision"]),
            u64(inputs["revocation_revision"]),
            u64(inputs["revoked_at"]),
        )
    )
    revocation_signature = root_private.sign(revocation_signing_bytes)
    intermediates = {
        "schema_version": 1,
        "request_signing_bytes_hex": request_signing_bytes.hex(),
        "request_proof_digest_hex": request_digest.hex(),
        "authorization_signing_bytes_hex": authorization_signing_bytes.hex(),
        "revocation_signing_bytes_hex": revocation_signing_bytes.hex(),
    }
    outputs = {
        "schema_version": 1,
        "account_id": account_id,
        "account_root_public_key_hex": root_public.hex(),
        "agent_public_key_hex": agent_public.hex(),
        "authorization_id": authorization_id,
        "agent_proof_hex": agent_proof.hex(),
        "authorization_signature_hex": authorization_signature.hex(),
        "authorization_hash_hex": authorization_hash.hex(),
        "revocation_signature_hex": revocation_signature.hex(),
    }
    return inputs, intermediates, outputs


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    inputs, intermediates, outputs = generate()
    write_json(args.output_dir / "inputs.json", inputs)
    write_json(args.output_dir / "intermediates.json", intermediates)
    write_json(args.output_dir / "outputs.json", outputs)


if __name__ == "__main__":
    main()
