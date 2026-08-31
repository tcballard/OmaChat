#!/usr/bin/env python3
"""Generate OmaChat account/registry v1 conformance transcripts.

This is an independent synthetic oracle. It deliberately does not import,
execute, or parse output from OmaChat's Rust implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519


ACCOUNT_ID_DOMAIN = b"omachat.account.v1\0"
DEVICE_ID_DOMAIN = b"omachat.device.v1\0"
LOCAL_BINDING_DOMAIN = b"omachat.local-account-binding.v1\0"
CLAIM_DOMAIN = b"omachat.registry.handle-claim.v1\0"
CLAIM_PROOF_DOMAIN = b"omachat.registry-handle-claim-proof.v1\0"
CLAIM_HASH_DOMAIN = b"omachat.registry.handle-claim-hash.v1\0"
RECEIPT_DOMAIN = b"omachat.registry.receipt.v1\0"
RECEIPT_HASH_DOMAIN = b"omachat.registry.receipt-hash.v1\0"
VERSION = 1
GENESIS_HASH = bytes(32)


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def push_u32(value: bytes) -> bytes:
    return u32(len(value)) + value


def push_u64(value: bytes) -> bytes:
    return u64(len(value)) + value


def push_optional(value: str | None) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + push_u32(value.encode("utf-8"))


def ed25519_private(seed: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def raw_public(private_key: Any) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def nostr_x_only_public(secret: bytes) -> bytes:
    private_value = int.from_bytes(secret, "big")
    public_numbers = ec.derive_private_key(
        private_value, ec.SECP256K1()
    ).public_key().public_numbers()
    return public_numbers.x.to_bytes(32, "big")


def account_id(root_public_key: bytes) -> str:
    return "oa1_" + sha256(ACCOUNT_ID_DOMAIN + root_public_key).hex()


def device_id(account: str, signing_public_key: bytes) -> str:
    return "od1_" + sha256(
        DEVICE_ID_DOMAIN + account.encode("ascii") + signing_public_key
    ).hex()


def binding_signing_bytes(
    *,
    account: str,
    root_public_key: bytes,
    recovery_public_key: bytes,
    handle: str | None,
    display_name: str | None,
    device: str,
    device_signing_public_key: bytes,
    noise_public_key: bytes,
    nostr_public_key: bytes,
    revision: int,
    issued_at: int,
) -> bytes:
    return b"".join(
        (
            LOCAL_BINDING_DOMAIN,
            u16(VERSION),
            push_u32(account.encode("ascii")),
            root_public_key,
            recovery_public_key,
            push_optional(handle),
            push_optional(display_name),
            push_u32(device.encode("ascii")),
            device_signing_public_key,
            noise_public_key,
            nostr_public_key,
            u64(revision),
            u64(issued_at),
        )
    )


def claim_proof_digest(
    command_id: bytes,
    expected_revision: int,
    binding_transcript: bytes,
    binding_signature: bytes,
) -> bytes:
    return sha256(
        b"".join(
            (
                CLAIM_DOMAIN,
                u16(VERSION),
                command_id,
                u64(expected_revision),
                push_u64(binding_transcript),
                binding_signature,
            )
        )
    )


def receipt_signing_bytes(
    *,
    sequence: int,
    command_id: bytes,
    account: str,
    handle: str,
    account_revision: int,
    claim_hash: bytes,
    previous_receipt_hash: bytes,
    previous_account_receipt_hash: bytes,
    accepted_at: int,
) -> bytes:
    return b"".join(
        (
            RECEIPT_DOMAIN,
            u16(VERSION),
            u64(sequence),
            command_id,
            push_u32(account.encode("ascii")),
            push_u32(handle.encode("ascii")),
            u64(account_revision),
            claim_hash,
            previous_receipt_hash,
            previous_account_receipt_hash,
            u64(accepted_at),
        )
    )


def fixed_inputs() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "registry_signing_seed_hex": (b"\x77" * 32).hex(),
        "accounts": [
            {
                "id": "alice",
                "account_root_seed_hex": (b"\x11" * 32).hex(),
                "recovery_seed_hex": (b"\x12" * 32).hex(),
                "device": {
                    "signing_seed_hex": (b"\x13" * 32).hex(),
                    "noise_secret_hex": (b"\x14" * 32).hex(),
                    "nostr_secret_hex": (b"\x15" * 32).hex(),
                },
            },
            {
                "id": "bob",
                "account_root_seed_hex": (b"\x21" * 32).hex(),
                "recovery_seed_hex": (b"\x22" * 32).hex(),
                "device": {
                    "signing_seed_hex": (b"\x23" * 32).hex(),
                    "noise_secret_hex": (b"\x24" * 32).hex(),
                    "nostr_secret_hex": (b"\x25" * 32).hex(),
                },
            },
        ],
        "transitions": [
            {
                "id": "alice-initial",
                "account": "alice",
                "command_id_hex": (b"\xa1" * 32).hex(),
                "expected_registry_revision": 0,
                "handle": "alice",
                "display_name": "Alice Example",
                "binding_revision": 1,
                "issued_at": 1_788_000_001,
                "accepted_at": 1_788_000_101,
            },
            {
                "id": "bob-initial",
                "account": "bob",
                "command_id_hex": (b"\xb1" * 32).hex(),
                "expected_registry_revision": 0,
                "handle": "bob",
                "display_name": "Bob Example",
                "binding_revision": 1,
                "issued_at": 1_788_000_002,
                "accepted_at": 1_788_000_102,
            },
            {
                "id": "alice-update-after-bob",
                "account": "alice",
                "command_id_hex": (b"\xa2" * 32).hex(),
                "expected_registry_revision": 1,
                "handle": "alice",
                "display_name": "Alice Example Updated",
                "binding_revision": 2,
                "issued_at": 1_788_000_003,
                "accepted_at": 1_788_000_103,
            },
        ],
    }


def generate() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    inputs = fixed_inputs()
    registry_private = ed25519_private(
        bytes.fromhex(inputs["registry_signing_seed_hex"])
    )
    account_material: dict[str, dict[str, Any]] = {}
    account_outputs = []

    for source in inputs["accounts"]:
        root_private = ed25519_private(bytes.fromhex(source["account_root_seed_hex"]))
        recovery_private = ed25519_private(bytes.fromhex(source["recovery_seed_hex"]))
        device_source = source["device"]
        device_signing_private = ed25519_private(
            bytes.fromhex(device_source["signing_seed_hex"])
        )
        noise_private = x25519.X25519PrivateKey.from_private_bytes(
            bytes.fromhex(device_source["noise_secret_hex"])
        )
        root_public_key = raw_public(root_private)
        recovery_public_key = raw_public(recovery_private)
        device_signing_public_key = raw_public(device_signing_private)
        noise_public_key = raw_public(noise_private)
        nostr_public_key = nostr_x_only_public(
            bytes.fromhex(device_source["nostr_secret_hex"])
        )
        derived_account_id = account_id(root_public_key)
        derived_device_id = device_id(derived_account_id, device_signing_public_key)
        material = {
            "root_private": root_private,
            "account_id": derived_account_id,
            "account_root_public_key": root_public_key,
            "recovery_public_key": recovery_public_key,
            "device_id": derived_device_id,
            "device_signing_public_key": device_signing_public_key,
            "noise_public_key": noise_public_key,
            "nostr_public_key": nostr_public_key,
        }
        account_material[source["id"]] = material
        account_outputs.append(
            {
                "id": source["id"],
                "account_id": derived_account_id,
                "account_root_public_key_hex": root_public_key.hex(),
                "recovery_public_key_hex": recovery_public_key.hex(),
                "device_id": derived_device_id,
                "device_signing_public_key_hex": device_signing_public_key.hex(),
                "noise_public_key_hex": noise_public_key.hex(),
                "nostr_public_key_hex": nostr_public_key.hex(),
            }
        )

    global_head = GENESIS_HASH
    account_heads: dict[str, bytes] = {}
    intermediate_transitions = []
    output_transitions = []
    for sequence, transition in enumerate(inputs["transitions"], start=1):
        material = account_material[transition["account"]]
        transcript = binding_signing_bytes(
            account=material["account_id"],
            root_public_key=material["account_root_public_key"],
            recovery_public_key=material["recovery_public_key"],
            handle=transition["handle"],
            display_name=transition["display_name"],
            device=material["device_id"],
            device_signing_public_key=material["device_signing_public_key"],
            noise_public_key=material["noise_public_key"],
            nostr_public_key=material["nostr_public_key"],
            revision=transition["binding_revision"],
            issued_at=transition["issued_at"],
        )
        binding_signature = material["root_private"].sign(transcript)
        command_id = bytes.fromhex(transition["command_id_hex"])
        proof_digest = claim_proof_digest(
            command_id,
            transition["expected_registry_revision"],
            transcript,
            binding_signature,
        )
        proof_signing_bytes = CLAIM_PROOF_DOMAIN + proof_digest
        claim_proof = material["root_private"].sign(proof_signing_bytes)
        claim_hash = sha256(CLAIM_HASH_DOMAIN + proof_digest + claim_proof)
        account_revision = transition["expected_registry_revision"] + 1
        previous_account_hash = account_heads.get(transition["account"], GENESIS_HASH)
        receipt_transcript = receipt_signing_bytes(
            sequence=sequence,
            command_id=command_id,
            account=material["account_id"],
            handle=transition["handle"],
            account_revision=account_revision,
            claim_hash=claim_hash,
            previous_receipt_hash=global_head,
            previous_account_receipt_hash=previous_account_hash,
            accepted_at=transition["accepted_at"],
        )
        receipt_signature = registry_private.sign(receipt_transcript)
        receipt_hash_preimage = push_u64(receipt_transcript) + receipt_signature
        receipt_hash = sha256(RECEIPT_HASH_DOMAIN + receipt_hash_preimage)

        intermediate_transitions.append(
            {
                "id": transition["id"],
                "binding_signing_bytes_hex": transcript.hex(),
                "claim_proof_digest_hex": proof_digest.hex(),
                "claim_proof_signing_bytes_hex": proof_signing_bytes.hex(),
                "receipt_signing_bytes_hex": receipt_transcript.hex(),
                "receipt_hash_preimage_hex": receipt_hash_preimage.hex(),
            }
        )
        output_transitions.append(
            {
                "id": transition["id"],
                "binding_signature_hex": binding_signature.hex(),
                "claim_proof_hex": claim_proof.hex(),
                "claim_hash_hex": claim_hash.hex(),
                "receipt": {
                    "version": VERSION,
                    "sequence": sequence,
                    "command_id_hex": command_id.hex(),
                    "account_id": material["account_id"],
                    "handle": transition["handle"],
                    "account_revision": account_revision,
                    "claim_hash_hex": claim_hash.hex(),
                    "previous_receipt_hash_hex": global_head.hex(),
                    "previous_account_receipt_hash_hex": previous_account_hash.hex(),
                    "accepted_at": transition["accepted_at"],
                    "signature_hex": receipt_signature.hex(),
                    "receipt_hash_hex": receipt_hash.hex(),
                },
            }
        )
        global_head = receipt_hash
        account_heads[transition["account"]] = receipt_hash

    intermediates = {
        "schema_version": 1,
        "transitions": intermediate_transitions,
    }
    outputs = {
        "schema_version": 1,
        "registry_public_key_hex": raw_public(registry_private).hex(),
        "accounts": account_outputs,
        "transitions": output_transitions,
    }
    return inputs, intermediates, outputs


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="new directory that will receive inputs/intermediates/outputs JSON",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    inputs, intermediates, outputs = generate()
    write_json(args.output_dir / "inputs.json", inputs)
    write_json(args.output_dir / "intermediates.json", intermediates)
    write_json(args.output_dir / "outputs.json", outputs)


if __name__ == "__main__":
    main()
