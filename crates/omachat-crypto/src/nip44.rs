//! NIP-44 version 2 encrypted payloads.
//!
//! This module is deliberately separate from OmaChat's legacy private envelope.
//! NIP-44 payloads must be carried by a signature-verified NIP-01 event; these
//! helpers only perform the encryption layer and cannot verify the outer event.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::{ProjectivePoint, PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

const VERSION: u8 = 2;
const SALT: &[u8] = b"nip44-v2";
const NONCE_LEN: usize = 32;
const MAC_LEN: usize = 32;
const MESSAGE_KEY_LEN: usize = 76;
const MIN_ENCODED_PAYLOAD_LEN: usize = 132;
const MIN_DECODED_PAYLOAD_LEN: usize = 99;
const EXTENDED_PREFIX_THRESHOLD: usize = 65_536;

/// OmaChat's defensive local ceiling for one decrypted NIP-44 plaintext.
///
/// NIP-44 permits larger payloads, but implementations are expected to enforce
/// a platform-appropriate bound before base64 decoding to limit memory abuse.
pub const MAX_PLAINTEXT_LEN: usize = 1024 * 1024;

/// Errors returned by NIP-44 v2 operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Nip44Error {
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidPlaintextLength,
    PayloadTooLarge,
    InvalidPayloadSize,
    InvalidBase64,
    UnsupportedVersion,
    InvalidMac,
    InvalidPadding,
    InvalidUtf8,
    RandomnessUnavailable,
    KeyDerivationFailed,
}

impl fmt::Display for Nip44Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSecretKey => "invalid NIP-44 secret key",
            Self::InvalidPublicKey => "invalid NIP-44 public key",
            Self::InvalidPlaintextLength => "invalid NIP-44 plaintext length",
            Self::PayloadTooLarge => "NIP-44 payload exceeds the local resource limit",
            Self::InvalidPayloadSize => "invalid NIP-44 payload size",
            Self::InvalidBase64 => "invalid NIP-44 base64 payload",
            Self::UnsupportedVersion => "unsupported NIP-44 payload version",
            Self::InvalidMac => "invalid NIP-44 message authentication code",
            Self::InvalidPadding => "invalid NIP-44 padding",
            Self::InvalidUtf8 => "invalid UTF-8 in NIP-44 plaintext",
            Self::RandomnessUnavailable => "secure randomness is unavailable",
            Self::KeyDerivationFailed => "NIP-44 key derivation failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for Nip44Error {}

/// Derive the stable NIP-44 v2 conversation key for a local secret and peer's
/// x-only Nostr public key.
pub fn conversation_key(
    local_secret: &[u8; 32],
    peer_public_key: &[u8; 32],
) -> Result<[u8; 32], Nip44Error> {
    let secret = SecretKey::from_slice(local_secret).map_err(|_| Nip44Error::InvalidSecretKey)?;
    let mut compressed_peer = [0_u8; 33];
    compressed_peer[0] = 0x02;
    compressed_peer[1..].copy_from_slice(peer_public_key);
    let peer =
        PublicKey::from_sec1_bytes(&compressed_peer).map_err(|_| Nip44Error::InvalidPublicKey)?;

    let shared = ProjectivePoint::from(*peer.as_affine()) * secret.to_nonzero_scalar().as_ref();
    let encoded = shared.to_affine().to_encoded_point(true);
    let shared_x = encoded.x().ok_or(Nip44Error::InvalidPublicKey)?;
    let (prk, _) = Hkdf::<Sha256>::extract(Some(SALT), shared_x);
    let mut result = [0_u8; 32];
    result.copy_from_slice(prk.as_slice());
    Ok(result)
}

/// Encrypt UTF-8 plaintext using a fresh CSPRNG nonce.
pub fn encrypt(
    local_secret: &[u8; 32],
    peer_public_key: &[u8; 32],
    plaintext: &str,
) -> Result<String, Nip44Error> {
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Nip44Error::RandomnessUnavailable)?;
    encrypt_with_nonce(local_secret, peer_public_key, plaintext, nonce)
}

/// Encrypt UTF-8 plaintext with an injected nonce.
///
/// This deterministic entry point exists for conformance vectors. Production
/// callers should use [`encrypt`] and must never reuse a nonce for a conversation.
pub fn encrypt_with_nonce(
    local_secret: &[u8; 32],
    peer_public_key: &[u8; 32],
    plaintext: &str,
    nonce: [u8; NONCE_LEN],
) -> Result<String, Nip44Error> {
    let key = Zeroizing::new(conversation_key(local_secret, peer_public_key)?);
    encrypt_with_conversation_key(&key, plaintext, nonce)
}

/// Decrypt a NIP-44 payload after the caller has verified its outer NIP-01
/// event signature and author key.
pub fn decrypt(
    local_secret: &[u8; 32],
    peer_public_key: &[u8; 32],
    payload: &str,
) -> Result<String, Nip44Error> {
    let key = Zeroizing::new(conversation_key(local_secret, peer_public_key)?);
    decrypt_with_conversation_key(&key, payload)
}

fn encrypt_with_conversation_key(
    conversation_key: &[u8; 32],
    plaintext: &str,
    nonce: [u8; NONCE_LEN],
) -> Result<String, Nip44Error> {
    let mut ciphertext = pad(plaintext.as_bytes())?;
    let keys = message_keys(conversation_key, &nonce)?;
    let mut cipher = ChaCha20::new_from_slices(&keys[..32], &keys[32..44])
        .map_err(|_| Nip44Error::KeyDerivationFailed)?;
    cipher.apply_keystream(&mut ciphertext);

    let mut hmac =
        Hmac::<Sha256>::new_from_slice(&keys[44..]).map_err(|_| Nip44Error::KeyDerivationFailed)?;
    hmac.update(&nonce);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len() + MAC_LEN);
    payload.push(VERSION);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac);
    Ok(STANDARD.encode(payload))
}

fn decrypt_with_conversation_key(
    conversation_key: &[u8; 32],
    payload: &str,
) -> Result<String, Nip44Error> {
    if payload.is_empty() || payload.starts_with('#') {
        return Err(Nip44Error::UnsupportedVersion);
    }
    if payload.len() < MIN_ENCODED_PAYLOAD_LEN {
        return Err(Nip44Error::InvalidPayloadSize);
    }
    if payload.len() > maximum_encoded_payload_len()? {
        return Err(Nip44Error::PayloadTooLarge);
    }

    let decoded = STANDARD
        .decode(payload)
        .map_err(|_| Nip44Error::InvalidBase64)?;
    if decoded.len() < MIN_DECODED_PAYLOAD_LEN {
        return Err(Nip44Error::InvalidPayloadSize);
    }
    if decoded[0] != VERSION {
        return Err(Nip44Error::UnsupportedVersion);
    }

    let nonce: &[u8; NONCE_LEN] = decoded[1..33]
        .try_into()
        .map_err(|_| Nip44Error::InvalidPayloadSize)?;
    let ciphertext_end = decoded.len() - MAC_LEN;
    let ciphertext = &decoded[33..ciphertext_end];
    let supplied_mac = &decoded[ciphertext_end..];
    let keys = message_keys(conversation_key, nonce)?;

    let mut hmac =
        Hmac::<Sha256>::new_from_slice(&keys[44..]).map_err(|_| Nip44Error::KeyDerivationFailed)?;
    hmac.update(nonce);
    hmac.update(ciphertext);
    hmac.verify_slice(supplied_mac)
        .map_err(|_| Nip44Error::InvalidMac)?;

    let mut padded = ciphertext.to_vec();
    let mut cipher = ChaCha20::new_from_slices(&keys[..32], &keys[32..44])
        .map_err(|_| Nip44Error::KeyDerivationFailed)?;
    cipher.apply_keystream(&mut padded);
    let plaintext = unpad(&padded)?;
    String::from_utf8(plaintext).map_err(|_| Nip44Error::InvalidUtf8)
}

fn message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Zeroizing<[u8; MESSAGE_KEY_LEN]>, Nip44Error> {
    let hkdf =
        Hkdf::<Sha256>::from_prk(conversation_key).map_err(|_| Nip44Error::KeyDerivationFailed)?;
    let mut keys = Zeroizing::new([0_u8; MESSAGE_KEY_LEN]);
    hkdf.expand(nonce, &mut keys[..])
        .map_err(|_| Nip44Error::KeyDerivationFailed)?;
    Ok(keys)
}

fn pad(plaintext: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    let plaintext_len = plaintext.len();
    if plaintext_len == 0 {
        return Err(Nip44Error::InvalidPlaintextLength);
    }
    if plaintext_len > MAX_PLAINTEXT_LEN || plaintext_len > u32::MAX as usize {
        return Err(Nip44Error::PayloadTooLarge);
    }

    let padded_len = calc_padded_len(plaintext_len)?;
    let prefix_len = if plaintext_len >= EXTENDED_PREFIX_THRESHOLD {
        6
    } else {
        2
    };
    let mut padded = Vec::with_capacity(prefix_len + padded_len);
    if prefix_len == 6 {
        padded.extend_from_slice(&[0, 0]);
        padded.extend_from_slice(&(plaintext_len as u32).to_be_bytes());
    } else {
        padded.extend_from_slice(&(plaintext_len as u16).to_be_bytes());
    }
    padded.extend_from_slice(plaintext);
    padded.resize(prefix_len + padded_len, 0);
    Ok(padded)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    if padded.len() < 2 {
        return Err(Nip44Error::InvalidPadding);
    }
    let first = u16::from_be_bytes([padded[0], padded[1]]);
    let (prefix_len, plaintext_len): (usize, usize) = if first == 0 {
        if padded.len() < 6 {
            return Err(Nip44Error::InvalidPadding);
        }
        let length = u32::from_be_bytes([padded[2], padded[3], padded[4], padded[5]]) as usize;
        if length < EXTENDED_PREFIX_THRESHOLD {
            return Err(Nip44Error::InvalidPadding);
        }
        (6, length)
    } else {
        (2, usize::from(first))
    };

    if plaintext_len > MAX_PLAINTEXT_LEN {
        return Err(Nip44Error::PayloadTooLarge);
    }
    let expected = prefix_len
        .checked_add(calc_padded_len(plaintext_len)?)
        .ok_or(Nip44Error::InvalidPadding)?;
    if padded.len() != expected {
        return Err(Nip44Error::InvalidPadding);
    }
    let end = prefix_len
        .checked_add(plaintext_len)
        .ok_or(Nip44Error::InvalidPadding)?;
    Ok(padded
        .get(prefix_len..end)
        .ok_or(Nip44Error::InvalidPadding)?
        .to_vec())
}

fn calc_padded_len(plaintext_len: usize) -> Result<usize, Nip44Error> {
    if plaintext_len == 0 {
        return Err(Nip44Error::InvalidPlaintextLength);
    }
    if plaintext_len <= 32 {
        return Ok(32);
    }
    let next_power = plaintext_len
        .checked_next_power_of_two()
        .ok_or(Nip44Error::PayloadTooLarge)?;
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    plaintext_len
        .checked_sub(1)
        .and_then(|length| length.checked_div(chunk))
        .and_then(|chunks| chunks.checked_add(1))
        .and_then(|chunks| chunks.checked_mul(chunk))
        .ok_or(Nip44Error::PayloadTooLarge)
}

fn maximum_encoded_payload_len() -> Result<usize, Nip44Error> {
    let prefix_len = if MAX_PLAINTEXT_LEN >= EXTENDED_PREFIX_THRESHOLD {
        6
    } else {
        2
    };
    let padded_len = calc_padded_len(MAX_PLAINTEXT_LEN)?;
    let raw_len = 1_usize
        .checked_add(NONCE_LEN)
        .and_then(|length| length.checked_add(prefix_len))
        .and_then(|length| length.checked_add(padded_len))
        .and_then(|length| length.checked_add(MAC_LEN))
        .ok_or(Nip44Error::PayloadTooLarge)?;
    raw_len
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|length| length.checked_mul(4))
        .ok_or(Nip44Error::PayloadTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sha2::Digest;

    const VECTORS: &str = include_str!("../../../conformance/fixtures/nip44.vectors.json");

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    #[test]
    fn matches_official_conversation_key_vectors() {
        let document = vectors();
        for vector in document["v2"]["valid"]["get_conversation_key"]
            .as_array()
            .unwrap()
        {
            let secret = bytes(vector["sec1"].as_str().unwrap());
            let public = bytes(vector["pub2"].as_str().unwrap());
            let expected = bytes(vector["conversation_key"].as_str().unwrap());
            assert_eq!(conversation_key(&secret, &public).unwrap(), expected);
        }
    }

    #[test]
    fn matches_official_message_key_vectors() {
        let document = vectors();
        let vectors = &document["v2"]["valid"]["get_message_keys"];
        let conversation = bytes(vectors["conversation_key"].as_str().unwrap());
        for vector in vectors["keys"].as_array().unwrap() {
            let nonce = bytes(vector["nonce"].as_str().unwrap());
            let keys = message_keys(&conversation, &nonce).unwrap();
            assert_eq!(
                &keys[..32],
                &bytes::<32>(vector["chacha_key"].as_str().unwrap())
            );
            assert_eq!(
                &keys[32..44],
                &bytes::<12>(vector["chacha_nonce"].as_str().unwrap())
            );
            assert_eq!(
                &keys[44..],
                &bytes::<32>(vector["hmac_key"].as_str().unwrap())
            );
        }
    }

    #[test]
    fn matches_official_padding_vectors() {
        let document = vectors();
        for vector in document["v2"]["valid"]["calc_padded_len"]
            .as_array()
            .unwrap()
        {
            let pair = vector.as_array().unwrap();
            assert_eq!(
                calc_padded_len(pair[0].as_u64().unwrap() as usize).unwrap(),
                pair[1].as_u64().unwrap() as usize
            );
        }
    }

    #[test]
    fn matches_official_encrypt_decrypt_vectors() {
        let document = vectors();
        for vector in document["v2"]["valid"]["encrypt_decrypt"]
            .as_array()
            .unwrap()
        {
            let conversation = bytes(vector["conversation_key"].as_str().unwrap());
            let nonce = bytes(vector["nonce"].as_str().unwrap());
            let plaintext = vector["plaintext"].as_str().unwrap();
            let expected = vector["payload"].as_str().unwrap();
            let payload = encrypt_with_conversation_key(&conversation, plaintext, nonce).unwrap();
            assert_eq!(payload, expected);
            assert_eq!(
                decrypt_with_conversation_key(&conversation, &payload).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn rejects_official_invalid_decrypt_vectors() {
        let document = vectors();
        for vector in document["v2"]["invalid"]["decrypt"].as_array().unwrap() {
            let conversation = bytes(vector["conversation_key"].as_str().unwrap());
            let payload = vector["payload"].as_str().unwrap();
            assert!(decrypt_with_conversation_key(&conversation, payload).is_err());
        }
    }

    #[test]
    fn matches_current_extended_prefix_boundary_hashes() {
        let conversation =
            bytes("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
        let nonce = bytes("0000000000000000000000000000000000000000000000000000000000000001");
        let cases = [
            (
                65_535,
                "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84",
            ),
            (
                65_536,
                "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616",
            ),
            (
                65_537,
                "eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435",
            ),
        ];
        for (length, expected_hash) in cases {
            let plaintext = "a".repeat(length);
            let payload = encrypt_with_conversation_key(&conversation, &plaintext, nonce).unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(payload.as_bytes())),
                expected_hash
            );
            assert_eq!(
                decrypt_with_conversation_key(&conversation, &payload).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn rejects_unversioned_empty_and_oversized_inputs_before_decryption() {
        let key = [1_u8; 32];
        assert_eq!(
            decrypt_with_conversation_key(&key, "#future").unwrap_err(),
            Nip44Error::UnsupportedVersion
        );
        assert_eq!(
            encrypt_with_conversation_key(&key, "", [2_u8; 32]).unwrap_err(),
            Nip44Error::InvalidPlaintextLength
        );
        let oversized = "a".repeat(MAX_PLAINTEXT_LEN + 1);
        assert_eq!(
            encrypt_with_conversation_key(&key, &oversized, [2_u8; 32]).unwrap_err(),
            Nip44Error::PayloadTooLarge
        );
    }
}
