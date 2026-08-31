//! Compatibility-critical cryptographic primitives backed by captured vectors.

mod identity;

pub use identity::{
    DerivationSource, DerivedNostrIdentity, IdentityError, IdentitySecrets, PublicIdentity,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use k256::{
    EncodedPoint, ProjectivePoint, PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::Sha256;
use std::{error::Error, fmt};

const PREFIX: &str = "v2:";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;

/// Derive bitchat's private-envelope key from the full compressed ECDH point.
///
/// This intentionally differs from ordinary NIP-44 helpers, which use only the
/// shared X coordinate. The x-only peer key is lifted using the even-Y prefix.
pub fn private_envelope_key(
    local_secret_key: &[u8; 32],
    peer_xonly_public_key: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    private_envelope_key_with_prefix(local_secret_key, peer_xonly_public_key, 0x02)
}

/// Open an envelope from an x-only peer key, trying the two possible Y
/// parities exactly as the pinned Swift receiver does.
pub fn open_from_xonly_peer(
    local_secret_key: &[u8; 32],
    peer_xonly_public_key: &[u8; 32],
    encoded: &str,
    maximum_plaintext_bytes: usize,
) -> Result<Vec<u8>, CryptoError> {
    let even_key = private_envelope_key_with_prefix(local_secret_key, peer_xonly_public_key, 0x02)?;
    match open(&even_key, encoded, maximum_plaintext_bytes) {
        Ok(plaintext) => Ok(plaintext),
        Err(CryptoError::Authentication) => {
            let odd_key =
                private_envelope_key_with_prefix(local_secret_key, peer_xonly_public_key, 0x03)?;
            open(&odd_key, encoded, maximum_plaintext_bytes)
        }
        Err(error) => Err(error),
    }
}

fn private_envelope_key_with_prefix(
    local_secret_key: &[u8; 32],
    peer_xonly_public_key: &[u8; 32],
    prefix: u8,
) -> Result<[u8; 32], CryptoError> {
    let secret = SecretKey::from_slice(local_secret_key).map_err(|_| CryptoError::SecretKey)?;
    let mut compressed_peer = [0; 33];
    compressed_peer[0] = prefix;
    compressed_peer[1..].copy_from_slice(peer_xonly_public_key);
    let peer = PublicKey::from_sec1_bytes(&compressed_peer).map_err(|_| CryptoError::PublicKey)?;
    let point = (ProjectivePoint::from(*peer.as_affine()) * secret.to_nonzero_scalar().as_ref())
        .to_affine();
    let encoded: EncodedPoint = point.to_encoded_point(true);
    let hkdf = Hkdf::<Sha256>::new(Some(&[]), encoded.as_bytes());
    let mut key = [0; 32];
    hkdf.expand(b"nip44-v2", &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Encrypt bytes using the captured `v2:` XChaCha20-Poly1305 wire layout.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    maximum_plaintext_bytes: usize,
) -> Result<String, CryptoError> {
    if plaintext.len() > maximum_plaintext_bytes {
        return Err(CryptoError::PlaintextTooLarge {
            bytes: plaintext.len(),
            maximum: maximum_plaintext_bytes,
        });
    }
    let key = Key::from(*key);
    let nonce = XNonce::from(*nonce);
    let cipher = XChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::Encryption)?;
    let mut payload = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(payload)))
}

/// Authenticate and decrypt the captured `v2:` wire layout.
pub fn open(
    key: &[u8; 32],
    encoded: &str,
    maximum_plaintext_bytes: usize,
) -> Result<Vec<u8>, CryptoError> {
    let body = encoded
        .strip_prefix(PREFIX)
        .ok_or(CryptoError::InvalidPrefix)?;
    let maximum_payload_bytes = maximum_plaintext_bytes
        .saturating_add(NONCE_BYTES)
        .saturating_add(TAG_BYTES);
    let maximum_encoded_bytes = maximum_payload_bytes.saturating_mul(4).saturating_add(2) / 3;
    if body.len() > maximum_encoded_bytes {
        return Err(CryptoError::CiphertextTooLarge {
            bytes: body.len(),
            maximum: maximum_encoded_bytes,
        });
    }
    let payload = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| CryptoError::InvalidBase64)?;
    if payload.len() < NONCE_BYTES + TAG_BYTES {
        return Err(CryptoError::TruncatedCiphertext);
    }
    if payload.len() - NONCE_BYTES - TAG_BYTES > maximum_plaintext_bytes {
        return Err(CryptoError::PlaintextTooLarge {
            bytes: payload.len() - NONCE_BYTES - TAG_BYTES,
            maximum: maximum_plaintext_bytes,
        });
    }
    let (nonce, ciphertext) = payload.split_at(NONCE_BYTES);
    let nonce = XNonce::from(
        <[u8; NONCE_BYTES]>::try_from(nonce).expect("nonce split has a fixed 24-byte length"),
    );
    let key = Key::from(*key);
    XChaCha20Poly1305::new(&key)
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::Authentication)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    SecretKey,
    PublicKey,
    KeyDerivation,
    PlaintextTooLarge { bytes: usize, maximum: usize },
    CiphertextTooLarge { bytes: usize, maximum: usize },
    Encryption,
    InvalidPrefix,
    InvalidBase64,
    TruncatedCiphertext,
    Authentication,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretKey => formatter.write_str("invalid secp256k1 secret key"),
            Self::PublicKey => formatter.write_str("invalid x-only secp256k1 public key"),
            Self::KeyDerivation => formatter.write_str("private-envelope HKDF failed"),
            Self::PlaintextTooLarge { bytes, maximum } => write!(
                formatter,
                "private-envelope plaintext is {bytes} bytes; maximum is {maximum}"
            ),
            Self::CiphertextTooLarge { bytes, maximum } => write!(
                formatter,
                "private-envelope encoded body is {bytes} bytes; maximum is {maximum}"
            ),
            Self::Encryption => formatter.write_str("private-envelope encryption failed"),
            Self::InvalidPrefix => formatter.write_str("private envelope is missing v2 prefix"),
            Self::InvalidBase64 => formatter.write_str("private envelope is not base64url"),
            Self::TruncatedCiphertext => formatter.write_str("private envelope is truncated"),
            Self::Authentication => formatter.write_str("private envelope authentication failed"),
        }
    }
}

impl Error for CryptoError {}
