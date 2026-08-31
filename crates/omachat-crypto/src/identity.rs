use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use k256::schnorr::SigningKey as SchnorrSigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_BYTES: usize = 32;
const DERIVATION_ATTEMPTS: u32 = 10;
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The four unrelated long-term secret roots used by OmaChat.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecrets {
    noise_static_secret: [u8; KEY_BYTES],
    signing_seed: [u8; KEY_BYTES],
    nostr_identity_secret: [u8; KEY_BYTES],
    nostr_device_seed: [u8; KEY_BYTES],
}

impl IdentitySecrets {
    pub fn generate() -> Result<Self, IdentityError> {
        let mut noise_static_secret = [0_u8; KEY_BYTES];
        let mut signing_seed = [0_u8; KEY_BYTES];
        let mut nostr_identity_secret = [0_u8; KEY_BYTES];
        let mut nostr_device_seed = [0_u8; KEY_BYTES];
        getrandom::fill(&mut noise_static_secret).map_err(|_| IdentityError::Random)?;
        getrandom::fill(&mut signing_seed).map_err(|_| IdentityError::Random)?;
        getrandom::fill(&mut nostr_identity_secret).map_err(|_| IdentityError::Random)?;
        getrandom::fill(&mut nostr_device_seed).map_err(|_| IdentityError::Random)?;
        Ok(Self {
            noise_static_secret,
            signing_seed,
            nostr_identity_secret,
            nostr_device_seed,
        })
    }

    #[must_use]
    pub fn from_seeds(
        noise_static_secret: [u8; KEY_BYTES],
        signing_seed: [u8; KEY_BYTES],
        nostr_device_seed: [u8; KEY_BYTES],
    ) -> Self {
        let nostr_identity_secret =
            Sha256::digest([b"nostr-identity|".as_slice(), nostr_device_seed.as_slice()].concat())
                .into();
        Self::from_all_seeds(
            noise_static_secret,
            signing_seed,
            nostr_identity_secret,
            nostr_device_seed,
        )
    }

    #[must_use]
    pub fn from_all_seeds(
        noise_static_secret: [u8; KEY_BYTES],
        signing_seed: [u8; KEY_BYTES],
        nostr_identity_secret: [u8; KEY_BYTES],
        nostr_device_seed: [u8; KEY_BYTES],
    ) -> Self {
        Self {
            noise_static_secret,
            signing_seed,
            nostr_identity_secret,
            nostr_device_seed,
        }
    }

    #[must_use]
    pub fn public_identity(&self) -> PublicIdentity {
        let noise_public_key = x25519(self.noise_static_secret, X25519_BASEPOINT_BYTES);
        let signing_public_key = SigningKey::from_bytes(&self.signing_seed)
            .verifying_key()
            .to_bytes();
        let fingerprint = Sha256::digest(noise_public_key);
        let fingerprint_hex = hex::encode(fingerprint);
        let peer_id = fingerprint_hex[..16].to_owned();
        PublicIdentity {
            noise_public_key,
            signing_public_key,
            fingerprint_hex,
            peer_id,
        }
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.signing_seed)
            .sign(message)
            .to_bytes()
    }

    pub fn derive_geohash_identity(
        &self,
        geohash: &str,
    ) -> Result<DerivedNostrIdentity, IdentityError> {
        derive_identity(&self.nostr_device_seed, geohash)
    }

    /// Stable Nostr identity used for private mailbox addressing. The
    /// independently generated device seed is kept separate from Noise and
    /// Ed25519 roots; the practically impossible invalid scalar case is
    /// deterministically rehashed instead of rotating identity.
    pub fn device_nostr_identity(&self) -> Result<DerivedNostrIdentity, IdentityError> {
        identity_from_private(self.nostr_identity_secret, DerivationSource::Candidate(0)).or_else(
            |_| {
                identity_from_private(
                    Sha256::digest(self.nostr_identity_secret).into(),
                    DerivationSource::Fallback,
                )
            },
        )
    }

    pub fn derive_bridge_identity(
        &self,
        cell: &str,
    ) -> Result<DerivedNostrIdentity, IdentityError> {
        derive_identity(&self.nostr_device_seed, &format!("bridge|{cell}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicIdentity {
    pub noise_public_key: [u8; KEY_BYTES],
    pub signing_public_key: [u8; KEY_BYTES],
    pub fingerprint_hex: String,
    pub peer_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationSource {
    Candidate(u32),
    Fallback,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedNostrIdentity {
    private_key: [u8; KEY_BYTES],
    #[zeroize(skip)]
    public_key: [u8; KEY_BYTES],
    #[zeroize(skip)]
    npub: String,
    #[zeroize(skip)]
    source: DerivationSource,
}

impl DerivedNostrIdentity {
    #[must_use]
    pub fn private_key(&self) -> &[u8; KEY_BYTES] {
        &self.private_key
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; KEY_BYTES] {
        &self.public_key
    }

    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    #[must_use]
    pub fn npub(&self) -> &str {
        &self.npub
    }

    #[must_use]
    pub fn source(&self) -> DerivationSource {
        self.source
    }
}

fn derive_identity(
    seed: &[u8; KEY_BYTES],
    label: &str,
) -> Result<DerivedNostrIdentity, IdentityError> {
    let label_bytes = label.as_bytes();
    let mut candidate = |iteration: u32| {
        let mut mac = Hmac::<Sha256>::new_from_slice(seed).expect("HMAC accepts any key length");
        mac.update(label_bytes);
        mac.update(&iteration.to_be_bytes());
        mac.finalize().into_bytes().into()
    };
    let mut fallback_hasher = Sha256::new();
    fallback_hasher.update(seed);
    fallback_hasher.update(label_bytes);
    let fallback = fallback_hasher.finalize().into();
    derive_with_candidates(&mut candidate, fallback)
}

fn derive_with_candidates(
    candidate: &mut impl FnMut(u32) -> [u8; KEY_BYTES],
    fallback: [u8; KEY_BYTES],
) -> Result<DerivedNostrIdentity, IdentityError> {
    for iteration in 0..DERIVATION_ATTEMPTS {
        if let Ok(identity) =
            identity_from_private(candidate(iteration), DerivationSource::Candidate(iteration))
        {
            return Ok(identity);
        }
    }
    identity_from_private(fallback, DerivationSource::Fallback)
}

fn identity_from_private(
    private_key: [u8; KEY_BYTES],
    source: DerivationSource,
) -> Result<DerivedNostrIdentity, IdentityError> {
    let signing_key = SchnorrSigningKey::from_bytes(&private_key)
        .map_err(|_| IdentityError::InvalidSecp256k1Scalar)?;
    let public_key: [u8; KEY_BYTES] = signing_key.verifying_key().to_bytes().into();
    Ok(DerivedNostrIdentity {
        private_key,
        public_key,
        npub: bech32_npub(&public_key),
        source,
    })
}

fn bech32_npub(public_key: &[u8; KEY_BYTES]) -> String {
    let data = convert_bits(public_key, 8, 5);
    let mut values = data.clone();
    values.extend_from_slice(&bech32_checksum("npub", &data));
    let mut encoded = String::from("npub1");
    encoded.extend(
        values
            .into_iter()
            .map(|value| BECH32_CHARSET[value as usize] as char),
    );
    encoded
}

fn convert_bits(input: &[u8], from: u32, to: u32) -> Vec<u8> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let mask = (1_u32 << to) - 1;
    let mut output = Vec::with_capacity((input.len() * from as usize).div_ceil(to as usize));
    for value in input {
        accumulator = (accumulator << from) | u32::from(*value);
        bits += from;
        while bits >= to {
            bits -= to;
            output.push(((accumulator >> bits) & mask) as u8);
        }
    }
    if bits > 0 {
        output.push(((accumulator << (to - bits)) & mask) as u8);
    }
    output
}

fn bech32_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values: Vec<u8> = hrp.bytes().map(|byte| byte >> 5).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|byte| byte & 0x1f));
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let polymod = bech32_polymod(&values) ^ 1;
    std::array::from_fn(|index| ((polymod >> (5 * (5 - index))) & 0x1f) as u8)
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1_u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (index, generator) in GENERATORS.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    Random,
    InvalidSecp256k1Scalar,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random => formatter.write_str("secure identity random generation failed"),
            Self::InvalidSecp256k1Scalar => {
                formatter.write_str("derived secp256k1 scalar is invalid")
            }
        }
    }
}

impl Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_candidates_retry_with_exact_iteration() {
        let mut seen = Vec::new();
        let mut candidates = |iteration| {
            seen.push(iteration);
            if iteration == 3 { [1; 32] } else { [0; 32] }
        };
        let identity = derive_with_candidates(&mut candidates, [2; 32]).expect("valid retry");
        assert_eq!(seen, vec![0, 1, 2, 3]);
        assert_eq!(identity.source(), DerivationSource::Candidate(3));
    }

    #[test]
    fn fallback_runs_only_after_ten_invalid_candidates() {
        let mut seen = Vec::new();
        let identity = derive_with_candidates(
            &mut |iteration| {
                seen.push(iteration);
                [0; 32]
            },
            [2; 32],
        )
        .expect("valid fallback");
        assert_eq!(seen, (0..10).collect::<Vec<_>>());
        assert_eq!(identity.source(), DerivationSource::Fallback);
        assert_eq!(identity.private_key(), &[2; 32]);
    }

    #[test]
    fn bridge_domain_is_separate_from_geohash_domain() {
        let secrets = IdentitySecrets::from_seeds([1; 32], [2; 32], [3; 32]);
        assert_ne!(
            secrets
                .derive_geohash_identity("u4pruy")
                .expect("geohash")
                .public_key(),
            secrets
                .derive_bridge_identity("u4pruy")
                .expect("bridge")
                .public_key()
        );
    }
}
