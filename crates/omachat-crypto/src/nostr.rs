use bech32::{Bech32, Hrp, primitives::decode::CheckedHrpstring};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use std::{error::Error, fmt};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;

/// A Nostr secret key. The 32 bytes are the BIP-340 scalar, not an `nsec` string.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NostrSecret {
    secret: [u8; KEY_BYTES],
}

impl NostrSecret {
    pub fn generate() -> Result<Self, NostrIdentityError> {
        let mut secret = [0_u8; KEY_BYTES];
        getrandom::fill(&mut secret).map_err(|_| NostrIdentityError::Random)?;
        Self::from_bytes(secret)
    }

    pub fn from_bytes(secret: [u8; KEY_BYTES]) -> Result<Self, NostrIdentityError> {
        SigningKey::from_bytes(&secret).map_err(|_| NostrIdentityError::InvalidSecret)?;
        Ok(Self { secret })
    }

    pub fn from_nsec(nsec: &str) -> Result<Self, NostrIdentityError> {
        let bytes = decode_key(nsec, "nsec")?;
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; KEY_BYTES] {
        let signing =
            SigningKey::from_bytes(&self.secret).expect("secret was checked at construction");
        let encoded = signing.verifying_key().to_bytes();
        let mut public_key = [0_u8; KEY_BYTES];
        public_key.copy_from_slice(encoded.as_slice());
        public_key
    }

    #[must_use]
    pub fn npub(&self) -> String {
        npub_from_public_key(&self.public_key()).expect("32-byte key encodes")
    }

    #[must_use]
    pub fn nsec(&self) -> String {
        encode_key("nsec", &self.secret).expect("32-byte secret encodes")
    }

    #[must_use]
    pub fn raw_secret(&self) -> &[u8; KEY_BYTES] {
        &self.secret
    }

    /// BIP-340 Schnorr signature over `message` (the message is not pre-hashed).
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], NostrIdentityError> {
        let signing =
            SigningKey::from_bytes(&self.secret).map_err(|_| NostrIdentityError::InvalidSecret)?;
        let mut aux = [0_u8; KEY_BYTES];
        getrandom::fill(&mut aux).map_err(|_| NostrIdentityError::Random)?;
        let signature = signing
            .sign_raw(message, &aux)
            .map_err(|_| NostrIdentityError::Sign)?;
        Ok(signature.to_bytes())
    }
}

#[must_use]
pub fn nostr_public_key_hex(public_key: &[u8; KEY_BYTES]) -> String {
    hex::encode(public_key)
}

pub fn npub_from_public_key(public_key: &[u8; KEY_BYTES]) -> Result<String, NostrIdentityError> {
    encode_key("npub", public_key)
}

pub fn public_key_from_npub(npub: &str) -> Result<[u8; KEY_BYTES], NostrIdentityError> {
    decode_key(npub, "npub")
}

pub fn verify_nostr(
    public_key: &[u8; KEY_BYTES],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), NostrIdentityError> {
    let key =
        VerifyingKey::from_bytes(public_key).map_err(|_| NostrIdentityError::InvalidPublicKey)?;
    let signature = Signature::try_from(signature.as_slice())
        .map_err(|_| NostrIdentityError::InvalidSignature)?;
    key.verify_raw(message, &signature)
        .map_err(|_| NostrIdentityError::InvalidSignature)
}

fn encode_key(hrp_text: &str, key: &[u8; KEY_BYTES]) -> Result<String, NostrIdentityError> {
    let hrp = Hrp::parse(hrp_text).map_err(|_| NostrIdentityError::Bech32)?;
    bech32::encode::<Bech32>(hrp, key).map_err(|_| NostrIdentityError::Bech32)
}

fn decode_key(encoded: &str, expected_hrp: &str) -> Result<[u8; KEY_BYTES], NostrIdentityError> {
    if encoded.len() > 90 || encoded.chars().any(char::is_whitespace) {
        return Err(NostrIdentityError::Bech32);
    }
    let checked =
        CheckedHrpstring::new::<Bech32>(encoded).map_err(|_| NostrIdentityError::Bech32)?;
    if checked.hrp().to_lowercase() != expected_hrp {
        return Err(NostrIdentityError::Bech32);
    }
    let mut key = [0_u8; KEY_BYTES];
    let mut length = 0_usize;
    for (index, byte) in checked.byte_iter().enumerate() {
        if index >= KEY_BYTES {
            return Err(NostrIdentityError::Bech32);
        }
        key[index] = byte;
        length += 1;
    }
    if length != KEY_BYTES {
        return Err(NostrIdentityError::Bech32);
    }
    Ok(key)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrIdentityError {
    Random,
    InvalidSecret,
    InvalidPublicKey,
    InvalidSignature,
    Sign,
    Bech32,
}

impl fmt::Display for NostrIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Random => "operating system randomness unavailable",
            Self::InvalidSecret => "not a valid secp256k1 secret key",
            Self::InvalidPublicKey => "not a valid x-only secp256k1 public key",
            Self::InvalidSignature => "BIP-340 signature does not verify",
            Self::Sign => "BIP-340 signing failed",
            Self::Bech32 => "not a valid NIP-19 bech32 key",
        })
    }
}

impl Error for NostrIdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nip19_vectors_round_trip() {
        let cases = [
            (
                "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
                "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6",
            ),
            (
                "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e",
                "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
            ),
        ];
        for (hex_key, npub) in cases {
            let mut public_key = [0_u8; 32];
            hex::decode_to_slice(hex_key, &mut public_key).unwrap();
            assert_eq!(npub_from_public_key(&public_key).unwrap(), npub);
            assert_eq!(public_key_from_npub(npub).unwrap(), public_key);
            assert_eq!(
                public_key_from_npub(&npub.to_uppercase()).unwrap(),
                public_key
            );
        }

        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let secret = NostrSecret::from_nsec(nsec).unwrap();
        assert_eq!(
            hex::encode(secret.public_key()),
            hex::encode({
                let mut raw = [0_u8; 32];
                hex::decode_to_slice(
                    "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa",
                    &mut raw,
                )
                .unwrap();
                NostrSecret::from_bytes(raw).unwrap().public_key()
            })
        );
        assert_eq!(secret.nsec(), nsec);
        let exported = secret.nsec();
        let again = NostrSecret::from_nsec(&exported).unwrap();
        assert_eq!(again.public_key(), secret.public_key());
        assert_eq!(again.nsec(), nsec);
    }

    #[test]
    fn nsec_rejects_bad_checksum_wrong_prefix_and_invalid_scalar() {
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let mut broken: Vec<u8> = nsec.bytes().collect();
        let last = broken.len() - 1;
        broken[last] ^= 1;
        let broken = String::from_utf8(broken).unwrap();
        assert!(NostrSecret::from_nsec(&broken).is_err());
        assert!(NostrSecret::from_nsec(&nsec.replacen("nsec", "npub", 1)).is_err());
        let bech32m =
            bech32::encode::<bech32::Bech32m>(Hrp::parse("nsec").unwrap(), &[1_u8; 32]).unwrap();
        assert!(NostrSecret::from_nsec(&bech32m).is_err());
        assert!(NostrSecret::from_bytes([0_u8; 32]).is_err());
    }

    #[test]
    fn schnorr_signature_verifies_and_rejects_a_tampered_message() {
        let secret = NostrSecret::from_nsec(
            "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
        )
        .unwrap();
        let signature = secret.sign(b"omachat-bind").unwrap();
        verify_nostr(&secret.public_key(), b"omachat-bind", &signature).unwrap();
        assert!(verify_nostr(&secret.public_key(), b"omachat-bind!", &signature).is_err());
        let mut forged = signature;
        forged[63] ^= 1;
        assert!(verify_nostr(&secret.public_key(), b"omachat-bind", &forged).is_err());
    }
}
