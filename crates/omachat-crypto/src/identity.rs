use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};
/// The existing signing_seed is retained when loading a pre-retirement identity.
/// Serde ignores the retired roots; newly persisted identities contain only this key.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecrets {
    signing_seed: [u8; 32],
}
impl IdentitySecrets {
    pub fn generate() -> Result<Self, IdentityError> {
        let mut signing_seed = [0; 32];
        getrandom::fill(&mut signing_seed).map_err(|_| IdentityError)?;
        Ok(Self { signing_seed })
    }
    pub fn from_signing_seed(signing_seed: [u8; 32]) -> Self {
        Self { signing_seed }
    }
    pub fn public_identity(&self) -> PublicIdentity {
        let signing_public_key = SigningKey::from_bytes(&self.signing_seed)
            .verifying_key()
            .to_bytes();
        PublicIdentity {
            signing_public_key,
            fingerprint_hex: hex::encode(Sha256::digest(signing_public_key)),
        }
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.signing_seed)
            .sign(message)
            .to_bytes()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicIdentity {
    pub signing_public_key: [u8; 32],
    pub fingerprint_hex: String,
}
#[derive(Debug)]
pub struct IdentityError;
impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("identity generation failed")
    }
}
impl std::error::Error for IdentityError {}
