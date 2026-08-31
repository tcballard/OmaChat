//! NIP-42 client authentication using the participating Nostr principal.

use crate::event::{EventError, EventLimits, SignedEvent, UnsignedEvent, xonly_public_key};
use std::{error::Error, fmt};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NIP42_AUTH_KIND: u32 = 22_242;

/// A relay-authentication signer for one Nostr principal.
///
/// This owns only the Nostr secret used for event authorship. Account-root and
/// recovery keys intentionally cannot be supplied through this API.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RelayAuthSigner {
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

impl RelayAuthSigner {
    pub fn from_secret_key(secret_key: [u8; 32]) -> Result<Self, AuthError> {
        let public_key = xonly_public_key(&secret_key).map_err(AuthError::Event)?;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn sign_challenge(
        &self,
        relay_url: &str,
        challenge: &str,
        created_at: u64,
        limits: &EventLimits,
    ) -> Result<SignedEvent, AuthError> {
        if challenge.is_empty() {
            return Err(AuthError::EmptyChallenge);
        }
        let mut auxiliary_randomness = [0_u8; 32];
        getrandom::fill(&mut auxiliary_randomness).map_err(|_| AuthError::Random)?;
        UnsignedEvent::new(
            hex::encode(self.public_key),
            created_at,
            NIP42_AUTH_KIND,
            vec![
                vec!["relay".into(), relay_url.into()],
                vec!["challenge".into(), challenge.into()],
            ],
            String::new(),
            limits,
        )
        .map_err(AuthError::Event)?
        .sign_with_aux(&self.secret_key, &auxiliary_randomness, limits)
        .map_err(AuthError::Event)
    }
}

impl fmt::Debug for RelayAuthSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAuthSigner")
            .field("public_key", &hex::encode(self.public_key))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub enum AuthError {
    EmptyChallenge,
    Random,
    Event(EventError),
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChallenge => formatter.write_str("relay authentication challenge is empty"),
            Self::Random => formatter.write_str("relay authentication randomness failed"),
            Self::Event(error) => write!(formatter, "invalid relay authentication event: {error}"),
        }
    }
}

impl Error for AuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::EmptyChallenge | Self::Random => None,
        }
    }
}
