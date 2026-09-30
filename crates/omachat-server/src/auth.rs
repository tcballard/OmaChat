//! Device-key authentication and server identity.
//!
//! The client proves control of an Ed25519 device key by signing a transcript
//! that binds the server's public key, a fresh server challenge and the
//! device key. The server proves its identity by signing the challenge with
//! its own key, so clients can pin the server independently of TLS.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rustix::fs::{Mode, OFlags, open};
use std::{
    error::Error,
    fmt,
    fs::File,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const AUTH_DOMAIN: &[u8] = b"omachat-server-auth-v1\0";
pub const HELLO_DOMAIN: &[u8] = b"omachat-server-hello-v1\0";
pub const KEY_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;

pub struct ServerIdentity {
    signing_key: SigningKey,
}

impl ServerIdentity {
    #[must_use]
    pub fn from_seed(seed: &[u8; KEY_BYTES]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; KEY_BYTES] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign the hello transcript so the client can pin this server.
    #[must_use]
    pub fn sign_hello(
        &self,
        challenge: &[u8; KEY_BYTES],
        device_public_key: &[u8; KEY_BYTES],
    ) -> [u8; SIGNATURE_BYTES] {
        self.signing_key
            .sign(&hello_transcript(challenge, device_public_key))
            .to_bytes()
    }
}

#[must_use]
pub fn hello_transcript(
    challenge: &[u8; KEY_BYTES],
    device_public_key: &[u8; KEY_BYTES],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(HELLO_DOMAIN.len() + 2 * KEY_BYTES);
    transcript.extend_from_slice(HELLO_DOMAIN);
    transcript.extend_from_slice(challenge);
    transcript.extend_from_slice(device_public_key);
    transcript
}

#[must_use]
pub fn auth_transcript(
    server_public_key: &[u8; KEY_BYTES],
    challenge: &[u8; KEY_BYTES],
    device_public_key: &[u8; KEY_BYTES],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(AUTH_DOMAIN.len() + 3 * KEY_BYTES);
    transcript.extend_from_slice(AUTH_DOMAIN);
    transcript.extend_from_slice(server_public_key);
    transcript.extend_from_slice(challenge);
    transcript.extend_from_slice(device_public_key);
    transcript
}

pub fn verify_hello_signature(
    server_public_key: &[u8; KEY_BYTES],
    challenge: &[u8; KEY_BYTES],
    device_public_key: &[u8; KEY_BYTES],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), AuthError> {
    VerifyingKey::from_bytes(server_public_key)
        .map_err(|_| AuthError::InvalidPublicKey)?
        .verify_strict(
            &hello_transcript(challenge, device_public_key),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| AuthError::InvalidSignature)
}

pub fn verify_device_signature(
    server_public_key: &[u8; KEY_BYTES],
    challenge: &[u8; KEY_BYTES],
    device_public_key: &[u8; KEY_BYTES],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), AuthError> {
    VerifyingKey::from_bytes(device_public_key)
        .map_err(|_| AuthError::InvalidPublicKey)?
        .verify_strict(
            &auth_transcript(server_public_key, challenge, device_public_key),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| AuthError::InvalidSignature)
}

/// Client-side helper: sign the challenge transcript with a device seed.
#[must_use]
pub fn sign_device_challenge(
    device_seed: &[u8; KEY_BYTES],
    server_public_key: &[u8; KEY_BYTES],
    challenge: &[u8; KEY_BYTES],
) -> [u8; SIGNATURE_BYTES] {
    let signing_key = SigningKey::from_bytes(device_seed);
    let device_public_key = signing_key.verifying_key().to_bytes();
    signing_key
        .sign(&auth_transcript(
            server_public_key,
            challenge,
            &device_public_key,
        ))
        .to_bytes()
}

pub fn random_challenge() -> Result<[u8; KEY_BYTES], AuthError> {
    let mut challenge = [0_u8; KEY_BYTES];
    getrandom::fill(&mut challenge).map_err(|_| AuthError::Random)?;
    Ok(challenge)
}

pub fn decode_key(value: &str) -> Result<[u8; KEY_BYTES], AuthError> {
    let bytes = hex::decode(value).map_err(|_| AuthError::InvalidEncoding)?;
    bytes.try_into().map_err(|_| AuthError::InvalidEncoding)
}

pub fn decode_signature(value: &str) -> Result<[u8; SIGNATURE_BYTES], AuthError> {
    let bytes = hex::decode(value).map_err(|_| AuthError::InvalidEncoding)?;
    bytes.try_into().map_err(|_| AuthError::InvalidEncoding)
}

/// Read a 32-byte seed from an owner-only regular file holding 64 hex
/// characters and an optional trailing newline.
pub fn load_seed_file(path: &Path) -> Result<Zeroizing<[u8; KEY_BYTES]>, SeedError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| SeedError::Io {
        path: path.to_owned(),
        source: std::io::Error::from_raw_os_error(error.raw_os_error()),
    })?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|source| SeedError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(SeedError::NotRegular(path.to_owned()));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SeedError::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    if metadata.len() > 65 {
        return Err(SeedError::Encoding(path.to_owned()));
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(65));
    file.read_to_end(&mut encoded)
        .map_err(|source| SeedError::Io {
            path: path.to_owned(),
            source,
        })?;
    let encoded = encoded.strip_suffix(b"\n").unwrap_or(encoded.as_slice());
    if encoded.len() != 2 * KEY_BYTES || !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err(SeedError::Encoding(path.to_owned()));
    }
    let mut seed = Zeroizing::new([0_u8; KEY_BYTES]);
    hex::decode_to_slice(encoded, seed.as_mut_slice())
        .map_err(|_| SeedError::Encoding(path.to_owned()))?;
    Ok(seed)
}

/// Create a new owner-only seed file with 32 random bytes as hex. Refuses to
/// overwrite an existing file.
pub fn generate_seed_file(path: &Path) -> Result<(), SeedError> {
    let mut seed = Zeroizing::new([0_u8; KEY_BYTES]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| SeedError::Random)?;
    let descriptor = open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| SeedError::Io {
        path: path.to_owned(),
        source: std::io::Error::from_raw_os_error(error.raw_os_error()),
    })?;
    let mut file = File::from(descriptor);
    use std::io::Write;
    let encoded = Zeroizing::new(format!("{}\n", hex::encode(seed.as_slice())));
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| SeedError::Io {
            path: path.to_owned(),
            source,
        })
}

#[derive(Debug)]
pub enum AuthError {
    InvalidPublicKey,
    InvalidSignature,
    InvalidEncoding,
    Random,
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKey => "invalid Ed25519 public key",
            Self::InvalidSignature => "signature does not verify",
            Self::InvalidEncoding => "expected hex of the exact length",
            Self::Random => "operating system randomness unavailable",
        })
    }
}

impl Error for AuthError {}

#[derive(Debug)]
pub enum SeedError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    NotRegular(PathBuf),
    Permissions {
        path: PathBuf,
        mode: u32,
    },
    Encoding(PathBuf),
    Random,
}

impl fmt::Display for SeedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::NotRegular(path) => write!(formatter, "{} is not a regular file", path.display()),
            Self::Permissions { path, mode } => write!(
                formatter,
                "{} has mode {mode:o}; it must be readable by its owner only",
                path.display()
            ),
            Self::Encoding(path) => write!(
                formatter,
                "{} must hold exactly 64 hex characters",
                path.display()
            ),
            Self::Random => formatter.write_str("operating system randomness unavailable"),
        }
    }
}

impl Error for SeedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_signature_round_trips_and_binds_every_field() {
        let server = ServerIdentity::from_seed(&[7_u8; 32]);
        let device_seed = [9_u8; 32];
        let device_public = SigningKey::from_bytes(&device_seed)
            .verifying_key()
            .to_bytes();
        let challenge = random_challenge().unwrap();
        let signature = sign_device_challenge(&device_seed, &server.public_key(), &challenge);
        verify_device_signature(&server.public_key(), &challenge, &device_public, &signature)
            .unwrap();
        let other_challenge = random_challenge().unwrap();
        assert!(
            verify_device_signature(
                &server.public_key(),
                &other_challenge,
                &device_public,
                &signature
            )
            .is_err()
        );
        let other_server = ServerIdentity::from_seed(&[8_u8; 32]);
        assert!(
            verify_device_signature(
                &other_server.public_key(),
                &challenge,
                &device_public,
                &signature
            )
            .is_err()
        );
        let hello = server.sign_hello(&challenge, &device_public);
        verify_hello_signature(&server.public_key(), &challenge, &device_public, &hello).unwrap();
    }

    #[test]
    fn seed_files_require_owner_only_mode_and_exact_hex() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("seed");
        generate_seed_file(&path).unwrap();
        assert!(generate_seed_file(&path).is_err(), "must not overwrite");
        let seed = load_seed_file(&path).unwrap();
        assert_ne!(*seed, [0_u8; 32]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_seed_file(&path),
            Err(SeedError::Permissions { .. })
        ));
        let short = directory.path().join("short");
        std::fs::write(&short, "abcd\n").unwrap();
        std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_seed_file(&short),
            Err(SeedError::Encoding(_))
        ));
    }
}
