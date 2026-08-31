//! Noise XX handshake and stateless replay-window transport.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";
const X_PROTOCOL_NAME: &[u8] = b"Noise_X_25519_ChaChaPoly_SHA256";
pub const INITIATOR_TIMEOUT_MS: u64 = 10_000;
pub const RESPONDER_TIMEOUT_MS: u64 = 20_000;
pub const RECOVERY_DELAY_MS: u64 = 200;
pub const REPLAY_WINDOW: u32 = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Initiator,
    Responder,
}

pub struct Handshake {
    role: Role,
    static_secret: Zeroizing<[u8; 32]>,
    ephemeral_secret: Zeroizing<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
    remote_ephemeral: Option<[u8; 32]>,
    symmetric: Symmetric,
    step: u8,
    split: Option<([u8; 32], [u8; 32])>,
}

impl Handshake {
    #[must_use]
    pub fn new(
        role: Role,
        static_secret: [u8; 32],
        ephemeral_secret: [u8; 32],
        prologue: &[u8],
    ) -> Self {
        let mut symmetric = Symmetric::new();
        symmetric.mix_hash(prologue);
        Self {
            role,
            static_secret: Zeroizing::new(static_secret),
            ephemeral_secret: Zeroizing::new(ephemeral_secret),
            remote_static: None,
            remote_ephemeral: None,
            symmetric,
            step: 0,
            split: None,
        }
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match (self.role, self.step) {
            (Role::Initiator, 0) => {
                let public = public(&self.ephemeral_secret);
                self.symmetric.mix_hash(&public);
                let mut message = public.to_vec();
                message.extend(self.symmetric.encrypt_and_hash(payload)?);
                self.step = 1;
                Ok(message)
            }
            (Role::Responder, 1) => {
                let remote_e = self.remote_ephemeral.ok_or(NoiseError::State)?;
                let public_e = public(&self.ephemeral_secret);
                self.symmetric.mix_hash(&public_e);
                let mut message = public_e.to_vec();
                self.symmetric
                    .mix_key(&x25519(*self.ephemeral_secret, remote_e));
                let public_s = public(&self.static_secret);
                message.extend(self.symmetric.encrypt_and_hash(&public_s)?);
                self.symmetric
                    .mix_key(&x25519(*self.static_secret, remote_e));
                message.extend(self.symmetric.encrypt_and_hash(payload)?);
                self.step = 2;
                Ok(message)
            }
            (Role::Initiator, 2) => {
                let remote_e = self.remote_ephemeral.ok_or(NoiseError::State)?;
                let public_s = public(&self.static_secret);
                let mut message = self.symmetric.encrypt_and_hash(&public_s)?;
                self.symmetric
                    .mix_key(&x25519(*self.static_secret, remote_e));
                message.extend(self.symmetric.encrypt_and_hash(payload)?);
                self.split = Some(self.symmetric.split());
                self.step = 3;
                Ok(message)
            }
            _ => Err(NoiseError::State),
        }
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match (self.role, self.step) {
            (Role::Responder, 0) => {
                let (remote_e, payload) = split_at(message, 32)?;
                self.remote_ephemeral = Some(remote_e.try_into().expect("fixed ephemeral"));
                self.symmetric.mix_hash(remote_e);
                let plaintext = self.symmetric.decrypt_and_hash(payload)?;
                self.step = 1;
                Ok(plaintext)
            }
            (Role::Initiator, 1) => {
                let (remote_e, rest) = split_at(message, 32)?;
                let remote_e: [u8; 32] = remote_e.try_into().expect("fixed ephemeral");
                self.remote_ephemeral = Some(remote_e);
                self.symmetric.mix_hash(&remote_e);
                self.symmetric
                    .mix_key(&x25519(*self.ephemeral_secret, remote_e));
                let (encrypted_static, payload) = split_at(rest, 48)?;
                let remote_s: [u8; 32] = self
                    .symmetric
                    .decrypt_and_hash(encrypted_static)?
                    .try_into()
                    .map_err(|_| NoiseError::Message)?;
                self.remote_static = Some(remote_s);
                self.symmetric
                    .mix_key(&x25519(*self.ephemeral_secret, remote_s));
                let plaintext = self.symmetric.decrypt_and_hash(payload)?;
                self.step = 2;
                Ok(plaintext)
            }
            (Role::Responder, 2) => {
                let (encrypted_static, payload) = split_at(message, 48)?;
                let remote_s: [u8; 32] = self
                    .symmetric
                    .decrypt_and_hash(encrypted_static)?
                    .try_into()
                    .map_err(|_| NoiseError::Message)?;
                self.remote_static = Some(remote_s);
                self.symmetric
                    .mix_key(&x25519(*self.ephemeral_secret, remote_s));
                let plaintext = self.symmetric.decrypt_and_hash(payload)?;
                self.split = Some(self.symmetric.split());
                self.step = 3;
                Ok(plaintext)
            }
            _ => Err(NoiseError::State),
        }
    }

    #[must_use]
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.symmetric.hash
    }
    #[must_use]
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.remote_static
    }

    pub fn into_transport(self) -> Result<RawTransport, NoiseError> {
        let (first, second) = self.split.ok_or(NoiseError::State)?;
        Ok(match self.role {
            Role::Initiator => RawTransport::new(first, second),
            Role::Responder => RawTransport::new(second, first),
        })
    }
}

struct Symmetric {
    chaining_key: [u8; 32],
    hash: [u8; 32],
    key: Option<Zeroizing<[u8; 32]>>,
    nonce: u64,
}
impl Symmetric {
    fn new() -> Self {
        Self::new_with_name(PROTOCOL_NAME)
    }

    fn new_with_name(protocol_name: &[u8]) -> Self {
        let mut hash = [0_u8; 32];
        hash[..protocol_name.len()].copy_from_slice(protocol_name);
        Self {
            chaining_key: hash,
            hash,
            key: None,
            nonce: 0,
        }
    }
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().into();
    }
    fn mix_key(&mut self, input: &[u8]) {
        let outputs = hkdf(&self.chaining_key, input);
        self.chaining_key = outputs.0;
        self.key = Some(Zeroizing::new(outputs.1));
        self.nonce = 0;
    }
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = if let Some(key) = &self.key {
            let result = cipher(key, self.nonce, &self.hash, plaintext, true)?;
            self.nonce += 1;
            result
        } else {
            plaintext.to_vec()
        };
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = if let Some(key) = &self.key {
            let result = cipher(key, self.nonce, &self.hash, ciphertext, false)?;
            self.nonce += 1;
            result
        } else {
            ciphertext.to_vec()
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }
    fn split(&self) -> ([u8; 32], [u8; 32]) {
        hkdf(&self.chaining_key, &[])
    }
}

pub struct RawTransport {
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_nonce: u64,
    recv_nonce: u64,
}
impl RawTransport {
    fn new(send: [u8; 32], recv: [u8; 32]) -> Self {
        Self {
            send_key: Zeroizing::new(send),
            recv_key: Zeroizing::new(recv),
            send_nonce: 0,
            recv_nonce: 0,
        }
    }
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let output = cipher(&self.send_key, self.send_nonce, &[], plaintext, true)?;
        self.send_nonce = self
            .send_nonce
            .checked_add(1)
            .ok_or(NoiseError::CounterExhausted)?;
        Ok(output)
    }
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let output = cipher(&self.recv_key, self.recv_nonce, &[], ciphertext, false)?;
        self.recv_nonce = self
            .recv_nonce
            .checked_add(1)
            .ok_or(NoiseError::CounterExhausted)?;
        Ok(output)
    }
    #[must_use]
    pub fn counters(&self) -> (u64, u64) {
        (self.send_nonce, self.recv_nonce)
    }
    pub fn into_framed(self) -> FramedTransport {
        FramedTransport::new(*self.send_key, *self.recv_key)
    }
}

pub struct FramedTransport {
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_counter: u64,
    replay: ReplayWindow,
}
impl FramedTransport {
    #[must_use]
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_key: Zeroizing::new(send_key),
            recv_key: Zeroizing::new(recv_key),
            send_counter: 0,
            replay: ReplayWindow::default(),
        }
    }
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let counter = u32::try_from(self.send_counter).map_err(|_| NoiseError::CounterExhausted)?;
        let mut output = counter.to_be_bytes().to_vec();
        output.extend(cipher(
            &self.send_key,
            u64::from(counter),
            &[],
            plaintext,
            true,
        )?);
        self.send_counter += 1;
        Ok(output)
    }
    pub fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let (counter, ciphertext) = split_at(frame, 4)?;
        let counter = u32::from_be_bytes(counter.try_into().expect("fixed counter"));
        self.replay.check(counter)?;
        let plaintext = cipher(&self.recv_key, u64::from(counter), &[], ciphertext, false)?;
        self.replay.commit(counter);
        Ok(plaintext)
    }
    pub fn rekey(&mut self, send_key: [u8; 32], recv_key: [u8; 32]) {
        self.send_key = Zeroizing::new(send_key);
        self.recv_key = Zeroizing::new(recv_key);
        self.send_counter = 0;
        self.replay = ReplayWindow::default();
    }
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u32>,
    bits: [u64; 16],
}
impl ReplayWindow {
    fn check(&self, counter: u32) -> Result<(), NoiseError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if counter > highest {
            return Ok(());
        }
        let behind = highest - counter;
        if behind >= REPLAY_WINDOW {
            return Err(NoiseError::Stale);
        }
        if self.bits[behind as usize / 64] & (1_u64 << (behind % 64)) != 0 {
            return Err(NoiseError::Replay);
        }
        Ok(())
    }
    fn commit(&mut self, counter: u32) {
        match self.highest {
            None => {
                self.highest = Some(counter);
                self.bits[0] = 1;
            }
            Some(highest) if counter > highest => {
                let shift = (counter - highest) as usize;
                if shift >= REPLAY_WINDOW as usize {
                    self.bits = [0; 16];
                } else {
                    shift_bitmap(&mut self.bits, shift);
                }
                self.highest = Some(counter);
                self.bits[0] |= 1;
            }
            Some(highest) => {
                let behind = (highest - counter) as usize;
                self.bits[behind / 64] |= 1_u64 << (behind % 64);
            }
        }
    }
}

fn shift_bitmap(bits: &mut [u64; 16], shift: usize) {
    let words = shift / 64;
    let remainder = shift % 64;
    let old = *bits;
    *bits = [0; 16];
    for (index, value) in old.into_iter().enumerate() {
        let target = index + words;
        if target < 16 {
            bits[target] |= value << remainder;
        }
        if remainder != 0 && target + 1 < 16 {
            bits[target + 1] |= value >> (64 - remainder);
        }
    }
}

#[must_use]
pub fn crossed_initiation_role(local_peer_id: &[u8], remote_peer_id: &[u8]) -> Role {
    if local_peer_id < remote_peer_id {
        Role::Initiator
    } else {
        Role::Responder
    }
}

/// Seal a one-way Noise X message. The responder static public key is a
/// pre-message and the sender static key is authenticated inside ciphertext.
pub fn seal_x(
    sender_static_secret: &[u8; 32],
    recipient_static_public: &[u8; 32],
    ephemeral_secret: &[u8; 32],
    prologue: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let mut symmetric = Symmetric::new_with_name(X_PROTOCOL_NAME);
    symmetric.mix_hash(prologue);
    symmetric.mix_hash(recipient_static_public);
    let ephemeral_public = public(ephemeral_secret);
    symmetric.mix_hash(&ephemeral_public);
    let mut message = ephemeral_public.to_vec();
    symmetric.mix_key(&x25519(*ephemeral_secret, *recipient_static_public));
    let sender_public = public(sender_static_secret);
    message.extend(symmetric.encrypt_and_hash(&sender_public)?);
    symmetric.mix_key(&x25519(*sender_static_secret, *recipient_static_public));
    message.extend(symmetric.encrypt_and_hash(payload)?);
    Ok(message)
}

/// Open a one-way Noise X message and return its authenticated sender static.
pub fn open_x(
    recipient_static_secret: &[u8; 32],
    prologue: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), NoiseError> {
    let recipient_public = public(recipient_static_secret);
    let mut symmetric = Symmetric::new_with_name(X_PROTOCOL_NAME);
    symmetric.mix_hash(prologue);
    symmetric.mix_hash(&recipient_public);
    let (ephemeral_public, rest) = split_at(message, 32)?;
    let ephemeral_public: [u8; 32] = ephemeral_public.try_into().expect("fixed ephemeral");
    symmetric.mix_hash(&ephemeral_public);
    symmetric.mix_key(&x25519(*recipient_static_secret, ephemeral_public));
    let (encrypted_static, encrypted_payload) = split_at(rest, 48)?;
    let sender_public: [u8; 32] = symmetric
        .decrypt_and_hash(encrypted_static)?
        .try_into()
        .map_err(|_| NoiseError::Message)?;
    symmetric.mix_key(&x25519(*recipient_static_secret, sender_public));
    Ok((
        symmetric.decrypt_and_hash(encrypted_payload)?,
        sender_public,
    ))
}

fn public(secret: &[u8; 32]) -> [u8; 32] {
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

fn hkdf(chaining_key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut extract = <Hmac<Sha256> as Mac>::new_from_slice(chaining_key).expect("HMAC key");
    extract.update(input);
    let temporary = extract.finalize().into_bytes();
    let mut first = <Hmac<Sha256> as Mac>::new_from_slice(&temporary).expect("HMAC key");
    first.update(&[1]);
    let first: [u8; 32] = first.finalize().into_bytes().into();
    let mut second = <Hmac<Sha256> as Mac>::new_from_slice(&temporary).expect("HMAC key");
    second.update(&first);
    second.update(&[2]);
    (first, second.finalize().into_bytes().into())
}

fn cipher(
    key: &[u8; 32],
    counter: u64,
    aad: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, NoiseError> {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let payload = Payload { msg: input, aad };
    if encrypt {
        cipher.encrypt(&Nonce::from(nonce), payload)
    } else {
        cipher.decrypt(&Nonce::from(nonce), payload)
    }
    .map_err(|_| NoiseError::Authentication)
}

fn split_at(bytes: &[u8], position: usize) -> Result<(&[u8], &[u8]), NoiseError> {
    if bytes.len() < position {
        Err(NoiseError::Message)
    } else {
        Ok(bytes.split_at(position))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoiseError {
    State,
    Message,
    Authentication,
    CounterExhausted,
    Replay,
    Stale,
}
impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Noise error: {self:?}")
    }
}
impl Error for NoiseError {}
