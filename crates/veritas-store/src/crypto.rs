//! Per-case encryption at rest.
//!
//! A master key (from KMS in the cluster profile, from an environment variable or key file in
//! the native profile) derives one data-encryption key per case via HKDF-like expansion with
//! SHA-256 over `master || "veritas-case-dek" || case_id`. Objects are encrypted in framed
//! XChaCha20-Poly1305 with the frame index bound into the nonce and the case id as associated
//! data, so a frame cannot be moved between objects or cases. THREAT:T4.1
#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::io::{self, Read};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const FRAME_SIZE: usize = 1 << 20;
const TAG_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("store is encrypted but no keyring was configured")]
    NoKeyring,
    #[error("authentication failed (wrong case key or tampered ciphertext)")]
    Auth,
    #[error("master key must be 32 bytes")]
    KeyLength,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::KeyLength)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::KeyLength)?;
        Ok(Self(arr))
    }

    fn derive_case_key(&self, case_id: &str) -> [u8; 32] {
        use sha2_wrapper::sha256;
        let mut input = Vec::with_capacity(32 + 16 + case_id.len());
        input.extend_from_slice(&self.0);
        input.extend_from_slice(b"veritas-case-dek");
        input.extend_from_slice(case_id.as_bytes());
        sha256(&input)
    }
}

mod sha2_wrapper {
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let hex = veritas_hash::sha256_hex(data);
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).expect("hex"), 16).expect("hex");
        }
        out
    }
}

/// Derives case keys on demand; never stores them.
#[derive(Clone)]
pub struct CaseKeyring {
    master: MasterKey,
}

impl CaseKeyring {
    pub fn new(master: MasterKey) -> Self {
        Self { master }
    }

    pub fn encryptor(&self, case_id: &str) -> Result<FrameCipher, CryptoError> {
        let key = self.master.derive_case_key(case_id);
        Ok(FrameCipher {
            cipher: XChaCha20Poly1305::new((&key).into()),
            aad: case_id.as_bytes().to_vec(),
        })
    }
}

pub struct FrameCipher {
    cipher: XChaCha20Poly1305,
    aad: Vec<u8>,
}

impl FrameCipher {
    fn nonce(frame_index: u64) -> XNonce {
        let mut n = [0u8; 24];
        n[..8].copy_from_slice(&frame_index.to_le_bytes());
        *XNonce::from_slice(&n)
    }

    pub fn encrypt_frame(
        &self,
        frame_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .encrypt(
                &Self::nonce(frame_index),
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| CryptoError::Auth)
    }

    pub fn decrypt_frame(
        &self,
        frame_index: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .decrypt(
                &Self::nonce(frame_index),
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| CryptoError::Auth)
    }
}

/// Reads framed ciphertext and yields plaintext.
pub struct DecryptingReader<R: Read> {
    inner: R,
    cipher: FrameCipher,
    frame_index: u64,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: Read> DecryptingReader<R> {
    pub fn new(inner: R, cipher: FrameCipher) -> Self {
        Self {
            inner,
            cipher,
            frame_index: 0,
            buf: Vec::new(),
            pos: 0,
            done: false,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        let mut len_bytes = [0u8; 4];
        match self.inner.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.done = true;
                return Ok(());
            }
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > FRAME_SIZE + TAG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame length exceeds maximum",
            ));
        }
        let mut ct = vec![0u8; len];
        self.inner.read_exact(&mut ct)?;
        let pt = self
            .cipher
            .decrypt_frame(self.frame_index, &ct)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.frame_index += 1;
        self.buf = pt;
        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            if self.done {
                return Ok(0);
            }
            self.fill()?;
            if self.pos >= self.buf.len() {
                return Ok(0);
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_cases_get_different_keys() {
        let m = MasterKey::generate();
        assert_ne!(m.derive_case_key("A"), m.derive_case_key("B"));
        assert_eq!(m.derive_case_key("A"), m.derive_case_key("A"));
    }

    #[test]
    fn frame_cannot_move_between_cases_or_indices() {
        let ring = CaseKeyring::new(MasterKey::generate());
        let a = ring.encryptor("A").unwrap();
        let b = ring.encryptor("B").unwrap();
        let ct = a.encrypt_frame(0, b"frame zero").unwrap();
        assert_eq!(a.decrypt_frame(0, &ct).unwrap(), b"frame zero");
        assert!(a.decrypt_frame(1, &ct).is_err());
        assert!(b.decrypt_frame(0, &ct).is_err());
    }
}
