//! Examiner signing keys: generation, fingerprinting, and passphrase-protected storage.
#![forbid(unsafe_code)]

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("key file is malformed: {0}")]
    Malformed(String),
    #[error("wrong passphrase or corrupted key file")]
    Decrypt,
    #[error("key derivation failed")]
    Kdf,
}

/// Key id is the first 16 bytes of SHA-256 over the raw public key, hex encoded.
pub fn key_id(pk: &VerifyingKey) -> String {
    let digest = veritas_hash::sha256_hex(pk.as_bytes());
    digest[..32].to_string()
}

/// A private key held in memory. Never implements Serialize; see [`EncryptedKeyFile`].
pub struct ExaminerKey {
    signing: SigningKey,
}

impl fmt::Debug for ExaminerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // THREAT:T6.1 private material is never printed, even in debug output.
        write!(f, "ExaminerKey({})", self.key_id())
    }
}

impl ExaminerKey {
    pub fn generate() -> Self {
        Self { signing: SigningKey::generate(&mut OsRng) }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(secret) }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn key_id(&self) -> String {
        key_id(&self.verifying_key())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key().as_bytes())
    }

    /// Encrypt the secret with a passphrase (Argon2id + XChaCha20-Poly1305) and write it.
    pub fn save_encrypted(&self, path: &Path, passphrase: &str) -> Result<(), KeyError> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let kek = derive_kek(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new((&*kek).into());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), self.signing.to_bytes().as_slice())
            .map_err(|_| KeyError::Decrypt)?;
        let file = EncryptedKeyFile {
            version: 1,
            kdf: "argon2id-m65536-t3-p1".into(),
            cipher: "xchacha20poly1305".into(),
            key_id: self.key_id(),
            public_key: self.public_key_hex(),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        let json = serde_json::to_string_pretty(&file).map_err(|e| KeyError::Malformed(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_encrypted(path: &Path, passphrase: &str) -> Result<Self, KeyError> {
        let text = std::fs::read_to_string(path)?;
        let file: EncryptedKeyFile =
            serde_json::from_str(&text).map_err(|e| KeyError::Malformed(e.to_string()))?;
        if file.version != 1 {
            return Err(KeyError::Malformed(format!("unsupported version {}", file.version)));
        }
        let salt = hex::decode(&file.salt).map_err(|e| KeyError::Malformed(e.to_string()))?;
        let nonce = hex::decode(&file.nonce).map_err(|e| KeyError::Malformed(e.to_string()))?;
        let ct = hex::decode(&file.ciphertext).map_err(|e| KeyError::Malformed(e.to_string()))?;
        let kek = derive_kek(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new((&*kek).into());
        let pt = Zeroizing::new(
            cipher.decrypt(XNonce::from_slice(&nonce), ct.as_slice()).map_err(|_| KeyError::Decrypt)?,
        );
        let secret: [u8; 32] = pt.as_slice().try_into().map_err(|_| KeyError::Decrypt)?;
        let key = Self::from_bytes(&secret);
        if key.key_id() != file.key_id {
            return Err(KeyError::Malformed("key id does not match public key".into()));
        }
        Ok(key)
    }
}

fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let params = argon2::Params::new(65536, 3, 1, Some(32)).map_err(|_| KeyError::Kdf)?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|_| KeyError::Kdf)?;
    Ok(out)
}

/// On-disk form of an encrypted key. Contains no secret material in the clear.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    pub version: u32,
    pub kdf: String,
    pub cipher: String,
    pub key_id: String,
    pub public_key: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypted_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.json");
        let k = ExaminerKey::generate();
        k.save_encrypted(&path, "correct horse").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&hex::encode(k.signing.to_bytes())));
        let loaded = ExaminerKey::load_encrypted(&path, "correct horse").unwrap();
        assert_eq!(loaded.key_id(), k.key_id());
        assert!(matches!(ExaminerKey::load_encrypted(&path, "wrong"), Err(KeyError::Decrypt)));
    }

    #[test]
    fn debug_never_leaks_secret() {
        let k = ExaminerKey::generate();
        let dbg = format!("{:?}", k);
        assert!(!dbg.contains(&hex::encode(k.signing.to_bytes())));
    }
}
