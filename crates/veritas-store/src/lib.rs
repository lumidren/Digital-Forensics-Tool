//! Content-addressed evidence store.
//!
//! Objects are addressed by the SHA-256 of their plaintext. The local backend writes to a
//! temporary file, fsyncs, renames into place, and clears the writable bit. An attempt to store a
//! second object at an existing address is answered with the existing object after a byte-level
//! comparison of the hash, so a committed object is never rewritten (WORM semantics).
//!
//! The S3 backend used in the cluster profile lives in the Python API layer
//! (`python/veritas/store/s3.py`) and requires Object Lock in compliance mode on the bucket.
#![forbid(unsafe_code)]

pub mod crypto;

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use veritas_hash::{Hashes, MultiHasher};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("object {0} not found")]
    NotFound(String),
    #[error("object {address} is corrupt: stored hash {stored} differs from recomputed {actual}")]
    Corrupt {
        address: String,
        stored: String,
        actual: String,
    },
    #[error("refusing to overwrite committed object {0}")]
    WriteOnce(String),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Metadata kept beside every object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub address: String,
    pub hashes: Hashes,
    pub case_id: String,
    pub encrypted: bool,
    pub original_name: Option<String>,
    pub content_type: Option<String>,
}

pub trait ContentStore {
    /// Store the bytes of `reader`; returns metadata including the address.
    fn put(
        &self,
        case_id: &str,
        reader: &mut dyn Read,
        original_name: Option<&str>,
    ) -> Result<ObjectMeta, StoreError>;
    /// Open an object for reading (plaintext).
    fn get(&self, address: &str) -> Result<Box<dyn Read>, StoreError>;
    fn meta(&self, address: &str) -> Result<ObjectMeta, StoreError>;
    fn exists(&self, address: &str) -> bool;
    fn list(&self) -> Result<Vec<String>, StoreError>;
}

/// Filesystem store with optional per-case encryption. THREAT:T1.2
pub struct LocalStore {
    root: PathBuf,
    keyring: Option<crypto::CaseKeyring>,
}

impl LocalStore {
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("meta"))?;
        fs::create_dir_all(root.join("tmp"))?;
        Ok(Self {
            root: root.to_path_buf(),
            keyring: None,
        })
    }

    /// Enable encryption at rest with a keyring that derives one key per case. THREAT:T4.1
    pub fn with_keyring(mut self, keyring: crypto::CaseKeyring) -> Self {
        self.keyring = Some(keyring);
        self
    }

    fn object_path(&self, address: &str) -> PathBuf {
        self.root
            .join("objects")
            .join(&address[..2])
            .join(&address[2..4])
            .join(address)
    }

    fn meta_path(&self, address: &str) -> PathBuf {
        self.root.join("meta").join(format!("{}.json", address))
    }

    fn set_readonly(path: &Path) -> io::Result<()> {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(path, perms)
    }

    /// Re-hash every stored object and compare with its metadata. THREAT:T1.5
    pub fn verify_all(&self) -> Result<Vec<Result<String, StoreError>>, StoreError> {
        let mut out = Vec::new();
        for address in self.list()? {
            let meta = self.meta(&address)?;
            let mut reader = self.get(&address)?;
            let mut h = MultiHasher::new();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            let actual = h.finalize();
            if actual == meta.hashes {
                out.push(Ok(address));
            } else {
                out.push(Err(StoreError::Corrupt {
                    address,
                    stored: meta.hashes.sha256,
                    actual: actual.sha256,
                }));
            }
        }
        Ok(out)
    }
}

impl ContentStore for LocalStore {
    fn put(
        &self,
        case_id: &str,
        reader: &mut dyn Read,
        original_name: Option<&str>,
    ) -> Result<ObjectMeta, StoreError> {
        // Stream to a temp file while hashing the plaintext; encrypt per 1 MiB frame if enabled.
        let tmp =
            self.root
                .join("tmp")
                .join(format!("{}-{}", std::process::id(), rand::random::<u64>()));
        let mut hasher = MultiHasher::new();
        let encryptor = match &self.keyring {
            Some(k) => Some(k.encryptor(case_id)?),
            None => None,
        };
        {
            let mut w = BufWriter::new(File::create(&tmp)?);
            let mut buf = vec![0u8; crypto::FRAME_SIZE];
            let mut frame_index: u64 = 0;
            loop {
                let n = read_full(reader, &mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                match &encryptor {
                    Some(enc) => {
                        let ct = enc.encrypt_frame(frame_index, &buf[..n])?;
                        w.write_all(&(ct.len() as u32).to_le_bytes())?;
                        w.write_all(&ct)?;
                    }
                    None => w.write_all(&buf[..n])?,
                }
                frame_index += 1;
                if n < buf.len() {
                    break;
                }
            }
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        let hashes = hasher.finalize();
        let address = hashes.sha256.clone();
        let final_path = self.object_path(&address);
        if final_path.exists() {
            // THREAT:T1.3 write-once: identical content already committed; discard the new copy.
            let _ = fs::remove_file(&tmp);
            let existing = self.meta(&address)?;
            if existing.hashes != hashes {
                return Err(StoreError::WriteOnce(address));
            }
            return Ok(existing);
        }
        fs::create_dir_all(final_path.parent().expect("object path has parent"))?;
        fs::rename(&tmp, &final_path)?;
        Self::set_readonly(&final_path)?;
        let meta = ObjectMeta {
            address: address.clone(),
            hashes,
            case_id: case_id.to_string(),
            encrypted: encryptor.is_some(),
            original_name: original_name.map(str::to_string),
            content_type: None,
        };
        let meta_path = self.meta_path(&address);
        let mut mf = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&meta_path)?;
        mf.write_all(serde_json::to_string_pretty(&meta)?.as_bytes())?;
        mf.sync_all()?;
        Self::set_readonly(&meta_path)?;
        Ok(meta)
    }

    fn get(&self, address: &str) -> Result<Box<dyn Read>, StoreError> {
        let meta = self.meta(address)?;
        let file = File::open(self.object_path(address))
            .map_err(|_| StoreError::NotFound(address.to_string()))?;
        if meta.encrypted {
            let keyring = self
                .keyring
                .as_ref()
                .ok_or(crypto::CryptoError::NoKeyring)?;
            let dec = keyring.encryptor(&meta.case_id)?;
            Ok(Box::new(crypto::DecryptingReader::new(
                BufReader::new(file),
                dec,
            )))
        } else {
            Ok(Box::new(BufReader::new(file)))
        }
    }

    fn meta(&self, address: &str) -> Result<ObjectMeta, StoreError> {
        let text = fs::read_to_string(self.meta_path(address))
            .map_err(|_| StoreError::NotFound(address.to_string()))?;
        Ok(serde_json::from_str(&text)?)
    }

    fn exists(&self, address: &str) -> bool {
        address.len() == 64 && self.object_path(address).exists()
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("meta"))? {
            let name = entry?.file_name().to_string_lossy().to_string();
            if let Some(addr) = name.strip_suffix(".json") {
                out.push(addr.to_string());
            }
        }
        out.sort();
        Ok(out)
    }
}

fn read_full(reader: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(mut r: Box<dyn Read>) -> Vec<u8> {
        let mut v = Vec::new();
        r.read_to_end(&mut v).unwrap();
        v
    }

    #[test]
    fn put_get_roundtrip_plain() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::open(dir.path()).unwrap();
        let data = b"hello evidence".to_vec();
        let meta = store
            .put("CASE-1", &mut &data[..], Some("hello.txt"))
            .unwrap();
        assert_eq!(meta.address, veritas_hash::hash_bytes(&data).sha256);
        assert!(store.exists(&meta.address));
        assert_eq!(read_all(store.get(&meta.address).unwrap()), data);
        assert_eq!(store.list().unwrap(), vec![meta.address.clone()]);
        assert!(store.verify_all().unwrap().iter().all(|r| r.is_ok()));
    }

    #[test]
    fn committed_objects_are_readonly_and_never_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::open(dir.path()).unwrap();
        let data = b"immutable".to_vec();
        let meta = store.put("CASE-1", &mut &data[..], None).unwrap();
        let path = store.object_path(&meta.address);
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        // Second put of identical content returns the same metadata and keeps one copy.
        let again = store.put("CASE-2", &mut &data[..], None).unwrap();
        assert_eq!(again.case_id, "CASE-1");
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn encrypted_roundtrip_and_cross_case_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let master = crypto::MasterKey::generate();
        let store = LocalStore::open(dir.path())
            .unwrap()
            .with_keyring(crypto::CaseKeyring::new(master.clone()));
        let data: Vec<u8> = (0..(3 * crypto::FRAME_SIZE + 123))
            .map(|i| (i % 253) as u8)
            .collect();
        let meta = store.put("CASE-A", &mut &data[..], None).unwrap();
        assert!(meta.encrypted);
        let on_disk = fs::read(store.object_path(&meta.address)).unwrap();
        assert!(!on_disk.windows(64).any(|w| w == &data[..64]));
        assert_eq!(read_all(store.get(&meta.address).unwrap()), data);
        assert!(store.verify_all().unwrap().iter().all(|r| r.is_ok()));

        // Corrupt the metadata to claim another case: decryption must fail, not leak.
        let mp = store.meta_path(&meta.address);
        let mut perms = fs::metadata(&mp).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        // test fixture: temp file, make it writable to tamper with it
        perms.set_readonly(false);
        fs::set_permissions(&mp, perms).unwrap();
        let mut m = store.meta(&meta.address).unwrap();
        m.case_id = "CASE-B".into();
        fs::write(&mp, serde_json::to_string(&m).unwrap()).unwrap();
        let mut r = store.get(&meta.address).unwrap();
        let mut sink = Vec::new();
        assert!(r.read_to_end(&mut sink).is_err());
    }

    #[test]
    fn tampered_object_detected_by_verify_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalStore::open(dir.path()).unwrap();
        let meta = store.put("CASE-1", &mut &b"original"[..], None).unwrap();
        let path = store.object_path(&meta.address);
        let mut perms = fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        // test fixture: temp file, make it writable to tamper with it
        perms.set_readonly(false);
        fs::set_permissions(&path, perms).unwrap();
        fs::write(&path, b"altered!").unwrap();
        let results = store.verify_all().unwrap();
        assert!(matches!(results[0], Err(StoreError::Corrupt { .. })));
    }
}
