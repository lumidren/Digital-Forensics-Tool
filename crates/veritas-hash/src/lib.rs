//! Single-pass multi-digest hashing.
//!
//! Evidence is hashed with three independent algorithms in one streaming pass so that bytes are
//! read exactly once from a possibly fragile source device. All three digests are recorded in the
//! custody ledger; an adversary would have to produce a simultaneous collision in MD5, SHA-256 and
//! SHA3-256 to substitute content.
#![forbid(unsafe_code)]

use digest::Digest;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

/// Lower-case hexadecimal digests of one byte stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha256: String,
    pub sha3_256: String,
    /// Number of bytes hashed.
    pub length: u64,
}

/// Streaming hasher that updates MD5, SHA-256 and SHA3-256 together. THREAT:T1.1
pub struct MultiHasher {
    md5: md5::Md5,
    sha256: sha2::Sha256,
    sha3: sha3::Sha3_256,
    length: u64,
}

impl Default for MultiHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiHasher {
    pub fn new() -> Self {
        Self {
            md5: md5::Md5::new(),
            sha256: sha2::Sha256::new(),
            sha3: sha3::Sha3_256::new(),
            length: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.sha256.update(data);
        self.sha3.update(data);
        self.length += data.len() as u64;
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn finalize(self) -> Hashes {
        Hashes {
            md5: hex::encode(self.md5.finalize()),
            sha256: hex::encode(self.sha256.finalize()),
            sha3_256: hex::encode(self.sha3.finalize()),
            length: self.length,
        }
    }
}

/// Hash an in-memory buffer.
pub fn hash_bytes(data: &[u8]) -> Hashes {
    let mut h = MultiHasher::new();
    h.update(data);
    h.finalize()
}

/// Hash a reader in chunks, invoking `progress` with the cumulative byte count after each chunk.
/// The chunk size is 4 MiB, which keeps sequential device reads large without holding much memory.
pub fn hash_reader<R: Read, F: FnMut(u64)>(mut reader: R, mut progress: F) -> io::Result<Hashes> {
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut h = MultiHasher::new();
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        progress(h.length());
    }
    Ok(h.finalize())
}

/// SHA-256 only, for content addressing and chain hashing.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_input_known_vectors() {
        let h = hash_bytes(b"");
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            h.sha3_256,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(h.length, 0);
    }

    #[test]
    fn abc_known_vectors() {
        let h = hash_bytes(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            h.sha3_256,
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(h.length, 3);
    }

    #[test]
    fn reader_matches_bytes_across_chunk_boundaries() {
        let data: Vec<u8> = (0..(9 * 1024 * 1024 + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        let mut calls = 0;
        let streamed = hash_reader(&data[..], |_| calls += 1).unwrap();
        assert_eq!(streamed, hash_bytes(&data));
        assert_eq!(calls, 3);
    }

    proptest! {
        #[test]
        fn split_updates_equal_single_update(data in proptest::collection::vec(any::<u8>(), 0..4096), split in 0usize..4096) {
            let split = split.min(data.len());
            let mut h = MultiHasher::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            prop_assert_eq!(h.finalize(), hash_bytes(&data));
        }
    }
}
