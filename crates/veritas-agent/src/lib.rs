//! Veritas acquisition agent.
//!
//! - [`triage`]: live-response collectors and a ZIP bundle writer with a hashed manifest.
//! - [`memory`]: WinPmem / LiME / osxpmem orchestration.
//! - [`image`]: physical or logical imaging to E01, AFF4 or split raw with bad-sector handling.
//! - [`writeblock`]: write-blocker verification before imaging.
//! - [`transfer`]: resumable mTLS upload of evidence segments.
//! - [`ledger_hook`]: signed custody-ledger entry for each acquisition, with SNTP time.
//!
//! Platform-specific behaviour is chosen at run time from `std::env::consts::OS`, so every code
//! path compiles and type-checks on every platform; no `unsafe` code is used.
#![forbid(unsafe_code)]

pub mod cmd;
pub mod image;
pub mod ledger_hook;
pub mod memory;
pub mod transfer;
pub mod triage;
pub mod writeblock;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ewf: {0}")]
    Ewf(#[from] veritas_ewf::EwfError),
    #[error("aff4: {0}")]
    Aff4(#[from] veritas_aff4::Aff4Error),
    #[error("ledger: {0}")]
    Ledger(#[from] veritas_ledger::LedgerError),
    #[error("key: {0}")]
    Key(#[from] veritas_ledger::keys::KeyError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("http: {0}")]
    Http(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("integrity: {0}")]
    Integrity(String),
    #[error("tool not found: {0}")]
    ToolNotFound(String),
    #[error("external tool failed: {0}")]
    ToolFailed(String),
    #[error("invalid argument: {0}")]
    Invalid(String),
    #[error("interrupted at byte {0}; state saved for resume")]
    Interrupted(u64),
}

pub type Result<T> = std::result::Result<T, AgentError>;

/// Agent name recorded in ledger tool info and EWF headers.
pub const AGENT_NAME: &str = "veritas-agent";
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// SHA-256 of a file, streamed.
pub fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::Digest;
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
