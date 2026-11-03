//! External anchoring of the chain head.
//!
//! The default anchor sink is an append-only text file kept on separate storage (a different
//! host, a WORM bucket, or printed). Each line records a sequence number and the entry hash at
//! that point. A verifier cross-checks anchors against the chain; a ledger that was rewritten
//! after an anchor cannot reproduce the anchored hash. THREAT:T2.6
#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRecord {
    pub ledger_id: String,
    pub seq: u64,
    pub head_hash: String,
    pub anchored_at: DateTime<Utc>,
    /// e.g. "file", "rfc3161:tsa.example", "transparency-log:..."
    pub sink: String,
    /// Opaque receipt from the sink (TSA token, log index), if any.
    pub receipt: Option<String>,
}

pub fn append_anchor(path: &Path, record: &AnchorRecord) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(serde_json::to_string(record)?.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()
}

pub fn load_anchors(path: &Path) -> std::io::Result<Vec<AnchorRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}
