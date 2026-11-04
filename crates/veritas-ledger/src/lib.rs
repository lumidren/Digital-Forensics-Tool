//! Chain-of-custody ledger.
//!
//! The ledger is an append-only sequence of [`Entry`] values. Each entry carries the SHA-256 of
//! the previous entry and an Ed25519 signature by the acting examiner over the canonical JSON of
//! the entry body. Verification needs only the entries, the key registry and the anchor list;
//! see [`verify`].
#![forbid(unsafe_code)]

pub mod anchor;
pub mod canonical;
pub mod keys;
pub mod verify;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer};
use keys::ExaminerKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use thiserror::Error;
use veritas_hash::Hashes;

pub const LEDGER_VERSION: u32 = 1;
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonical: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("ledger file is corrupt at line {line}: {reason}")]
    Corrupt { line: usize, reason: String },
}

/// What happened to the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// First entry of a ledger; carries the ledger id and the case id.
    Genesis,
    /// Evidence created by the agent (imaging, memory capture, triage bundle).
    Acquire,
    /// Evidence received and stored by the platform.
    Ingest,
    /// Evidence bytes read (by a parser, by an examiner, by an export).
    Access,
    /// Evidence or a derived object left the platform.
    Export,
    /// A derived object was produced (parsed output, report).
    Transform,
    /// A key was enrolled; the entry must be signed by an existing admin key.
    KeyEnrolled,
    /// A key was revoked; later entries by that key are invalid.
    KeyRevoked,
    /// Chain head anchored externally.
    Anchor,
    /// Free-text examiner note tied to the chain.
    Note,
}

/// Where time came from, so that a court can weigh the timestamp. THREAT:T2.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSource {
    /// e.g. "ntp:time.nist.gov", "gps", "manual", "system-clock"
    pub source: String,
    /// Measured local clock minus reference clock, milliseconds.
    pub offset_ms: i64,
    /// Half-width of the uncertainty interval, milliseconds.
    pub uncertainty_ms: u64,
}

/// Tool identity recorded with every entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    /// SHA-256 of the tool binary, when known.
    pub binary_sha256: Option<String>,
    pub command_line: String,
}

/// Source device description for acquisition entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DeviceInfo {
    pub description: String,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub size_bytes: Option<u64>,
    pub sector_size: Option<u32>,
    pub write_blocked: Option<bool>,
    pub host: Option<String>,
}

/// Unsigned entry body. Everything the signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryBody {
    pub ledger_version: u32,
    pub ledger_id: String,
    pub seq: u64,
    pub prev_hash: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub actor_key_id: String,
    pub kind: EntryKind,
    pub evidence_id: Option<String>,
    pub hashes: Option<Hashes>,
    pub device: Option<DeviceInfo>,
    pub time_source: Option<TimeSource>,
    pub tool: ToolInfo,
    pub purpose: String,
    #[serde(default)]
    pub details: BTreeMap<String, serde_json::Value>,
}

/// A signed, chained entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(flatten)]
    pub body: EntryBody,
    /// Ed25519 signature (hex) over `canonical_bytes(body)`.
    pub signature: String,
    /// SHA-256 (hex) over `canonical_bytes(body) || signature_bytes`. The next entry's prev_hash.
    pub entry_hash: String,
}

impl Entry {
    pub fn sign(body: EntryBody, key: &ExaminerKey) -> Result<Self, LedgerError> {
        let bytes = canonical::canonical_bytes(&body)?;
        let sig: Signature = key.signing_key().sign(&bytes);
        let signature = hex::encode(sig.to_bytes());
        let entry_hash = compute_entry_hash(&bytes, &sig.to_bytes());
        Ok(Self {
            body,
            signature,
            entry_hash,
        })
    }
}

/// THREAT:T2.2 chain hash covers body and signature so neither can change without detection.
pub fn compute_entry_hash(body_canonical: &[u8], signature: &[u8]) -> String {
    let mut buf = Vec::with_capacity(body_canonical.len() + signature.len());
    buf.extend_from_slice(body_canonical);
    buf.extend_from_slice(signature);
    veritas_hash::sha256_hex(&buf)
}

/// Inputs for appending; the ledger fills in seq, prev_hash and ledger id.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub kind: EntryKind,
    pub evidence_id: Option<String>,
    pub hashes: Option<Hashes>,
    pub device: Option<DeviceInfo>,
    pub time_source: Option<TimeSource>,
    pub tool: ToolInfo,
    pub purpose: String,
    pub details: BTreeMap<String, serde_json::Value>,
}

impl NewEntry {
    pub fn simple(actor: &str, kind: EntryKind, purpose: &str, tool: ToolInfo) -> Self {
        Self {
            timestamp: Utc::now(),
            actor: actor.to_string(),
            kind,
            evidence_id: None,
            hashes: None,
            device: None,
            time_source: None,
            tool,
            purpose: purpose.to_string(),
            details: BTreeMap::new(),
        }
    }
}

/// An append-only ledger persisted as JSON Lines.
#[derive(Debug, Clone)]
pub struct Ledger {
    pub ledger_id: String,
    pub entries: Vec<Entry>,
}

impl Ledger {
    /// Create a new ledger with a signed genesis entry.
    pub fn create(
        ledger_id: &str,
        case_id: &str,
        key: &ExaminerKey,
        actor: &str,
        tool: ToolInfo,
    ) -> Result<Self, LedgerError> {
        let mut details = BTreeMap::new();
        details.insert(
            "case_id".to_string(),
            serde_json::Value::String(case_id.to_string()),
        );
        let body = EntryBody {
            ledger_version: LEDGER_VERSION,
            ledger_id: ledger_id.to_string(),
            seq: 0,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            timestamp: Utc::now(),
            actor: actor.to_string(),
            actor_key_id: key.key_id(),
            kind: EntryKind::Genesis,
            evidence_id: None,
            hashes: None,
            device: None,
            time_source: None,
            tool,
            purpose: "ledger created".to_string(),
            details,
        };
        let genesis = Entry::sign(body, key)?;
        Ok(Self {
            ledger_id: ledger_id.to_string(),
            entries: vec![genesis],
        })
    }

    pub fn head(&self) -> Option<&Entry> {
        self.entries.last()
    }

    pub fn head_hash(&self) -> String {
        self.head()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string())
    }

    /// Append a signed entry. THREAT:T1.4 callers record every evidence access through here.
    pub fn append(&mut self, new: NewEntry, key: &ExaminerKey) -> Result<&Entry, LedgerError> {
        let seq = self.entries.len() as u64;
        let body = EntryBody {
            ledger_version: LEDGER_VERSION,
            ledger_id: self.ledger_id.clone(),
            seq,
            prev_hash: self.head_hash(),
            timestamp: new.timestamp,
            actor: new.actor,
            actor_key_id: key.key_id(),
            kind: new.kind,
            evidence_id: new.evidence_id,
            hashes: new.hashes,
            device: new.device,
            time_source: new.time_source,
            tool: new.tool,
            purpose: new.purpose,
            details: new.details,
        };
        let entry = Entry::sign(body, key)?;
        self.entries.push(entry);
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Append the last entry to a JSON Lines file (one line per entry, append only).
    pub fn append_to_file(&self, path: &Path) -> Result<(), LedgerError> {
        let entry = self.head().ok_or_else(|| LedgerError::Corrupt {
            line: 0,
            reason: "empty ledger".into(),
        })?;
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        let line = serde_json::to_string(entry)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        Ok(())
    }

    /// Write every entry (used for exports and tests).
    pub fn write_all(&self, path: &Path) -> Result<(), LedgerError> {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        for e in &self.entries {
            f.write_all(serde_json::to_string(e)?.as_bytes())?;
            f.write_all(b"\n")?;
        }
        f.sync_all()?;
        Ok(())
    }

    /// Load a JSON Lines ledger without verifying it. Use [`verify::verify_ledger`] afterwards.
    pub fn load(path: &Path) -> Result<Self, LedgerError> {
        let f = std::fs::File::open(path)?;
        let reader = BufReader::new(f);
        let mut entries = Vec::new();
        for (i, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: Entry = serde_json::from_str(&line).map_err(|e| LedgerError::Corrupt {
                line: i + 1,
                reason: e.to_string(),
            })?;
            entries.push(entry);
        }
        let ledger_id = entries
            .first()
            .map(|e| e.body.ledger_id.clone())
            .ok_or_else(|| LedgerError::Corrupt {
                line: 0,
                reason: "ledger has no entries".into(),
            })?;
        Ok(Self { ledger_id, entries })
    }
}

/// Registry of keys permitted to sign, with validity windows. Distributed out of band.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRegistry {
    pub keys: Vec<KeyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    pub key_id: String,
    pub public_key: String,
    pub holder: String,
    /// "admin" keys may enrol or revoke other keys; "examiner" keys may not.
    pub role: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
}

impl KeyRegistry {
    pub fn with_key(mut self, key: &ExaminerKey, holder: &str, role: &str) -> Self {
        self.keys.push(KeyRecord {
            key_id: key.key_id(),
            public_key: key.public_key_hex(),
            holder: holder.to_string(),
            role: role.to_string(),
            valid_from: Utc::now() - chrono::Duration::minutes(5),
            valid_to: None,
        });
        self
    }

    pub fn find(&self, key_id: &str) -> Option<&KeyRecord> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }
}

/// Self-contained export for an independent verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyExport {
    pub format: String,
    pub format_version: u32,
    pub exported_at: DateTime<Utc>,
    pub exported_by: String,
    pub exporter_key_id: String,
    pub head_hash: String,
    pub entry_count: u64,
    pub registry: KeyRegistry,
    pub anchors: Vec<anchor::AnchorRecord>,
    pub entries: Vec<Entry>,
    /// Signature over canonical(export without this field).
    pub signature: String,
}

impl CustodyExport {
    pub fn build(
        ledger: &Ledger,
        registry: KeyRegistry,
        anchors: Vec<anchor::AnchorRecord>,
        key: &ExaminerKey,
        exported_by: &str,
    ) -> Result<Self, LedgerError> {
        let mut export = Self {
            format: "veritas-custody".into(),
            format_version: 1,
            exported_at: Utc::now(),
            exported_by: exported_by.to_string(),
            exporter_key_id: key.key_id(),
            head_hash: ledger.head_hash(),
            entry_count: ledger.entries.len() as u64,
            registry,
            anchors,
            entries: ledger.entries.clone(),
            signature: String::new(),
        };
        let bytes = canonical::canonical_bytes(&export)?;
        let sig = key.signing_key().sign(&bytes);
        export.signature = hex::encode(sig.to_bytes());
        Ok(export)
    }

    /// Bytes the export signature covers: the export with an empty signature field.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let mut clone = self.clone();
        clone.signature = String::new();
        Ok(canonical::canonical_bytes(&clone)?)
    }
}

pub fn tool_info(name: &str, command_line: &str) -> ToolInfo {
    ToolInfo {
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        binary_sha256: None,
        command_line: command_line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verify::{verify_ledger, Verdict};

    fn tool() -> ToolInfo {
        tool_info("test", "test")
    }

    #[test]
    fn create_append_verify_roundtrip() {
        let key = ExaminerKey::generate();
        let reg = KeyRegistry::default().with_key(&key, "alice", "admin");
        let mut ledger = Ledger::create("L1", "CASE-1", &key, "alice", tool()).unwrap();
        let mut e = NewEntry::simple("alice", EntryKind::Acquire, "image disk0", tool());
        e.evidence_id = Some("EV-1".into());
        e.hashes = Some(veritas_hash::hash_bytes(b"evidence"));
        ledger.append(e, &key).unwrap();
        ledger
            .append(
                NewEntry::simple("alice", EntryKind::Access, "parse", tool()),
                &key,
            )
            .unwrap();
        let report = verify_ledger(&ledger.entries, &reg, &[]);
        assert_eq!(report.verdict, Verdict::Pass, "{:?}", report.failures);
        assert_eq!(report.entries_checked, 3);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ledger.jsonl");
        ledger.write_all(&p).unwrap();
        let loaded = Ledger::load(&p).unwrap();
        assert_eq!(loaded.entries, ledger.entries);
    }

    #[test]
    fn tampering_with_any_field_fails() {
        let key = ExaminerKey::generate();
        let reg = KeyRegistry::default().with_key(&key, "alice", "admin");
        let mut ledger = Ledger::create("L1", "CASE-1", &key, "alice", tool()).unwrap();
        ledger
            .append(
                NewEntry::simple("alice", EntryKind::Access, "parse", tool()),
                &key,
            )
            .unwrap();
        ledger
            .append(
                NewEntry::simple("alice", EntryKind::Note, "ok", tool()),
                &key,
            )
            .unwrap();

        // Change the purpose of entry 1.
        let mut t = ledger.entries.clone();
        t[1].body.purpose = "something else".into();
        assert_eq!(verify_ledger(&t, &reg, &[]).verdict, Verdict::Fail);

        // Delete entry 1.
        let mut t = ledger.entries.clone();
        t.remove(1);
        assert_eq!(verify_ledger(&t, &reg, &[]).verdict, Verdict::Fail);

        // Swap entries 1 and 2.
        let mut t = ledger.entries.clone();
        t.swap(1, 2);
        assert_eq!(verify_ledger(&t, &reg, &[]).verdict, Verdict::Fail);

        // Re-sign entry 1 with an unregistered key (attacker has no enrolled key).
        let rogue = ExaminerKey::generate();
        let mut t = ledger.entries.clone();
        let mut body = t[1].body.clone();
        body.purpose = "forged".into();
        body.actor_key_id = rogue.key_id();
        t[1] = Entry::sign(body, &rogue).unwrap();
        assert_eq!(verify_ledger(&t, &reg, &[]).verdict, Verdict::Fail);

        // Truncate the tail: verification passes for the prefix, but head hash mismatch is reported when expected head is given.
        let mut t = ledger.entries.clone();
        t.pop();
        let report = verify::verify_export_head(&t, &ledger.head_hash());
        assert!(!report);
    }

    #[test]
    fn export_signature_covers_everything() {
        let key = ExaminerKey::generate();
        let reg = KeyRegistry::default().with_key(&key, "alice", "admin");
        let ledger = Ledger::create("L1", "CASE-1", &key, "alice", tool()).unwrap();
        let export = CustodyExport::build(&ledger, reg.clone(), vec![], &key, "alice").unwrap();
        assert_eq!(verify::verify_export(&export).verdict, Verdict::Pass);
        let mut tampered = export.clone();
        tampered.head_hash = GENESIS_PREV_HASH.into();
        assert_eq!(verify::verify_export(&tampered).verdict, Verdict::Fail);
    }
}
