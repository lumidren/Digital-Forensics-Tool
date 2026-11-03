//! Independent verification of a ledger. Shares only `canonical` with the writer.
#![forbid(unsafe_code)]

use crate::anchor::AnchorRecord;
use crate::canonical::canonical_bytes;
use crate::{compute_entry_hash, CustodyExport, Entry, EntryKind, KeyRecord, KeyRegistry, GENESIS_PREV_HASH, LEDGER_VERSION};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub seq: Option<u64>,
    pub check: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub verdict: Verdict,
    pub entries_checked: u64,
    pub signatures_checked: u64,
    pub anchors_checked: u64,
    pub head_hash: String,
    pub failures: Vec<Failure>,
}

impl Report {
    fn fail(&mut self, seq: Option<u64>, check: &str, detail: String) {
        self.verdict = Verdict::Fail;
        self.failures.push(Failure { seq, check: check.to_string(), detail });
    }
}

fn parse_pk(hex_pk: &str) -> Option<VerifyingKey> {
    let bytes = hex::decode(hex_pk).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Effective key state during replay: registry keys plus keys enrolled/revoked in-ledger.
#[derive(Clone)]
struct KeyState {
    record: KeyRecord,
    revoked_at: Option<DateTime<Utc>>,
}

/// Verify a sequence of entries from scratch.
pub fn verify_ledger(entries: &[Entry], registry: &KeyRegistry, anchors: &[AnchorRecord]) -> Report {
    let mut report = Report {
        verdict: Verdict::Pass,
        entries_checked: 0,
        signatures_checked: 0,
        anchors_checked: 0,
        head_hash: GENESIS_PREV_HASH.to_string(),
        failures: Vec::new(),
    };
    if entries.is_empty() {
        report.fail(None, "non_empty", "ledger has no entries".into());
        return report;
    }

    let mut keys: BTreeMap<String, KeyState> = registry
        .keys
        .iter()
        .map(|k| (k.key_id.clone(), KeyState { record: k.clone(), revoked_at: None }))
        .collect();

    let mut prev_hash = GENESIS_PREV_HASH.to_string();
    let mut prev_time: Option<DateTime<Utc>> = None;
    let ledger_id = entries[0].body.ledger_id.clone();

    for (i, entry) in entries.iter().enumerate() {
        let seq = entry.body.seq;
        report.entries_checked += 1;

        // THREAT:T2.3 sequence must be dense and ordered.
        if seq != i as u64 {
            report.fail(Some(seq), "sequence", format!("expected seq {} found {}", i, seq));
        }
        if entry.body.ledger_version != LEDGER_VERSION {
            report.fail(Some(seq), "version", format!("unsupported ledger version {}", entry.body.ledger_version));
        }
        if entry.body.ledger_id != ledger_id {
            report.fail(Some(seq), "ledger_id", "entry belongs to a different ledger".into());
        }
        if i == 0 && entry.body.kind != EntryKind::Genesis {
            report.fail(Some(seq), "genesis", "first entry is not a genesis entry".into());
        }
        if i > 0 && entry.body.kind == EntryKind::Genesis {
            report.fail(Some(seq), "genesis", "genesis entry after the first position".into());
        }
        if entry.body.prev_hash != prev_hash {
            report.fail(Some(seq), "prev_hash", format!("expected {} found {}", prev_hash, entry.body.prev_hash));
        }
        if let Some(pt) = prev_time {
            if entry.body.timestamp < pt {
                report.fail(Some(seq), "monotonic_time", format!("timestamp {} precedes previous {}", entry.body.timestamp, pt));
            }
        }

        // Canonical body and hash.
        let body_bytes = match canonical_bytes(&entry.body) {
            Ok(b) => b,
            Err(e) => {
                report.fail(Some(seq), "canonical", e.to_string());
                prev_hash = entry.entry_hash.clone();
                continue;
            }
        };
        let sig_bytes = match hex::decode(&entry.signature) {
            Ok(b) => b,
            Err(_) => {
                report.fail(Some(seq), "signature_format", "signature is not hex".into());
                Vec::new()
            }
        };
        let expected_hash = compute_entry_hash(&body_bytes, &sig_bytes);
        if expected_hash != entry.entry_hash {
            report.fail(Some(seq), "entry_hash", format!("expected {} found {}", expected_hash, entry.entry_hash));
        }

        // Signature by a key that was valid at the time. THREAT:T6.2 THREAT:T6.3
        match keys.get(&entry.body.actor_key_id).cloned() {
            None => report.fail(Some(seq), "key_unknown", format!("key {} is not enrolled", entry.body.actor_key_id)),
            Some(state) => {
                let r = &state.record;
                if entry.body.timestamp < r.valid_from {
                    report.fail(Some(seq), "key_validity", "entry predates key validity window".into());
                }
                if let Some(to) = r.valid_to {
                    if entry.body.timestamp > to {
                        report.fail(Some(seq), "key_validity", "entry postdates key validity window".into());
                    }
                }
                if let Some(rev) = state.revoked_at {
                    if entry.body.timestamp >= rev {
                        report.fail(Some(seq), "key_revoked", format!("key {} revoked at {}", r.key_id, rev));
                    }
                }
                match (parse_pk(&r.public_key), Signature::from_slice(&sig_bytes)) {
                    (Some(pk), Ok(sig)) => {
                        report.signatures_checked += 1;
                        if pk.verify(&body_bytes, &sig).is_err() {
                            report.fail(Some(seq), "signature", "Ed25519 signature does not verify".into());
                        }
                    }
                    _ => report.fail(Some(seq), "signature_format", "public key or signature malformed".into()),
                }
                // Key management entries must come from admin keys.
                if matches!(entry.body.kind, EntryKind::KeyEnrolled | EntryKind::KeyRevoked) && r.role != "admin" {
                    report.fail(Some(seq), "authority", "key management entry signed by a non-admin key".into());
                }
            }
        }

        // Apply in-ledger key management after validating the signer.
        match entry.body.kind {
            EntryKind::KeyEnrolled => match serde_json::from_value::<KeyRecord>(
                serde_json::Value::Object(entry.body.details.clone().into_iter().collect()),
            ) {
                Ok(rec) => {
                    keys.insert(rec.key_id.clone(), KeyState { record: rec, revoked_at: None });
                }
                Err(e) => report.fail(Some(seq), "key_enrolled", format!("details do not describe a key: {}", e)),
            },
            EntryKind::KeyRevoked => {
                let target = entry.body.details.get("key_id").and_then(|v| v.as_str()).map(str::to_string);
                match target.and_then(|t| keys.get_mut(&t)) {
                    Some(state) => state.revoked_at = Some(entry.body.timestamp),
                    None => report.fail(Some(seq), "key_revoked", "revocation names an unknown key".into()),
                }
            }
            _ => {}
        }

        prev_hash = entry.entry_hash.clone();
        prev_time = Some(entry.body.timestamp);
    }
    report.head_hash = prev_hash;

    // Anchors: each must match the entry hash at its sequence.
    for a in anchors {
        report.anchors_checked += 1;
        match entries.get(a.seq as usize) {
            Some(e) if e.entry_hash == a.head_hash => {}
            Some(e) => report.fail(Some(a.seq), "anchor", format!("anchor hash {} differs from entry hash {}", a.head_hash, e.entry_hash)),
            None => report.fail(Some(a.seq), "anchor", "anchor refers to a sequence beyond the ledger".into()),
        }
    }
    report
}

/// True when the chain head equals the expected head (detects truncation of the tail).
pub fn verify_export_head(entries: &[Entry], expected_head: &str) -> bool {
    entries.last().map(|e| e.entry_hash == expected_head).unwrap_or(false)
}

/// Verify a self-contained custody export: outer signature, head, count and the full chain.
pub fn verify_export(export: &CustodyExport) -> Report {
    let mut report = verify_ledger(&export.entries, &export.registry, &export.anchors);
    if export.format != "veritas-custody" || export.format_version != 1 {
        report.fail(None, "export_format", format!("unsupported export {} v{}", export.format, export.format_version));
    }
    if export.entry_count != export.entries.len() as u64 {
        report.fail(None, "export_count", format!("export claims {} entries, contains {}", export.entry_count, export.entries.len()));
    }
    if !verify_export_head(&export.entries, &export.head_hash) {
        report.fail(None, "export_head", "export head hash does not match the last entry (tail truncated?)".into());
    }
    match (export.registry.find(&export.exporter_key_id), export.signed_bytes()) {
        (Some(rec), Ok(bytes)) => match (parse_pk(&rec.public_key), hex::decode(&export.signature).ok().and_then(|b| Signature::from_slice(&b).ok())) {
            (Some(pk), Some(sig)) => {
                report.signatures_checked += 1;
                if pk.verify(&bytes, &sig).is_err() {
                    report.fail(None, "export_signature", "export signature does not verify".into());
                }
            }
            _ => report.fail(None, "export_signature", "exporter key or signature malformed".into()),
        },
        (None, _) => report.fail(None, "export_signature", format!("exporter key {} not in registry", export.exporter_key_id)),
        (_, Err(e)) => report.fail(None, "export_signature", e.to_string()),
    }
    report
}
