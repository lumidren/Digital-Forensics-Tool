//! End-to-end: build a ledger, export it, run the `veritas-verify` binary, expect PASS; tamper
//! with the export on disk, expect FAIL and a non-zero exit status.

use std::process::Command;
use veritas_ledger::anchor::{append_anchor, AnchorRecord};
use veritas_ledger::keys::ExaminerKey;
use veritas_ledger::{tool_info, CustodyExport, EntryKind, KeyRegistry, Ledger, NewEntry};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_veritas-verify"))
}

#[test]
fn export_pass_then_tamper_fail() {
    let dir = tempfile::tempdir().unwrap();
    let key = ExaminerKey::generate();
    let registry = KeyRegistry::default().with_key(&key, "alice", "admin");
    let mut ledger = Ledger::create(
        "L-TEST",
        "CASE-7",
        &key,
        "alice",
        tool_info("test", "cargo test"),
    )
    .unwrap();
    let mut acquire = NewEntry::simple(
        "alice",
        EntryKind::Acquire,
        "image laptop disk",
        tool_info("veritas-agent", "image /dev/sda"),
    );
    acquire.evidence_id = Some("EV-1".into());
    acquire.hashes = Some(veritas_hash::hash_bytes(b"disk bytes"));
    ledger.append(acquire, &key).unwrap();
    ledger
        .append(
            NewEntry::simple(
                "alice",
                EntryKind::Ingest,
                "stored",
                tool_info("veritas-api", "ingest"),
            ),
            &key,
        )
        .unwrap();

    let anchors_path = dir.path().join("anchors.jsonl");
    let head = ledger.head().unwrap();
    append_anchor(
        &anchors_path,
        &AnchorRecord {
            ledger_id: ledger.ledger_id.clone(),
            seq: head.body.seq,
            head_hash: head.entry_hash.clone(),
            anchored_at: chrono::Utc::now(),
            sink: "file".into(),
            receipt: None,
        },
    )
    .unwrap();
    let anchors = veritas_ledger::anchor::load_anchors(&anchors_path).unwrap();

    let export = CustodyExport::build(&ledger, registry.clone(), anchors, &key, "alice").unwrap();
    let export_path = dir.path().join("custody.json");
    std::fs::write(&export_path, serde_json::to_string_pretty(&export).unwrap()).unwrap();

    let out = bin().arg("export").arg(&export_path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", stdout);
    assert!(stdout.trim().ends_with("PASS"), "{}", stdout);
    assert!(stdout.contains("anchors checked:    1"));

    // Raw ledger path with registry file.
    let ledger_path = dir.path().join("ledger.jsonl");
    ledger.write_all(&ledger_path).unwrap();
    let reg_path = dir.path().join("registry.json");
    std::fs::write(&reg_path, serde_json::to_string(&registry).unwrap()).unwrap();
    let out = bin()
        .arg("ledger")
        .arg(&ledger_path)
        .arg("--registry")
        .arg(&reg_path)
        .arg("--anchors")
        .arg(&anchors_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["verdict"], "Pass");

    // Tamper: flip one character of the evidence hash inside the export.
    let text = std::fs::read_to_string(&export_path).unwrap();
    let sha = export.entries[1]
        .body
        .hashes
        .as_ref()
        .unwrap()
        .sha256
        .clone();
    let mut flipped = sha.clone();
    let first = flipped.remove(0);
    flipped.insert(0, if first == 'a' { 'b' } else { 'a' });
    std::fs::write(&export_path, text.replace(&sha, &flipped)).unwrap();
    let out = bin().arg("export").arg(&export_path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout.trim().ends_with("FAIL"), "{}", stdout);
    assert!(stdout.contains("signature"), "{}", stdout);
}
