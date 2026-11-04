//! Writes our view of each corpus hive for the Python parity tests
//! (`python/tests/parity/test_regf.py`, `test_registry_artifacts.py`).
//!
//! Run with: `cargo test -p veritas-artifacts --test regf_parity_dump -- --ignored`
//! Output: `target/parity/regf/<hive>.jsonl` (one key per line) and
//! `target/parity/registry/<hive>.json` (shimcache / UserAssist entries).
//! `VERITAS_PARITY_OUT` overrides the output root.
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use veritas_artifacts::regf::Hive;
use veritas_artifacts::registry::{shellbags, shimcache, userassist};

const HIVES: &[&str] = &[
    "NTUSER.DAT",
    "NTUSER-WIN7.DAT",
    "NTUSER-RunTests.DAT",
    "NTUSER-CCLEANER.DAT",
    "SYSTEM",
    "SOFTWARE",
    "regf/NTUSER.DAT",
    "regf/UsrClass.dat",
    "regf/100_sub_keys.hiv",
    "regf/corrupt_sub_key_list.hiv",
    "winreg/Amcache.hve",
    "winreg/win10-Amcache.hve",
];

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/plaso")
}

fn out_root() -> PathBuf {
    std::env::var_os("VERITAS_PARITY_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/parity"))
}

fn safe(name: &str) -> String {
    name.replace(['/', '\\'], "__")
}

#[test]
#[ignore = "writes parity artefacts; run explicitly"]
fn regf_parity_dump() {
    let regf_dir = out_root().join("regf");
    let reg_dir = out_root().join("registry");
    std::fs::create_dir_all(&regf_dir).unwrap();
    std::fs::create_dir_all(&reg_dir).unwrap();
    for name in HIVES {
        let p = corpus().join(name);
        let Ok(bytes) = std::fs::read(&p) else {
            eprintln!("skip missing {}", p.display());
            continue;
        };
        let hive = Hive::parse(&bytes).expect("parse");
        let f = std::fs::File::create(regf_dir.join(format!("{}.jsonl", safe(name)))).unwrap();
        let mut w = std::io::BufWriter::new(f);
        hive.walk(|path, _, k| {
            let values: Vec<serde_json::Value> = k
                .values()
                .iter()
                .map(|v| {
                    // Raw 4-byte data field of resident values (for the libregf normalisation in the parity test).
                    let field = if v.resident { hive.cell(v.offset).ok().and_then(|c| c.get(8..12)).map(hex::encode) } else { None };
                    json!({"name": v.name, "type": v.kind.as_u32(), "data_hex": hex::encode(&v.raw), "resident_field_hex": field, "error": v.data_error})
                })
                .collect();
            let line = json!({
                "path": path,
                "name": k.name,
                "last_written_raw": k.last_written_raw,
                "last_written_ns": k.last_written_ns,
                "class_name": k.class_name,
                "subkey_count": k.subkey_count,
                "value_count": k.value_count,
                "values": values,
            });
            serde_json::to_writer(&mut w, &line).unwrap();
            w.write_all(b"\n").unwrap();
        })
        .unwrap();
        w.flush().unwrap();

        let shim = shimcache::from_hive(&hive).and_then(|(_, _, r)| r.ok()).map(|c| {
            json!({
                "format": c.format,
                "entries": c.entries.iter().map(|e| json!({"index": e.index, "path": e.path, "last_modified_raw": e.last_modified_raw, "executed": e.executed, "insert_flags": e.insert_flags})).collect::<Vec<_>>(),
            })
        });
        let ua: Vec<serde_json::Value> = userassist::entries(&hive)
            .iter()
            .map(|e| json!({"guid": e.guid, "value_name": e.value_name, "count": e.count, "focus_count": e.focus_count, "focus_duration_ms": e.focus_duration_ms, "last_executed_raw": e.last_executed_raw, "format": e.format}))
            .collect();
        let bags: Vec<serde_json::Value> = shellbags::entries(&hive)
            .iter()
            .map(|e| json!({"key": e.key_rel_path, "value": e.value_name, "path": e.path, "item_types": e.item_types, "error": e.decode_error}))
            .collect();
        let deleted = hive.recover_deleted();
        let doc = json!({
            "hive": name,
            "shimcache": shim,
            "userassist": ua,
            "shellbags": bags,
            "deleted_keys": deleted.keys.len(),
            "deleted_values": deleted.values.len(),
        });
        std::fs::write(
            reg_dir.join(format!("{}.json", safe(name))),
            serde_json::to_vec_pretty(&doc).unwrap(),
        )
        .unwrap();
    }
}
