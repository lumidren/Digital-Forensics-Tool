//! AFF4 evidence: `open_evidence` detects AFF4 containers and `fs-tool` lists the same files from
//! an AFF4 conversion of a raw image as from the raw image itself.
use std::path::{Path, PathBuf};
use std::process::Command;
use veritas_fs::io::{open_evidence, read_vec};

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus")
        .join(rel)
}

fn to_aff4(src: &Path, out: &Path) {
    let opts = veritas_aff4::Aff4Options {
        compression: veritas_aff4::Compression::Snappy,
        chunks_per_segment: 16, // several bevies for a 4 MiB image
        ..Default::default()
    };
    let mut w = veritas_aff4::Aff4Writer::create(out, opts).unwrap();
    w.write(&std::fs::read(src).unwrap()).unwrap();
    w.finish().unwrap();
}

fn fs_tool(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_fs-tool"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fs-tool {:?}: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn open_evidence_reads_aff4_media() {
    let dir = tempfile::tempdir().unwrap();
    let raw = corpus("dfvfs/ntfs.raw");
    let aff4 = dir.path().join("ntfs.aff4");
    to_aff4(&raw, &aff4);
    let src = open_evidence(&aff4).unwrap();
    let bytes = std::fs::read(&raw).unwrap();
    assert_eq!(src.size(), bytes.len() as u64);
    assert_eq!(read_vec(src.as_ref(), 0, src.size()).unwrap(), bytes);
    // A plain ZIP is still read as raw bytes.
    let zip = dir.path().join("plain.zip");
    let mut zw = veritas_aff4::zip::ZipWriter::new(std::io::Cursor::new(Vec::new()), (0, 0x21));
    zw.add_stored("a.txt", b"hello").unwrap();
    let zbytes = zw.finish(b"").unwrap().into_inner();
    std::fs::write(&zip, &zbytes).unwrap();
    assert_eq!(open_evidence(&zip).unwrap().size(), zbytes.len() as u64);
}

#[test]
fn fs_tool_lists_files_from_aff4() {
    let dir = tempfile::tempdir().unwrap();
    let raw = corpus("dfvfs/ntfs.raw");
    let aff4 = dir.path().join("ntfs.aff4");
    to_aff4(&raw, &aff4);
    let raw_s = raw.to_string_lossy().to_string();
    let aff4_s = aff4.to_string_lossy().to_string();
    let from_raw = fs_tool(&["ls", &raw_s, "-r"]);
    let from_aff4 = fs_tool(&["ls", &aff4_s, "-r"]);
    assert!(from_aff4.lines().count() > 5, "{}", from_aff4);
    assert!(from_aff4.contains("\"NTFS\""));
    assert_eq!(from_raw, from_aff4);
    assert_eq!(
        fs_tool(&["partitions", &raw_s]),
        fs_tool(&["partitions", &aff4_s])
    );
}
