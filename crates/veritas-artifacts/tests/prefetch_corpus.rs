//! Prefetch corpus tests. Every expected value below was produced by libscca-python
//! (pyscca 20260527) on the same files: executable_filename, prefetch_hash, run_count,
//! format_version, get_last_run_time_as_integer(i), number_of_filenames / get_filename(0) and
//! get_volume_information(i).{device_path, serial_number, get_creation_time_as_integer()}.
use proptest::prelude::*;
use std::path::PathBuf;
use veritas_artifacts::prefetch;

fn corpus(rel: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/corpus/plaso").join(rel);
    match std::fs::read(&p) {
        Ok(d) => Some(d),
        Err(_) if std::env::var("VERITAS_REQUIRE_CORPUS").is_err() => {
            eprintln!("skipping: corpus file {} missing (run testdata/fetch.py)", p.display());
            None
        }
        Err(e) => panic!("corpus file {} missing: {e}", p.display()),
    }
}

struct Case {
    file: &'static str,
    exe: &'static str,
    hash: u32,
    run_count: u32,
    version: u32,
    runs: &'static [u64],
    n_files: usize,
    first_file: &'static str,
    volumes: &'static [(&'static str, u32, u64)],
}

const CASES: &[Case] = &[
    Case { file: "AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf", exe: "AM_DELTA_PATCH_1.443.990.0.EX", hash: 1882705798, run_count: 1, version: 31, runs: &[134146862246686325], n_files: 18, first_file: r"\VOLUME{01dc94cf1f08c4a4-bc1f1bfc}\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\VOLUME{01dc94cf1f08c4a4-bc1f1bfc}", 3156155388, 134145706214081700)] },
    Case { file: "BYTECODEGENERATOR.EXE-C1E9BCE6.pf", exe: "BYTECODEGENERATOR.EXE", hash: 3253320934, run_count: 7, version: 30, runs: &[130761151180911341, 130761151153576520, 130761151055135991, 130761150858427278, 130761150798586549, 130761150659066547, 130761150382515193], n_files: 1085, first_file: r"\VOLUME{01d08edc0cbccaad-3e0d2d25}\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\VOLUME{01d08edc0cbccaad-3e0d2d25}", 1041050917, 130761464951392941)] },
    Case { file: "CMD.EXE-087B4001.pf", exe: "CMD.EXE", hash: 142295041, run_count: 2, version: 17, runs: &[130073839092812500], n_files: 33, first_file: r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\DEVICE\HARDDISKVOLUME1", 617285451, 130073843862343750)] },
    Case { file: "NOTEPAD.EXE-D8414F97.pf", exe: "NOTEPAD.EXE", hash: 3628158871, run_count: 2, version: 30, runs: &[132042381048777787, 132042361808157052], n_files: 56, first_file: r"\VOLUME{01d3096ba3a46863-2ca3d1ae}\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\VOLUME{01d3096ba3a46863-2ca3d1ae}", 748933550, 131459172035487843)] },
    Case { file: "ONEDRIVE.EXE-7E152375.pf", exe: "ONEDRIVE.EXE", hash: 2115314549, run_count: 2, version: 30, runs: &[130761150654852771, 130761150286747101], n_files: 134, first_file: r"\VOLUME{01d08edc0cbccaad-3e0d2d25}\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\VOLUME{01d08edc0cbccaad-3e0d2d25}", 1041050917, 130761464951392941)] },
    Case { file: "PING.EXE-B29F6629.pf", exe: "PING.EXE", hash: 2996790825, run_count: 14, version: 23, runs: &[129782124559329556], n_files: 27, first_file: r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\DEVICE\HARDDISKVOLUME1", 2885903653, 129338842464843750)] },
    Case { file: "TASKHOST.EXE-3AE259FC.pf", exe: "TASKHOST.EXE", hash: 987912700, run_count: 4, version: 26, runs: &[130253748090378333, 130253740890103565, 130253411945960606, 130253406736429375], n_files: 51, first_file: r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\DEVICE\HARDDISKVOLUME2", 1751925321, 130253758461465476)] },
    Case { file: "WUAUCLT.EXE-830BCC14.pf", exe: "WUAUCLT.EXE", hash: 2198588436, run_count: 25, version: 23, runs: &[129763198598079963], n_files: 103, first_file: r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\NTDLL.DLL", volumes: &[(r"\DEVICE\HARDDISKVOLUME1", 2885903653, 129338842464843750), (r"\DEVICE\HARDDISKVOLUMESHADOWCOPY2", 2885903653, 129338842464843750), (r"\DEVICE\HARDDISKVOLUMESHADOWCOPY4", 2885903653, 129338842464843750), (r"\DEVICE\HARDDISKVOLUMESHADOWCOPY7", 2885903653, 129338842464843750), (r"\DEVICE\HARDDISKVOLUMESHADOWCOPY8", 2885903653, 129338842464843750)] },
];

#[test]
fn all_samples_match_pyscca() {
    for c in CASES {
        let Some(d) = corpus(&format!("winprefetch/{}", c.file)) else { return };
        let p = prefetch::parse(&d).unwrap_or_else(|e| panic!("{}: {e}", c.file));
        assert_eq!(p.executable_filename, c.exe, "{}", c.file);
        assert_eq!(p.prefetch_hash, c.hash, "{}", c.file);
        assert_eq!(p.run_count, c.run_count, "{}", c.file);
        assert_eq!(p.version, c.version, "{}", c.file);
        assert_eq!(p.last_run_filetimes, c.runs, "{}", c.file);
        assert_eq!(p.file_metrics.len(), c.n_files, "{}", c.file);
        assert_eq!(p.file_metrics[0].filename, c.first_file, "{}", c.file);
        let vols: Vec<(&str, u32, u64)> = p.volumes.iter().map(|v| (v.device_path.as_str(), v.serial_number, v.creation_filetime)).collect();
        assert_eq!(vols, c.volumes, "{}", c.file);
        assert_eq!(p.compressed, c.version >= 30, "{}", c.file);
    }
}

#[test]
fn events_per_run_time() {
    let Some(d) = corpus("winprefetch/TASKHOST.EXE-3AE259FC.pf") else { return };
    let p = prefetch::parse(&d).unwrap();
    let ev = prefetch::events(&p, "sha", "TASKHOST.EXE-3AE259FC.pf");
    assert_eq!(ev.len(), 4);
    assert_eq!(ev[0].timestamp_desc, "Last Time Executed");
    assert!(ev[1..].iter().all(|e| e.timestamp_desc == "Previous Last Time Executed"));
    assert_eq!(ev[0].data_type, "windows:prefetch:execution");
    assert_eq!(ev[0].attrs["executable"], "TASKHOST.EXE");
    assert_eq!(ev[0].attrs["run_count"], 4);
    assert_eq!(ev[0].attrs["prefetch_hash"], "0x3AE259FC");
    let mapped = ev[0].attrs["mapped_files"].as_array().unwrap();
    let mut sorted = mapped.clone();
    sorted.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    assert_eq!(mapped, &sorted);
    assert_eq!(ev[0].attrs["volume_serial_numbers"][0], "0x686C4249"); // pyscca serial 1751925321
    // determinism
    let again = prefetch::events(&prefetch::parse(&d).unwrap(), "sha", "TASKHOST.EXE-3AE259FC.pf");
    assert_eq!(serde_json::to_string(&ev).unwrap(), serde_json::to_string(&again).unwrap());
}

#[test]
fn mam_decompression_bomb_is_refused() {
    // MAM\x04 declaring 1 GiB of output.
    let mut d = b"MAM\x04".to_vec();
    d.extend_from_slice(&(1u32 << 30).to_le_bytes());
    d.extend_from_slice(&[0u8; 300]);
    assert!(matches!(prefetch::parse(&d), Err(veritas_artifacts::error::ParseError::Limit(_))));
    assert!(prefetch::lzxpress_huffman_decompress(&[0u8; 300], prefetch::MAX_DECOMPRESSED + 1).is_err());
}

#[test]
fn lzxpress_rejects_empty_table() {
    assert!(prefetch::lzxpress_huffman_decompress(&[0u8; 260], 10).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]
    #[test]
    fn compressed_mutations_never_panic(muts in proptest::collection::vec((0usize..1_000_000, any::<u8>()), 1..32), cut in 0usize..1_000_000) {
        if let Some(mut d) = corpus("winprefetch/NOTEPAD.EXE-D8414F97.pf") {
            let n = d.len();
            for (o, b) in muts { d[o % n] = b; }
            let _ = prefetch::parse(&d);
            let _ = prefetch::parse(&d[..cut % n]);
        }
    }

    #[test]
    fn uncompressed_mutations_never_panic(muts in proptest::collection::vec((0usize..1_000_000, any::<u8>()), 1..32), cut in 0usize..1_000_000) {
        for f in ["winprefetch/CMD.EXE-087B4001.pf", "winprefetch/TASKHOST.EXE-3AE259FC.pf"] {
            if let Some(mut d) = corpus(f) {
                let n = d.len();
                for (o, b) in &muts { d[o % n] = *b; }
                let _ = prefetch::parse(&d);
                let _ = prefetch::parse(&d[..cut % n]);
            }
        }
    }

    #[test]
    fn lzxpress_random_never_panics(d in proptest::collection::vec(any::<u8>(), 0..2048), n in 0usize..200_000) {
        let _ = prefetch::lzxpress_huffman_decompress(&d, n);
    }
}
