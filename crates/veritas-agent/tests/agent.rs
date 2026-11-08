use rand::{RngCore, SeedableRng};
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::Path;
use std::time::Duration;
use veritas_aff4::Aff4Reader;
use veritas_agent::image::{self, ImageOptions, OutputFormat};
use veritas_agent::ledger_hook::{self, Acquisition};
use veritas_agent::triage::{self, bundle, Profile, TriageOptions};
use veritas_agent::writeblock;
use veritas_agent::AgentError;
use veritas_ewf::{EwfReader, RawSegmented};
use veritas_ledger::keys::ExaminerKey;
use veritas_ledger::verify::{verify_ledger, Verdict};
use veritas_ledger::{DeviceInfo, EntryKind, KeyRegistry, Ledger, TimeSource};

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rand::rngs::StdRng::seed_from_u64(seed).fill_bytes(&mut v);
    // Some compressible stretches so E01 exercises both chunk encodings.
    for b in v.iter_mut().skip(1 << 20).take(1 << 19) {
        *b = 0;
    }
    v
}

fn source_file(dir: &Path, len: usize) -> (std::path::PathBuf, Vec<u8>) {
    let data = random_bytes(len, len as u64);
    let p = dir.join("source.bin");
    std::fs::write(&p, &data).unwrap();
    (p, data)
}

#[test]
fn aff4_image_matches_source_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = source_file(dir.path(), 3 * 1024 * 1024 + 300);
    let expected = veritas_hash::hash_reader(std::fs::File::open(&src).unwrap(), |_| {}).unwrap();
    let mut opts = ImageOptions::new(OutputFormat::Aff4, dir.path().join("img"));
    opts.case_number = "C-9".into();
    opts.examiner = "Examiner".into();
    opts.state_file = Some(dir.path().join("img.state.json"));
    let r = image::image_path(&src, &opts, &mut |_| true).unwrap();
    assert_eq!(r.format, OutputFormat::Aff4);
    assert_eq!(r.hashes, expected);
    assert_eq!(r.bytes, data.len() as u64);
    assert_eq!(r.segments.len(), 1);
    assert_eq!(r.segments[0].path, dir.path().join("img.aff4"));
    assert_eq!(
        r.segments[0].sha256,
        veritas_agent::sha256_file(&r.segments[0].path).unwrap()
    );
    assert!(!dir.path().join("img.state.json").exists());
    let summary = r.aff4.as_ref().unwrap();
    assert_eq!(summary.hashes, expected);
    assert!(r.ewf.is_none());
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["format"], "aff4");
    let mut reader = Aff4Reader::open(&r.segments[0].path).unwrap();
    assert_eq!(reader.case().case_number, "C-9");
    assert_eq!(reader.case().description, src.display().to_string());
    let mut back = Vec::new();
    reader.read_to_end(&mut back).unwrap();
    assert_eq!(back, data);
    assert!(reader.verify().unwrap().verified);
    // The output is never overwritten.
    assert!(image::image_path(&src, &opts, &mut |_| true).is_err());
}

#[test]
fn e01_and_raw_images_match_source_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = source_file(dir.path(), 6 * 1024 * 1024 + 512 * 7);
    let expected = veritas_hash::hash_reader(std::fs::File::open(&src).unwrap(), |_| {}).unwrap();

    let mut opts = ImageOptions::new(OutputFormat::E01, dir.path().join("img"));
    opts.segment_size = Some(2 * 1024 * 1024);
    opts.case_number = "C-1".into();
    let mut calls = 0;
    let r = image::image_path(&src, &opts, &mut |_| {
        calls += 1;
        true
    })
    .unwrap();
    assert!(calls > 0);
    assert_eq!(r.hashes, expected);
    assert!(r.segments.len() >= 3);
    let ewf = r.ewf.as_ref().unwrap();
    assert_eq!(ewf.hashes, expected);
    let mut reader = EwfReader::open(&r.segments[0].path).unwrap();
    let mut back = Vec::new();
    reader.read_to_end(&mut back).unwrap();
    assert_eq!(back, data);
    assert!(reader.verify().unwrap().verified);
    for s in &r.segments {
        assert_eq!(s.sha256, veritas_agent::sha256_file(&s.path).unwrap());
    }

    let mut opts = ImageOptions::new(OutputFormat::Raw, dir.path().join("raw"));
    opts.segment_size = Some(2 * 1024 * 1024);
    let r = image::image_path(&src, &opts, &mut |_| true).unwrap();
    assert_eq!(r.hashes, expected);
    assert_eq!(r.segments.len(), 4);
    assert!(r.segments[0].path.to_string_lossy().ends_with(".000"));
    let mut rs = RawSegmented::open(&r.segments[0].path).unwrap();
    let mut back = Vec::new();
    rs.read_to_end(&mut back).unwrap();
    assert_eq!(back, data);

    let opts = ImageOptions::new(OutputFormat::Raw, dir.path().join("single"));
    let r = image::image_path(&src, &opts, &mut |_| true).unwrap();
    assert_eq!(r.segments.len(), 1);
    assert!(r.segments[0].path.to_string_lossy().ends_with(".raw"));
    assert_eq!(r.hashes, expected);
}

/// In-memory device whose reads fail when they touch any of `bad` (byte ranges).
struct FaultyDevice {
    data: Vec<u8>,
    pos: u64,
    bad: Vec<Range<u64>>,
    failed_reads: u32,
}

impl Read for FaultyDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.data.len() as u64 {
            return Ok(0);
        }
        let end = (self.pos + buf.len() as u64).min(self.data.len() as u64);
        if self.bad.iter().any(|r| r.start < end && self.pos < r.end) {
            self.failed_reads += 1;
            return Err(io::Error::other("simulated CRC error"));
        }
        let n = (end - self.pos) as usize;
        buf[..n].copy_from_slice(&self.data[self.pos as usize..end as usize]);
        self.pos = end;
        Ok(n)
    }
}

impl Seek for FaultyDevice {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(d) => (self.data.len() as i64 + d) as u64,
            SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
        };
        Ok(self.pos)
    }
}

#[test]
fn bad_sectors_are_zero_filled_and_mapped() {
    let dir = tempfile::tempdir().unwrap();
    let data = random_bytes(512 * 4096, 77);
    let bad = vec![
        512 * 100..512 * 103,
        512 * 2000..512 * 2000 + 1,
        512 * 4095..512 * 4096,
    ];
    for format in [OutputFormat::E01, OutputFormat::Aff4, OutputFormat::Raw] {
        let mut dev = FaultyDevice {
            data: data.clone(),
            pos: 0,
            bad: bad.clone(),
            failed_reads: 0,
        };
        let mut opts = ImageOptions::new(format, dir.path().join(format!("bad_{:?}", format)));
        opts.block_sectors = 64;
        opts.retries = 2;
        let r = image::image_reader(
            &mut dev,
            "faulty",
            Some(data.len() as u64),
            &opts,
            &mut |_| true,
        )
        .unwrap();
        assert!(dev.failed_reads > 0);
        let ranges: Vec<(u64, u64)> = r
            .bad_sectors
            .iter()
            .map(|b| (b.first_sector, b.sector_count))
            .collect();
        assert_eq!(ranges, vec![(100, 3), (2000, 1), (4095, 1)]);
        let mut expected = data.clone();
        for rg in &bad {
            let s = (rg.start / 512 * 512) as usize;
            let e = (rg.end.div_ceil(512) * 512) as usize;
            expected[s..e].iter_mut().for_each(|b| *b = 0);
        }
        assert_eq!(r.hashes, veritas_hash::hash_bytes(&expected));
        if format == OutputFormat::E01 {
            let mut er = EwfReader::open(&r.segments[0].path).unwrap();
            assert_eq!(er.acquisition_errors(), &r.bad_sectors[..]);
            let mut back = Vec::new();
            er.read_to_end(&mut back).unwrap();
            assert_eq!(back, expected);
        }
        if format == OutputFormat::Aff4 {
            let mut ar = Aff4Reader::open(&r.segments[0].path).unwrap();
            assert_eq!(
                ar.acquisition_errors(),
                &r.aff4.as_ref().unwrap().bad_sectors[..]
            );
            let runs: Vec<(u64, u64)> = ar
                .acquisition_errors()
                .iter()
                .map(|b| (b.first_sector, b.sector_count))
                .collect();
            assert_eq!(runs, ranges);
            let mut back = Vec::new();
            ar.read_to_end(&mut back).unwrap();
            assert_eq!(back, expected);
            assert!(ar.verify().unwrap().verified);
        }
    }
}

#[test]
fn raw_acquisition_resumes_from_current_segment() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _data) = source_file(dir.path(), 5 * 1024 * 1024);
    let expected = veritas_hash::hash_reader(std::fs::File::open(&src).unwrap(), |_| {}).unwrap();
    let mut opts = ImageOptions::new(OutputFormat::Raw, dir.path().join("res"));
    opts.segment_size = Some(1024 * 1024);
    opts.block_sectors = 256;
    opts.state_file = Some(dir.path().join("res.state.json"));
    let err = image::image_path(&src, &opts, &mut |p| p.bytes_done < 2_500_000).unwrap_err();
    assert!(matches!(err, AgentError::Interrupted(_)));
    let st = image::ImageState::load(opts.state_file.as_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(st.completed_segments.len(), 2);
    assert_eq!(st.current_segment_start, 2 * 1024 * 1024);
    let r = image::image_path(&src, &opts, &mut |_| true).unwrap();
    assert_eq!(r.resumed_from, Some(2 * 1024 * 1024));
    assert_eq!(r.hashes, expected);
    assert_eq!(r.segments.len(), 5);
    // Tampering with a completed segment between runs is detected on resume.
    let mut opts2 = opts.clone();
    opts2.out_base = dir.path().join("res2");
    opts2.state_file = Some(dir.path().join("res2.state.json"));
    let _ = image::image_path(&src, &opts2, &mut |p| p.bytes_done < 2_500_000);
    let seg0 = dir.path().join("res2.000");
    let mut b = std::fs::read(&seg0).unwrap();
    b[10] ^= 1;
    std::fs::write(&seg0, b).unwrap();
    assert!(matches!(
        image::image_path(&src, &opts2, &mut |_| true),
        Err(AgentError::Integrity(_))
    ));
}

#[test]
fn triage_bundle_has_valid_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("bundle.zip");
    let opts = TriageOptions {
        profile: Profile::Quick,
        max_file_bytes: 32 * 1024 * 1024,
        command_timeout: Duration::from_secs(120),
        ..Default::default()
    };
    let mut seen = Vec::new();
    let m = triage::run_triage(&out, &opts, &mut |n, _, _| seen.push(n.to_string())).unwrap();
    assert!(seen.contains(&"processes".to_string()));
    let verified = bundle::verify_bundle(&out).unwrap();
    assert_eq!(verified.files, m.files);
    let names: Vec<&str> = m.files.iter().map(|f| f.path.as_str()).collect();
    assert!(names.contains(&"system/system_info.json"), "{:?}", names);
    assert!(names.contains(&"processes/processes.json"));
    assert!(names.contains(&"network/connections.json"));
    // Processes JSON is well formed and lists this test process.
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&out).unwrap()).unwrap();
    let mut s = String::new();
    zip.by_name("processes/processes.json")
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();
    let procs: Vec<triage::ProcessRecord> = serde_json::from_str(&s).unwrap();
    assert!(procs.iter().any(|p| p.pid == std::process::id()));
    for f in &m.files {
        assert_eq!(f.sha256.len(), 64);
    }
    eprintln!(
        "triage: {} files, {} recorded errors, elevated={:?}",
        m.files.len(),
        m.errors.len(),
        m.elevated
    );
}

#[test]
fn writeblock_check_returns_status() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("x.img");
    std::fs::write(&f, b"abc").unwrap();
    assert_eq!(writeblock::check(&f).read_only, Some(false));
    let dev = if cfg!(windows) {
        r"\\.\PhysicalDrive0"
    } else {
        "/dev/sda"
    };
    let s = writeblock::check(Path::new(dev));
    assert!(!s.method.is_empty());
    eprintln!("{} -> {:?}", dev, s);
}

#[test]
fn ledger_entry_appended_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.json");
    ExaminerKey::generate()
        .save_encrypted(&key_path, "correct horse battery")
        .unwrap();
    let key = ExaminerKey::load_encrypted(&key_path, "correct horse battery").unwrap();
    let ledger_path = dir.path().join("ledger.jsonl");
    let acq = Acquisition {
        case_id: "CASE-9".into(),
        evidence_id: "EV-1".into(),
        actor: "alice".into(),
        purpose: "disk image".into(),
        hashes: veritas_hash::hash_bytes(b"evidence bytes"),
        device: DeviceInfo {
            description: "test device".into(),
            write_blocked: Some(true),
            sector_size: Some(512),
            ..Default::default()
        },
        details: Default::default(),
    };
    let ts = TimeSource {
        source: "ntp:test".into(),
        offset_ms: -12,
        uncertainty_ms: 30,
    };
    let tool = ledger_hook::agent_tool_info();
    assert!(tool.binary_sha256.is_some());
    ledger_hook::append_acquisition(
        &ledger_path,
        &key,
        &acq,
        ts.clone(),
        tool.clone(),
        chrono::Utc::now(),
    )
    .unwrap();
    // System-clock fallback with unknown uncertainty must also sign and verify.
    let fallback = ledger_hook::measure_time(&["invalid.invalid"], Duration::from_millis(100));
    ledger_hook::append_acquisition(&ledger_path, &key, &acq, fallback, tool, chrono::Utc::now())
        .unwrap();
    let ledger = Ledger::load(&ledger_path).unwrap();
    assert_eq!(ledger.entries.len(), 3);
    assert_eq!(ledger.entries[1].body.kind, EntryKind::Acquire);
    assert_eq!(ledger.entries[1].body.time_source.as_ref(), Some(&ts));
    assert_eq!(
        ledger.entries[1]
            .body
            .device
            .as_ref()
            .unwrap()
            .write_blocked,
        Some(true)
    );
    let reg = KeyRegistry::default().with_key(&key, "alice", "examiner");
    let report = verify_ledger(&ledger.entries, &reg, &[]);
    assert_eq!(report.verdict, Verdict::Pass, "{:?}", report.failures);
}
