//! ZIP bundle writer. Every stored file is hashed (SHA-256) while it is written and listed in
//! `manifest.json`, which is written last. Failures are recorded per item, never fatal.

use crate::{AgentError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub const MANIFEST_NAME: &str = "manifest.json";

/// One file in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Path inside the ZIP.
    pub path: String,
    /// SHA-256 of the stored bytes.
    pub sha256: String,
    pub size: u64,
    pub collected_at: DateTime<Utc>,
    pub collector: String,
    /// Original location on the host, when the file was copied.
    pub source: Option<String>,
    /// True when the copy stopped at the configured size cap.
    #[serde(default)]
    pub truncated: bool,
    /// Set when reading the source failed part-way; the stored bytes are what was read.
    #[serde(default)]
    pub error: Option<String>,
}

/// One item that could not be collected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionError {
    pub collector: String,
    pub item: String,
    pub error: String,
    pub at: DateTime<Utc>,
}

/// Bundle manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub format_version: u32,
    pub tool: String,
    pub tool_version: String,
    pub host: Option<String>,
    pub os: String,
    pub profile: String,
    pub elevated: Option<bool>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub files: Vec<ManifestFile>,
    pub errors: Vec<CollectionError>,
}

struct HashingWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: sha2::Sha256,
    count: u64,
}

impl<W: Write> Write for HashingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Streaming ZIP bundle with a manifest.
pub struct BundleWriter {
    zip: ZipWriter<BufWriter<File>>,
    manifest: Manifest,
    names: BTreeSet<String>,
    /// Size cap per copied file.
    pub max_file_bytes: u64,
}

/// Turn a host path or label into a safe ZIP entry name.
pub fn zip_name(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| match c {
            '\\' => '/',
            ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    while s.starts_with('/') || s.starts_with("./") {
        s = s.trim_start_matches('/').trim_start_matches("./").to_string();
    }
    let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty() && *p != "." && *p != "..").collect();
    if parts.is_empty() {
        "unnamed".to_string()
    } else {
        parts.join("/")
    }
}

impl BundleWriter {
    /// Create the ZIP (refuses to overwrite an existing file).
    pub fn create(path: &Path, profile: &str, max_file_bytes: u64) -> Result<Self> {
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        let manifest = Manifest {
            format: "veritas-triage".into(),
            format_version: 1,
            tool: crate::AGENT_NAME.into(),
            tool_version: crate::AGENT_VERSION.into(),
            host: sysinfo::System::host_name(),
            os: format!("{} {}", std::env::consts::OS, sysinfo::System::long_os_version().unwrap_or_default()),
            profile: profile.into(),
            elevated: None,
            started_at: Utc::now(),
            finished_at: None,
            files: Vec::new(),
            errors: Vec::new(),
        };
        Ok(Self { zip: ZipWriter::new(BufWriter::new(file)), manifest, names: BTreeSet::new(), max_file_bytes })
    }

    pub fn set_elevated(&mut self, elevated: Option<bool>) {
        self.manifest.elevated = elevated;
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn unique_name(&mut self, raw: &str) -> String {
        let base = zip_name(raw);
        let mut name = base.clone();
        let mut n = 1;
        while self.names.contains(&name) || name == MANIFEST_NAME {
            name = format!("{}~{}", base, n);
            n += 1;
        }
        self.names.insert(name.clone());
        name
    }

    /// Record a per-item failure.
    pub fn error(&mut self, collector: &str, item: &str, error: impl ToString) {
        self.manifest.errors.push(CollectionError { collector: collector.into(), item: item.into(), error: error.to_string(), at: Utc::now() });
    }

    /// Store an entry produced by `fill`, hashing what it writes.
    fn add_entry<F>(&mut self, collector: &str, name: &str, source: Option<String>, large: bool, fill: F) -> Result<String>
    where
        F: FnOnce(&mut dyn Write) -> std::result::Result<bool, String>,
    {
        let name = self.unique_name(name);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated).large_file(large);
        self.zip.start_file(name.as_str(), opts)?;
        let mut hw = HashingWriter { inner: &mut self.zip, hasher: sha2::Sha256::new(), count: 0 };
        let result = fill(&mut hw);
        let (sha, size) = (hex::encode(hw.hasher.finalize()), hw.count);
        let (truncated, error) = match result {
            Ok(t) => (t, None),
            Err(e) => (false, Some(e)),
        };
        if let Some(e) = &error {
            self.error(collector, source.as_deref().unwrap_or(&name), e);
        }
        self.manifest.files.push(ManifestFile {
            path: name.clone(),
            sha256: sha,
            size,
            collected_at: Utc::now(),
            collector: collector.into(),
            source,
            truncated,
            error,
        });
        Ok(name)
    }

    /// Store an in-memory buffer.
    pub fn add_bytes(&mut self, collector: &str, name: &str, data: &[u8], source: Option<&str>) -> Result<String> {
        self.add_entry(collector, name, source.map(String::from), data.len() as u64 > u32::MAX as u64, |w| {
            w.write_all(data).map_err(|e| e.to_string())?;
            Ok(false)
        })
    }

    /// Store a value as pretty JSON.
    pub fn add_json<T: Serialize>(&mut self, collector: &str, name: &str, value: &T) -> Result<String> {
        let data = serde_json::to_vec_pretty(value)?;
        self.add_bytes(collector, name, &data, None)
    }

    /// Copy a host file into the bundle (streamed, capped at `max_file_bytes`). Failure to open
    /// the file is recorded as an error and returns `Ok(None)`.
    pub fn add_file(&mut self, collector: &str, name: &str, src: &Path) -> Result<Option<String>> {
        let file = match File::open(src) {
            Ok(f) => f,
            Err(e) => {
                self.error(collector, &src.display().to_string(), e);
                return Ok(None);
            }
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let cap = self.max_file_bytes;
        let name = self.add_entry(collector, name, Some(src.display().to_string()), len > u32::MAX as u64 && cap > u32::MAX as u64, move |w| {
            let mut limited = file.take(cap);
            copy_stream(&mut limited, w)?;
            Ok(len > cap)
        })?;
        Ok(Some(name))
    }

    /// Store bytes produced by a streaming writer callback (used for raw NTFS streams).
    pub fn add_stream<F>(&mut self, collector: &str, name: &str, source: Option<&str>, large: bool, fill: F) -> Result<String>
    where
        F: FnOnce(&mut dyn Write) -> std::result::Result<(), String>,
    {
        self.add_entry(collector, name, source.map(String::from), large, |w| fill(w).map(|_| false))
    }

    /// Copy files from a directory tree. `filter` selects files by path; `max_files` caps the
    /// count. Unreadable directories and files are recorded as errors.
    pub fn add_tree(&mut self, collector: &str, prefix: &str, dir: &Path, recursive: bool, max_files: usize, filter: &dyn Fn(&Path) -> bool) -> Result<usize> {
        let mut stack = vec![dir.to_path_buf()];
        let mut count = 0usize;
        while let Some(d) = stack.pop() {
            let entries = match std::fs::read_dir(&d) {
                Ok(e) => e,
                Err(e) => {
                    self.error(collector, &d.display().to_string(), e);
                    continue;
                }
            };
            let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            paths.sort();
            for p in paths {
                let meta = match std::fs::symlink_metadata(&p) {
                    Ok(m) => m,
                    Err(e) => {
                        self.error(collector, &p.display().to_string(), e);
                        continue;
                    }
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    if recursive {
                        stack.push(p);
                    }
                    continue;
                }
                if !filter(&p) {
                    continue;
                }
                if count >= max_files {
                    self.error(collector, &p.display().to_string(), format!("file limit {} reached", max_files));
                    return Ok(count);
                }
                let rel = p.strip_prefix(dir).map(|r| r.to_string_lossy().into_owned()).unwrap_or_else(|_| p.display().to_string());
                if self.add_file(collector, &format!("{}/{}", prefix, rel), &p)?.is_some() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Write `manifest.json` and close the archive.
    pub fn finish(mut self) -> Result<Manifest> {
        self.manifest.finished_at = Some(Utc::now());
        let data = serde_json::to_vec_pretty(&self.manifest)?;
        self.zip.start_file(MANIFEST_NAME, SimpleFileOptions::default().compression_method(CompressionMethod::Deflated))?;
        self.zip.write_all(&data)?;
        let mut inner = self.zip.finish()?;
        inner.flush()?;
        inner.get_ref().sync_all()?;
        Ok(self.manifest)
    }
}

fn copy_stream(r: &mut dyn Read, w: &mut dyn Write) -> std::result::Result<(), String> {
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read failed: {}", e)),
        };
        w.write_all(&buf[..n]).map_err(|e| format!("write failed: {}", e))?;
    }
}

/// Re-open a bundle and check every manifest entry's SHA-256 against the stored bytes.
pub fn verify_bundle(path: &Path) -> Result<Manifest> {
    let mut zip = zip::ZipArchive::new(File::open(path)?)?;
    let manifest: Manifest = {
        let mut f = zip.by_name(MANIFEST_NAME)?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        serde_json::from_str(&s)?
    };
    for entry in &manifest.files {
        let mut f = zip.by_name(&entry.path)?;
        let mut h = sha2::Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut size = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            size += n as u64;
        }
        let sha = hex::encode(h.finalize());
        if sha != entry.sha256 || size != entry.size {
            return Err(AgentError::Integrity(format!("{}: manifest sha256 {} size {}, stored {} size {}", entry.path, entry.sha256, entry.size, sha, size)));
        }
    }
    if zip.len() != manifest.files.len() + 1 {
        return Err(AgentError::Integrity(format!("archive has {} entries, manifest lists {}", zip.len(), manifest.files.len())));
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_names_are_sanitised() {
        assert_eq!(zip_name(r"C:\Windows\System32\Tasks\x"), "C_/Windows/System32/Tasks/x");
        assert_eq!(zip_name("/etc/../passwd"), "etc/passwd");
        assert_eq!(zip_name(""), "unnamed");
    }

    #[test]
    fn bundle_roundtrip_and_errors() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("a.txt");
        std::fs::write(&src, b"hello world").unwrap();
        let out = dir.path().join("b.zip");
        let mut b = BundleWriter::create(&out, "quick", 5).unwrap();
        b.add_bytes("t", "x/one.txt", b"one", None).unwrap();
        b.add_bytes("t", "x/one.txt", b"two", None).unwrap();
        b.add_file("t", "copied/a.txt", &src).unwrap();
        b.add_file("t", "missing", &dir.path().join("nope")).unwrap();
        let m = b.finish().unwrap();
        assert_eq!(m.files.len(), 3);
        assert_eq!(m.errors.len(), 1);
        assert!(m.files[2].truncated);
        assert_eq!(m.files[2].size, 5);
        let v = verify_bundle(&out).unwrap();
        assert_eq!(v.files, m.files);
    }
}
