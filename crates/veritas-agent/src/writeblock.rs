//! Write-blocker verification before imaging.
//!
//! The check never writes. Evidence gathered:
//! - Windows: whether the device opens for write access at all (a hardware blocker or a
//!   read-only disk attribute makes `CreateFile(GENERIC_WRITE)` fail; opening alone modifies
//!   nothing), plus `Get-Disk | Select IsReadOnly` for `\\.\PhysicalDriveN`.
//! - Linux: `/sys/block/<dev>/ro` and `blockdev --getro`.
//! - Regular files: the read-only attribute / permission bits.
//!
//! `read_only` is `Some(true)` only when a method positively reports read-only, `Some(false)` when
//! the device is demonstrably writable, `None` when nothing conclusive was learned.

use crate::cmd;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBlockStatus {
    pub read_only: Option<bool>,
    /// Methods consulted, `;`-separated.
    pub method: String,
    /// Raw observations backing the conclusion.
    pub evidence: String,
}

/// Disk number of `\\.\PhysicalDriveN`.
pub fn physical_drive_number(path: &str) -> Option<u32> {
    let lower = path.to_ascii_lowercase();
    lower.strip_prefix(r"\\.\physicaldrive").and_then(|n| n.parse().ok())
}

/// Linux block device name (`sdb` for `/dev/sdb`, parent `sdb` for `/dev/sdb1`, `nvme0n1` for
/// `/dev/nvme0n1p2`).
pub fn linux_block_name(path: &str) -> Option<(String, Option<String>)> {
    let name = path.strip_prefix("/dev/")?.to_string();
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let parent = if name.starts_with("nvme") || name.starts_with("mmcblk") || name.starts_with("loop") {
        name.rfind('p').filter(|&i| i > 0 && name[i + 1..].chars().all(|c| c.is_ascii_digit()) && !name[i + 1..].is_empty()).map(|i| name[..i].to_string())
    } else {
        let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
        if trimmed != name && !trimmed.is_empty() {
            Some(trimmed.to_string())
        } else {
            None
        }
    };
    Some((name, parent))
}

/// Check whether `device` is write-protected.
pub fn check(device: &Path) -> WriteBlockStatus {
    let path_s = device.to_string_lossy().into_owned();
    let mut methods = Vec::new();
    let mut evidence = Vec::new();
    let mut verdict: Option<bool> = None;
    let mut merge = |v: Option<bool>| {
        verdict = match (verdict, v) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            _ => None,
        };
    };
    let t = Duration::from_secs(60);

    let meta = std::fs::metadata(device);
    let is_regular_file = meta.as_ref().map(|m| m.is_file()).unwrap_or(false);
    if is_regular_file {
        let ro = meta.as_ref().map(|m| m.permissions().readonly()).unwrap_or(false);
        methods.push("file-permissions".to_string());
        evidence.push(format!("readonly attribute: {}", ro));
        merge(Some(ro));
        return WriteBlockStatus { read_only: verdict, method: methods.join(";"), evidence: evidence.join("; ") };
    }

    match std::env::consts::OS {
        "windows" => {
            methods.push("open-for-write".to_string());
            match std::fs::OpenOptions::new().read(true).write(true).open(device) {
                Ok(_) => {
                    evidence.push("device opened with write access (not write-blocked)".into());
                    merge(Some(false));
                }
                Err(e) if e.raw_os_error() == Some(19) => {
                    // ERROR_WRITE_PROTECT
                    evidence.push(format!("open for write failed with ERROR_WRITE_PROTECT: {}", e));
                    merge(Some(true));
                }
                Err(e) => evidence.push(format!("open for write failed: {} (inconclusive)", e)),
            }
            if let Some(n) = physical_drive_number(&path_s) {
                methods.push("Get-Disk.IsReadOnly".to_string());
                match cmd::powershell(&format!("(Get-Disk -Number {}).IsReadOnly", n), t) {
                    Ok(o) if o.success() => {
                        let s = o.stdout_lossy().trim().to_string();
                        evidence.push(format!("Get-Disk -Number {} IsReadOnly={}", n, s));
                        match s.as_str() {
                            "True" => merge(Some(true)),
                            "False" => merge(Some(false)),
                            _ => {}
                        }
                    }
                    Ok(o) => evidence.push(format!("Get-Disk failed: {}", o.failure_text())),
                    Err(e) => evidence.push(format!("Get-Disk failed: {}", e)),
                }
            }
        }
        "linux" => {
            if let Some((name, parent)) = linux_block_name(&path_s) {
                for n in std::iter::once(name.clone()).chain(parent.clone()) {
                    let sys = match &parent {
                        Some(p) if *p != n => format!("/sys/block/{}/{}/ro", p, n),
                        _ => format!("/sys/block/{}/ro", n),
                    };
                    if let Ok(v) = std::fs::read_to_string(&sys) {
                        methods.push(sys.clone());
                        evidence.push(format!("{}={}", sys, v.trim()));
                        merge(Some(v.trim() == "1"));
                    }
                }
            }
            methods.push("blockdev --getro".to_string());
            match cmd::run("blockdev", &["--getro", path_s.as_str()], t) {
                Ok(o) if o.success() => {
                    let s = o.stdout_lossy().trim().to_string();
                    evidence.push(format!("blockdev --getro={}", s));
                    merge(Some(s == "1"));
                }
                Ok(o) => evidence.push(format!("blockdev failed: {}", o.failure_text())),
                Err(e) => evidence.push(format!("blockdev failed: {}", e)),
            }
        }
        _ => {
            methods.push("diskutil info".to_string());
            match cmd::run("diskutil", &["info", path_s.as_str()], t) {
                Ok(o) if o.success() => {
                    let text = o.stdout_lossy();
                    for line in text.lines() {
                        let l = line.trim();
                        if l.starts_with("Media Read-Only:") || l.starts_with("Read-Only Media:") {
                            evidence.push(l.to_string());
                            merge(Some(l.ends_with("Yes")));
                        }
                    }
                }
                Ok(o) => evidence.push(format!("diskutil failed: {}", o.failure_text())),
                Err(e) => evidence.push(format!("diskutil failed: {}", e)),
            }
        }
    }
    if methods.is_empty() {
        methods.push("none".into());
    }
    WriteBlockStatus { read_only: verdict, method: methods.join(";"), evidence: evidence.join("; ") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_name_parsing() {
        assert_eq!(physical_drive_number(r"\\.\PhysicalDrive2"), Some(2));
        assert_eq!(physical_drive_number(r"\\.\C:"), None);
        assert_eq!(linux_block_name("/dev/sdb1"), Some(("sdb1".into(), Some("sdb".into()))));
        assert_eq!(linux_block_name("/dev/sdb"), Some(("sdb".into(), None)));
        assert_eq!(linux_block_name("/dev/nvme0n1p2"), Some(("nvme0n1p2".into(), Some("nvme0n1".into()))));
        assert_eq!(linux_block_name("/dev/nvme0n1"), Some(("nvme0n1".into(), None)));
        assert_eq!(linux_block_name("/tmp/x"), None);
    }

    #[test]
    fn checks_never_panic() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("img.bin");
        std::fs::write(&f, b"data").unwrap();
        let s = check(&f);
        assert_eq!(s.read_only, Some(false));
        let mut perms = std::fs::metadata(&f).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&f, perms).unwrap();
        assert_eq!(check(&f).read_only, Some(true));
        let missing = check(&dir.path().join("does-not-exist"));
        assert!(!missing.method.is_empty());
        let mut perms = std::fs::metadata(&f).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&f, perms).unwrap();
    }
}
