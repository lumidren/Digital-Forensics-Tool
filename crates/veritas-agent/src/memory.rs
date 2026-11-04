//! Physical memory capture through WinPmem (Windows), LiME (Linux) or osxpmem (macOS).
//!
//! The agent locates the tool, records the SHA-256 of the tool binary and of the kernel driver
//! it loads (WinPmem and osxpmem embed their driver in the binary, so the binary hash is the
//! driver hash; for LiME the driver is the `lime.ko` module), runs it with the documented
//! arguments, then hashes the capture. The command runner is a trait so tests run without the
//! tools installed.

use crate::{AgentError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use veritas_hash::Hashes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTool {
    WinPmem,
    Lime,
    OsxPmem,
}

impl MemoryTool {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "winpmem" => Some(Self::WinPmem),
            "lime" => Some(Self::Lime),
            "osxpmem" => Some(Self::OsxPmem),
            _ => None,
        }
    }

    /// File names searched for in the configured directory, the agent's directory and `PATH`.
    pub fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::WinPmem => &["winpmem_mini_x64_rc2.exe", "winpmem_mini_x64.exe", "winpmem_mini_x86.exe", "winpmem.exe", "go-winpmem.exe", "go-winpmem_amd64.exe"],
            Self::Lime => &["lime.ko"],
            Self::OsxPmem => &["osxpmem", "osxpmem.app/osxpmem"],
        }
    }

    pub fn default_for_os() -> Option<Self> {
        match std::env::consts::OS {
            "windows" => Some(Self::WinPmem),
            "linux" => Some(Self::Lime),
            "macos" => Some(Self::OsxPmem),
            _ => None,
        }
    }
}

/// Output of one external command.
#[derive(Debug, Clone, Default)]
pub struct RunOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Executes external programs; replaced by a mock in tests.
pub trait CommandRunner {
    fn run(&self, program: &Path, args: &[OsString]) -> std::io::Result<RunOutput>;
}

/// Runs programs with `std::process::Command`.
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &Path, args: &[OsString]) -> std::io::Result<RunOutput> {
        let out = std::process::Command::new(program).args(args).stdin(std::process::Stdio::null()).output()?;
        Ok(RunOutput { exit_code: out.status.code(), stdout: out.stdout, stderr: out.stderr })
    }
}

#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub tool: MemoryTool,
    /// Explicit tool path (binary, or `lime.ko`); searched for when `None`.
    pub binary: Option<PathBuf>,
    pub output: PathBuf,
    /// Extra arguments appended to the tool's own.
    pub extra_args: Vec<String>,
}

/// Record of a capture, suitable for the ledger entry details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCapture {
    pub tool: MemoryTool,
    pub binary_path: String,
    pub binary_sha256: String,
    pub driver_path: String,
    pub driver_sha256: String,
    pub command_lines: Vec<String>,
    pub exit_code: Option<i32>,
    pub output: String,
    pub hashes: Hashes,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub os: String,
    pub kernel_version: Option<String>,
    pub stderr_tail: String,
}

/// Locate the tool: explicit path, then the agent's directory, then each `PATH` entry.
pub fn locate_binary(tool: MemoryTool, configured: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = configured {
        return if p.is_file() { Ok(p.to_path_buf()) } else { Err(AgentError::ToolNotFound(p.display().to_string())) };
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            dirs.push(d.to_path_buf());
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    if tool == MemoryTool::Lime {
        if let Some(k) = sysinfo::System::kernel_version() {
            dirs.push(PathBuf::from(format!("/lib/modules/{}/extra", k)));
        }
    }
    for d in dirs {
        for c in tool.candidates() {
            let p = d.join(c);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err(AgentError::ToolNotFound(format!("{:?}: none of {:?} found in the agent directory or PATH", tool, tool.candidates())))
}

fn tail(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let start = s.len().saturating_sub(2000);
    s.get(start..).unwrap_or("").to_string()
}

fn render(program: &Path, args: &[OsString]) -> String {
    let mut s = program.display().to_string();
    for a in args {
        s.push(' ');
        s.push_str(&a.to_string_lossy());
    }
    s
}

/// Capture memory with the configured tool and hash the result. The output file must not exist.
pub fn capture(cfg: &MemoryConfig, runner: &dyn CommandRunner) -> Result<MemoryCapture> {
    if cfg.output.exists() {
        return Err(AgentError::Invalid(format!("refusing to overwrite {}", cfg.output.display())));
    }
    let binary = locate_binary(cfg.tool, cfg.binary.as_deref())?;
    let binary_sha256 = crate::sha256_file(&binary)?;
    let out_s: OsString = cfg.output.clone().into_os_string();
    let extra: Vec<OsString> = cfg.extra_args.iter().map(OsString::from).collect();
    let started_at = Utc::now();
    let mut command_lines = Vec::new();
    let (exit_code, stderr) = match cfg.tool {
        MemoryTool::WinPmem => {
            // winpmem_mini: `winpmem_mini_x64.exe <output>`; go-winpmem: `go-winpmem acquire <output>`.
            let go = binary.file_name().map(|n| n.to_string_lossy().starts_with("go-winpmem")).unwrap_or(false);
            let mut args = Vec::new();
            if go {
                args.push(OsString::from("acquire"));
            }
            args.push(out_s.clone());
            args.extend(extra);
            command_lines.push(render(&binary, &args));
            let o = runner.run(&binary, &args)?;
            (o.exit_code, o.stderr)
        }
        MemoryTool::OsxPmem => {
            let mut args = vec![OsString::from("--format"), OsString::from("raw"), OsString::from("-o"), out_s.clone()];
            args.extend(extra);
            command_lines.push(render(&binary, &args));
            let o = runner.run(&binary, &args)?;
            (o.exit_code, o.stderr)
        }
        MemoryTool::Lime => {
            let insmod = PathBuf::from("insmod");
            let mut param = OsString::from("path=");
            param.push(&out_s);
            param.push(" format=lime");
            let mut args = vec![binary.clone().into_os_string(), param];
            args.extend(extra);
            command_lines.push(render(&insmod, &args));
            let o = runner.run(&insmod, &args)?;
            // LiME writes the capture during module init; unload it afterwards either way.
            let rm_args = vec![OsString::from("lime")];
            command_lines.push(render(Path::new("rmmod"), &rm_args));
            let rm = runner.run(Path::new("rmmod"), &rm_args);
            let mut stderr = o.stderr;
            if let Ok(r) = rm {
                stderr.extend_from_slice(&r.stderr);
            }
            (o.exit_code, stderr)
        }
    };
    if exit_code != Some(0) {
        return Err(AgentError::ToolFailed(format!("{} exited with {:?}: {}", command_lines[0], exit_code, tail(&stderr))));
    }
    let meta = std::fs::metadata(&cfg.output).map_err(|e| AgentError::ToolFailed(format!("no capture written to {}: {}", cfg.output.display(), e)))?;
    if meta.len() == 0 {
        return Err(AgentError::ToolFailed(format!("capture {} is empty", cfg.output.display())));
    }
    let hashes = veritas_hash::hash_reader(std::fs::File::open(&cfg.output)?, |_| {})?;
    Ok(MemoryCapture {
        tool: cfg.tool,
        binary_path: binary.display().to_string(),
        driver_path: binary.display().to_string(),
        driver_sha256: binary_sha256.clone(),
        binary_sha256,
        command_lines,
        exit_code,
        output: cfg.output.display().to_string(),
        hashes,
        started_at,
        finished_at: Utc::now(),
        os: std::env::consts::OS.to_string(),
        kernel_version: sysinfo::System::kernel_version(),
        stderr_tail: tail(&stderr),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Pretends to be the tool: writes a fake image to the output path found in the arguments.
    struct Mock {
        calls: RefCell<Vec<String>>,
        fail: bool,
    }

    impl CommandRunner for Mock {
        fn run(&self, program: &Path, args: &[OsString]) -> std::io::Result<RunOutput> {
            self.calls.borrow_mut().push(render(program, args));
            if self.fail {
                return Ok(RunOutput { exit_code: Some(1), stdout: vec![], stderr: b"driver load failed".to_vec() });
            }
            for a in args {
                let s = a.to_string_lossy();
                let path = s.strip_prefix("path=").map(|p| p.trim_end_matches(" format=lime").to_string()).unwrap_or_else(|| s.to_string());
                if path.ends_with(".raw") || path.ends_with(".lime") {
                    std::fs::write(&path, vec![0x5au8; 1 << 16])?;
                }
            }
            Ok(RunOutput { exit_code: Some(0), stdout: vec![], stderr: vec![] })
        }
    }

    #[test]
    fn winpmem_capture_is_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("winpmem_mini_x64_rc2.exe");
        std::fs::write(&bin, b"fake winpmem").unwrap();
        let out = dir.path().join("mem.raw");
        let mock = Mock { calls: RefCell::new(vec![]), fail: false };
        let cfg = MemoryConfig { tool: MemoryTool::WinPmem, binary: Some(bin.clone()), output: out.clone(), extra_args: vec![] };
        let cap = capture(&cfg, &mock).unwrap();
        assert_eq!(cap.hashes, veritas_hash::hash_bytes(&vec![0x5au8; 1 << 16]));
        assert_eq!(cap.binary_sha256, veritas_hash::sha256_hex(b"fake winpmem"));
        assert_eq!(cap.driver_sha256, cap.binary_sha256);
        assert_eq!(mock.calls.borrow().len(), 1);
        assert!(mock.calls.borrow()[0].ends_with("mem.raw"));
        // Refuses to overwrite.
        assert!(capture(&cfg, &mock).is_err());
    }

    #[test]
    fn lime_loads_and_unloads_module() {
        let dir = tempfile::tempdir().unwrap();
        let ko = dir.path().join("lime.ko");
        std::fs::write(&ko, b"fake module").unwrap();
        let out = dir.path().join("mem.lime");
        let mock = Mock { calls: RefCell::new(vec![]), fail: false };
        let cfg = MemoryConfig { tool: MemoryTool::Lime, binary: Some(ko), output: out, extra_args: vec![] };
        let cap = capture(&cfg, &mock).unwrap();
        let calls = mock.calls.borrow();
        assert!(calls[0].starts_with("insmod"));
        assert!(calls[0].contains("format=lime"));
        assert_eq!(calls[1], "rmmod lime");
        assert_eq!(cap.driver_sha256, veritas_hash::sha256_hex(b"fake module"));
    }

    #[test]
    fn tool_failure_and_missing_tool_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("osxpmem");
        std::fs::write(&bin, b"x").unwrap();
        let mock = Mock { calls: RefCell::new(vec![]), fail: true };
        let cfg = MemoryConfig { tool: MemoryTool::OsxPmem, binary: Some(bin), output: dir.path().join("m.raw"), extra_args: vec![] };
        assert!(matches!(capture(&cfg, &mock), Err(AgentError::ToolFailed(_))));
        let cfg = MemoryConfig { tool: MemoryTool::OsxPmem, binary: Some(dir.path().join("absent")), output: dir.path().join("n.raw"), extra_args: vec![] };
        assert!(matches!(capture(&cfg, &mock), Err(AgentError::ToolNotFound(_))));
    }
}
