//! Running external commands with a timeout and full output capture.

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Captured result of an external command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdOutput {
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    #[serde(skip)]
    pub stdout: Vec<u8>,
    #[serde(skip)]
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
    /// Short description of a failure for error records.
    pub fn failure_text(&self) -> String {
        let err = self.stderr_lossy();
        let err = err.trim();
        let out = self.stdout_lossy();
        let detail = if err.is_empty() {
            out.trim().chars().take(400).collect::<String>()
        } else {
            err.chars().take(400).collect()
        };
        if self.timed_out {
            format!("{} timed out", self.program)
        } else {
            format!(
                "{} exited with {:?}: {}",
                self.program, self.exit_code, detail
            )
        }
    }
}

/// Run `program args...`, wait at most `timeout`, capture stdout and stderr. A command that
/// cannot be started yields `Err` with the spawn error text.
pub fn run<S: AsRef<OsStr>>(
    program: &str,
    args: &[S],
    timeout: Duration,
) -> Result<CmdOutput, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {}: {}", program, e))?;
    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    // Drain both pipes on threads so a chatty child cannot deadlock on a full pipe.
    let out_thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut v);
        }
        v
    });
    let err_thread = std::thread::spawn(move || {
        let mut v = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut v);
        }
        v
    });
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("waiting for {}: {}", program, e)),
        }
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    Ok(CmdOutput {
        program: program.to_string(),
        args: args
            .iter()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .collect(),
        exit_code: status.and_then(|s| s.code()),
        stdout,
        stderr,
        timed_out,
    })
}

/// Run a Windows PowerShell script block non-interactively.
pub fn powershell(script: &str, timeout: Duration) -> Result<CmdOutput, String> {
    run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_program_is_an_error_not_a_panic() {
        assert!(run(
            "definitely-not-a-real-program-xyz",
            &["a"],
            Duration::from_secs(5)
        )
        .is_err());
    }

    #[test]
    fn captures_output() {
        let out = if cfg!(windows) {
            run("cmd", &["/C", "echo hello"], Duration::from_secs(20)).unwrap()
        } else {
            run("sh", &["-c", "echo hello"], Duration::from_secs(20)).unwrap()
        };
        assert!(out.success());
        assert!(out.stdout_lossy().contains("hello"));
    }
}
