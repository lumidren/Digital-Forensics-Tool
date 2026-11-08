//! Resumable evidence upload over HTTPS with mutual TLS.
//!
//! Protocol (JSON bodies):
//! - `POST /api/v1/intake/sessions` with the manifest (evidence id, segments with size and
//!   SHA-256) returns `{"session_id": ...}`.
//! - `GET /api/v1/intake/sessions/{id}` returns `{"segments": [{"index", "size", "sha256"}]}` for
//!   the segments the server already holds; only those whose hash matches the manifest count.
//! - `PUT /api/v1/intake/sessions/{id}/segments/{n}` streams one segment with an
//!   `X-Segment-SHA256` header; the server recomputes and rejects a mismatch.
//! - `POST /api/v1/intake/sessions/{id}/complete` closes the session.
//!
//! The session id is kept in a small state file so an interrupted upload resumes in a later run.
//! TLS uses the platform stack through `native-tls` (SChannel, Secure Transport, OpenSSL). The
//! client identity is a PEM certificate chain plus a PKCS#8 PEM private key; only the given CA
//! is trusted (built-in roots are disabled), which pins the intake server's issuing CA.

use crate::{AgentError, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadSegment {
    pub index: u32,
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Upload manifest written by `veritas-agent image` next to the image (`<base>.manifest.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadManifest {
    pub evidence_id: String,
    pub case_id: Option<String>,
    pub segments: Vec<UploadSegment>,
    /// Image format of the segments (`e01`, `aff4` or `raw`), when written by `image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

impl UploadManifest {
    pub fn from_segments(
        evidence_id: &str,
        case_id: Option<&str>,
        segs: &[crate::image::SegmentInfo],
    ) -> Self {
        Self {
            evidence_id: evidence_id.to_string(),
            case_id: case_id.map(String::from),
            segments: segs
                .iter()
                .enumerate()
                .map(|(i, s)| UploadSegment {
                    index: i as u32,
                    name: s
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    path: s.path.clone(),
                    size: s.size,
                    sha256: s.sha256.clone(),
                })
                .collect(),
            format: None,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    /// Segment paths are resolved relative to the manifest's directory when not absolute.
    pub fn resolve_paths(&mut self, manifest_path: &Path) {
        let dir = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        for s in &mut self.segments {
            if s.path.is_relative() && !s.path.exists() {
                s.path = dir.join(&s.path);
            }
        }
    }

    fn digest(&self) -> String {
        veritas_hash::sha256_hex(serde_json::to_string(self).unwrap_or_default().as_bytes())
    }
}

/// Client certificate material (PEM files).
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub ca: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadState {
    server: String,
    manifest_sha256: String,
    session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadReport {
    pub session_id: String,
    pub uploaded: Vec<u32>,
    pub skipped: Vec<u32>,
    pub completed: bool,
}

#[derive(Deserialize)]
struct SessionCreated {
    session_id: String,
}

#[derive(Deserialize)]
struct RemoteSegment {
    index: u32,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
struct SessionStatus {
    #[serde(default)]
    segments: Vec<RemoteSegment>,
}

pub struct UploadClient {
    agent: ureq::Agent,
    base: String,
    /// In-run attempts per segment before giving up (state is kept for a later run).
    pub retries: u32,
}

fn http_err(e: ureq::Error) -> AgentError {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            AgentError::Http(format!(
                "HTTP {}: {}",
                code,
                body.chars().take(300).collect::<String>()
            ))
        }
        ureq::Error::Transport(t) => AgentError::Http(format!("transport: {}", t)),
    }
}

impl UploadClient {
    /// Build a client for `server` (`https://host[:port]`). HTTPS requires `tls`; plain `http://`
    /// is accepted only for loopback test servers.
    pub fn new(server: &str, tls: Option<&TlsConfig>) -> Result<Self> {
        let base = server.trim_end_matches('/').to_string();
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(120))
            .timeout_write(Duration::from_secs(600))
            .max_idle_connections(0);
        if base.starts_with("https://") {
            let tls = tls.ok_or_else(|| {
                AgentError::Tls("https upload requires --client-cert, --client-key and --ca".into())
            })?;
            let cert = std::fs::read(&tls.client_cert)?;
            let key = std::fs::read(&tls.client_key)?;
            let ca = std::fs::read(&tls.ca)?;
            let identity = native_tls::Identity::from_pkcs8(&cert, &key).map_err(|e| {
                // SChannel imports only RSA PKCS#8 keys; OpenSSL and Secure Transport also take EC.
                let hint = if cfg!(windows) {
                    " (on Windows the client key must be RSA)"
                } else {
                    ""
                };
                AgentError::Tls(format!("client identity: {}{}", e, hint))
            })?;
            let ca = native_tls::Certificate::from_pem(&ca)
                .map_err(|e| AgentError::Tls(format!("CA certificate: {}", e)))?;
            let connector = native_tls::TlsConnector::builder()
                .identity(identity) // THREAT:T8.1 per-engagement client certificate presented on every connection (mTLS)
                .add_root_certificate(ca)
                .disable_built_in_roots(true)
                .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
                .build()
                .map_err(|e| AgentError::Tls(e.to_string()))?;
            builder = builder.tls_connector(Arc::new(connector));
        } else if base.starts_with("http://") {
            let host = base.trim_start_matches("http://");
            if !(host.starts_with("127.0.0.1")
                || host.starts_with("localhost")
                || host.starts_with("[::1]"))
            {
                return Err(AgentError::Tls(
                    "plain http is only allowed to a loopback address".into(),
                ));
            }
        } else {
            return Err(AgentError::Invalid(format!(
                "unsupported server URL {}",
                server
            )));
        }
        Ok(Self {
            agent: builder.build(),
            base,
            retries: 3,
        })
    }

    fn create_session(&self, m: &UploadManifest) -> Result<String> {
        let body = serde_json::json!({
            "evidence_id": m.evidence_id,
            "case_id": m.case_id,
            "segments": m.segments.iter().map(|s| serde_json::json!({"index": s.index, "name": s.name, "size": s.size, "sha256": s.sha256})).collect::<Vec<_>>(),
        });
        let resp = self
            .agent
            .post(&format!("{}/api/v1/intake/sessions", self.base))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(http_err)?;
        let created: SessionCreated = serde_json::from_reader(resp.into_reader())?;
        if created.session_id.is_empty()
            || !created
                .session_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AgentError::Http(
                "server returned an invalid session id".into(),
            ));
        }
        Ok(created.session_id)
    }

    /// Segment indices the server already holds with the manifest's hash; `None` if the session
    /// is unknown to the server.
    fn present(&self, session: &str, m: &UploadManifest) -> Result<Option<Vec<u32>>> {
        match self
            .agent
            .get(&format!("{}/api/v1/intake/sessions/{}", self.base, session))
            .call()
        {
            Ok(resp) => {
                let st: SessionStatus = serde_json::from_reader(resp.into_reader())?;
                Ok(Some(
                    st.segments
                        .iter()
                        .filter(|r| {
                            m.segments.iter().any(|s| {
                                s.index == r.index
                                    && s.size == r.size
                                    && s.sha256.eq_ignore_ascii_case(&r.sha256)
                            })
                        })
                        .map(|r| r.index)
                        .collect(),
                ))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(http_err(e)),
        }
    }

    fn put_segment(&self, session: &str, s: &UploadSegment) -> Result<()> {
        // The segment is re-hashed locally and must match the manifest before it is sent; the
        // server recomputes the hash from the body and rejects any mismatch.
        let actual = crate::sha256_file(&s.path)?;
        let size = std::fs::metadata(&s.path)?.len();
        if !actual.eq_ignore_ascii_case(&s.sha256) || size != s.size {
            // THREAT:T8.2 segment hash check
            return Err(AgentError::Integrity(format!(
                "{}: sha256 {} size {} does not match manifest {} size {}",
                s.path.display(),
                actual,
                size,
                s.sha256,
                s.size
            )));
        }
        let file = std::fs::File::open(&s.path)?;
        self.agent
            .put(&format!(
                "{}/api/v1/intake/sessions/{}/segments/{}",
                self.base, session, s.index
            ))
            .set("Content-Type", "application/octet-stream")
            .set("Content-Length", &s.size.to_string())
            .set("X-Segment-SHA256", &s.sha256)
            .send(file.take(s.size))
            .map_err(http_err)?;
        Ok(())
    }

    fn complete(&self, session: &str) -> Result<()> {
        self.agent
            .post(&format!(
                "{}/api/v1/intake/sessions/{}/complete",
                self.base, session
            ))
            .set("Content-Type", "application/json")
            .send_string("{}")
            .map_err(http_err)?;
        Ok(())
    }

    /// Upload every segment the server does not yet hold, resuming a session recorded in
    /// `state_path` when it belongs to the same server and manifest.
    pub fn upload(
        &self,
        m: &UploadManifest,
        state_path: Option<&Path>,
        progress: &mut dyn FnMut(u32, &str),
    ) -> Result<UploadReport> {
        let digest = m.digest();
        let saved: Option<UploadState> = state_path
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok());
        let mut session = saved
            .filter(|s| s.server == self.base && s.manifest_sha256 == digest)
            .map(|s| s.session_id);
        let mut present = match &session {
            Some(id) => self.present(id, m)?,
            None => None,
        };
        if present.is_none() {
            let id = self.create_session(m)?;
            if let Some(p) = state_path {
                let st = UploadState {
                    server: self.base.clone(),
                    manifest_sha256: digest.clone(),
                    session_id: id.clone(),
                };
                std::fs::write(p, serde_json::to_vec_pretty(&st)?)?;
            }
            present = self.present(&id, m)?.or(Some(Vec::new()));
            session = Some(id);
        }
        let session = session.ok_or_else(|| AgentError::Http("no session".into()))?;
        let mut present = present.unwrap_or_default();
        let mut report = UploadReport {
            session_id: session.clone(),
            uploaded: Vec::new(),
            skipped: present.clone(),
            completed: false,
        };
        for s in &m.segments {
            if present.contains(&s.index) {
                progress(s.index, "already present");
                continue;
            }
            let mut attempt = 0;
            loop {
                attempt += 1;
                progress(s.index, "uploading");
                match self.put_segment(&session, s) {
                    Ok(()) => {
                        report.uploaded.push(s.index);
                        progress(s.index, "uploaded");
                        break;
                    }
                    Err(e @ AgentError::Integrity(_)) => return Err(e),
                    Err(e) if attempt >= self.retries.max(1) => return Err(e),
                    Err(_) => {
                        // Connection lost: learn what arrived before retrying.
                        std::thread::sleep(Duration::from_millis(200 * attempt as u64));
                        if let Ok(Some(p)) = self.present(&session, m) {
                            present = p;
                            if present.contains(&s.index) {
                                report.uploaded.push(s.index);
                                break;
                            }
                        }
                    }
                }
            }
        }
        self.complete(&session)?;
        report.completed = true;
        if let Some(p) = state_path {
            let _ = std::fs::remove_file(p);
        }
        Ok(report)
    }
}
