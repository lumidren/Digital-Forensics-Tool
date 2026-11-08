//! Upload protocol tests against an in-process HTTP/1.1 intake server that can drop a
//! connection half-way through a segment upload.

use sha2::Digest;
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use veritas_agent::transfer::{UploadClient, UploadManifest, UploadSegment};
use veritas_agent::AgentError;

#[derive(Default)]
struct Session {
    manifest: BTreeMap<u32, (u64, String)>,
    received: BTreeMap<u32, (u64, String)>,
    completed: bool,
}

#[derive(Default)]
struct ServerState {
    sessions: HashMap<String, Session>,
    created: u32,
    puts: BTreeMap<u32, u32>,
    rejected: u32,
    /// Segment indices whose next PUT is cut off after half the body.
    drop_next_put: Vec<u32>,
}

type Shared = Arc<Mutex<ServerState>>;

fn respond(stream: &mut TcpStream, code: u16, body: &str) {
    let reason = match code {
        200 => "OK",
        201 => "Created",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        _ => "Error",
    };
    let msg = format!("HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", code, reason, body.len(), body);
    let _ = stream.write_all(msg.as_bytes());
    let _ = stream.flush();
}

fn handle(mut stream: TcpStream, state: Shared) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    assert!(
        !headers.contains_key("transfer-encoding"),
        "client must send Content-Length"
    );
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let (method, path) = (parts[0], parts[1]);
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    if method == "PUT" && segs.len() == 7 && segs[5] == "segments" {
        let idx: u32 = segs[6].parse().unwrap();
        let drop_now = {
            let mut st = state.lock().unwrap();
            *st.puts.entry(idx).or_default() += 1;
            if let Some(pos) = st.drop_next_put.iter().position(|&i| i == idx) {
                st.drop_next_put.remove(pos);
                true
            } else {
                false
            }
        };
        if drop_now {
            let mut half = vec![0u8; len / 2];
            let _ = reader.read_exact(&mut half);
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        let mut body = vec![0u8; len];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let sha = hex::encode(sha2::Sha256::digest(&body));
        let claimed = headers.get("x-segment-sha256").cloned().unwrap_or_default();
        let mut st = state.lock().unwrap();
        let ok = {
            let Some(sess) = st.sessions.get_mut(segs[4]) else {
                drop(st);
                return respond(&mut stream, 404, "{}");
            };
            let expected = sess.manifest.get(&idx).cloned();
            if claimed == sha && expected == Some((len as u64, sha.clone())) {
                sess.received.insert(idx, (len as u64, sha));
                true
            } else {
                false
            }
        };
        if ok {
            drop(st);
            respond(&mut stream, 201, "{}");
        } else {
            st.rejected += 1;
            drop(st);
            respond(&mut stream, 422, "{\"error\":\"segment hash mismatch\"}");
        }
        return;
    }

    let mut body = vec![0u8; len];
    let _ = reader.read_exact(&mut body);
    let mut st = state.lock().unwrap();
    match (method, segs.len()) {
        ("POST", 4) => {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            st.created += 1;
            let id = format!("sess-{}", st.created);
            let mut sess = Session::default();
            for s in v["segments"].as_array().unwrap() {
                sess.manifest.insert(
                    s["index"].as_u64().unwrap() as u32,
                    (
                        s["size"].as_u64().unwrap(),
                        s["sha256"].as_str().unwrap().to_string(),
                    ),
                );
            }
            st.sessions.insert(id.clone(), sess);
            drop(st);
            respond(&mut stream, 201, &format!("{{\"session_id\":\"{}\"}}", id));
        }
        ("GET", 5) => {
            let id = segs[4];
            match st.sessions.get(id) {
                Some(sess) => {
                    let list: Vec<_> = sess
                        .received
                        .iter()
                        .map(
                            |(i, (sz, h))| serde_json::json!({"index": i, "size": sz, "sha256": h}),
                        )
                        .collect();
                    let b = serde_json::json!({ "session_id": id, "segments": list, "complete": sess.completed }).to_string();
                    drop(st);
                    respond(&mut stream, 200, &b);
                }
                None => {
                    drop(st);
                    respond(&mut stream, 404, "{}");
                }
            }
        }
        ("POST", 6) if segs[5] == "complete" => {
            let id = segs[4].to_string();
            let all = match st.sessions.get_mut(&id) {
                Some(sess) if sess.manifest.keys().all(|k| sess.received.contains_key(k)) => {
                    sess.completed = true;
                    true
                }
                _ => false,
            };
            drop(st);
            if all {
                respond(&mut stream, 200, "{\"complete\":true}");
            } else {
                respond(&mut stream, 422, "{\"error\":\"missing segments\"}");
            }
        }
        _ => {
            drop(st);
            respond(&mut stream, 404, "{}");
        }
    }
}

fn start_server(state: Shared) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let st = state.clone();
            std::thread::spawn(move || handle(s, st));
        }
    });
    format!("http://{}", addr)
}

fn make_manifest(dir: &Path, n: u32, size: usize) -> UploadManifest {
    let mut segments = Vec::new();
    for i in 0..n {
        let data: Vec<u8> = (0..size)
            .map(|j| ((j * 31 + i as usize * 7) % 251) as u8)
            .collect();
        let path = dir.join(format!("img.{:03}", i));
        std::fs::write(&path, &data).unwrap();
        segments.push(UploadSegment {
            index: i,
            name: format!("img.{:03}", i),
            path,
            size: size as u64,
            sha256: hex::encode(sha2::Sha256::digest(&data)),
        });
    }
    UploadManifest {
        evidence_id: "EV-1".into(),
        case_id: Some("CASE-1".into()),
        segments,
        format: None,
    }
}

#[test]
fn dropped_connection_resumes_in_a_later_run() {
    let dir = tempfile::tempdir().unwrap();
    let state: Shared = Arc::default();
    state.lock().unwrap().drop_next_put.push(1);
    let url = start_server(state.clone());
    let m = make_manifest(dir.path(), 3, 3 * 1024 * 1024);
    let state_file = dir.path().join("upload-state.json");
    let mut client = UploadClient::new(&url, None).unwrap();
    client.retries = 1;
    let first = client.upload(&m, Some(&state_file), &mut |_, _| {});
    assert!(matches!(first, Err(AgentError::Http(_))), "{:?}", first);
    assert!(state_file.exists());
    let second = client
        .upload(&m, Some(&state_file), &mut |_, _| {})
        .unwrap();
    assert!(second.completed);
    assert_eq!(second.skipped, vec![0]);
    assert_eq!(second.uploaded, vec![1, 2]);
    let st = state.lock().unwrap();
    assert_eq!(st.created, 1, "the second run must reuse the session");
    assert_eq!(st.puts.get(&0), Some(&1));
    assert_eq!(st.puts.get(&1), Some(&2));
    assert_eq!(st.puts.get(&2), Some(&1));
    assert!(st.sessions["sess-1"].completed);
    assert!(!state_file.exists());
}

#[test]
fn dropped_connection_is_retried_within_a_run() {
    let dir = tempfile::tempdir().unwrap();
    let state: Shared = Arc::default();
    state.lock().unwrap().drop_next_put.push(2);
    let url = start_server(state.clone());
    let m = make_manifest(dir.path(), 3, 512 * 1024);
    let client = UploadClient::new(&url, None).unwrap();
    let report = client.upload(&m, None, &mut |_, _| {}).unwrap();
    assert!(report.completed);
    assert_eq!(report.uploaded, vec![0, 1, 2]);
    assert_eq!(state.lock().unwrap().puts.get(&2), Some(&2));
}

#[test]
fn segment_hash_mismatch_is_never_sent() {
    let dir = tempfile::tempdir().unwrap();
    let state: Shared = Arc::default();
    let url = start_server(state.clone());
    let mut m = make_manifest(dir.path(), 2, 4096);
    m.segments[1].sha256 = "00".repeat(32);
    let client = UploadClient::new(&url, None).unwrap();
    let r = client.upload(&m, None, &mut |_, _| {});
    assert!(matches!(r, Err(AgentError::Integrity(_))), "{:?}", r);
    let st = state.lock().unwrap();
    assert_eq!(st.puts.get(&1), None);
    assert_eq!(st.rejected, 0);
}

#[test]
fn server_rejects_tampered_body() {
    // A file modified after the manifest was written fails the local check first; the server-side
    // check is exercised by claiming a hash the body does not have.
    let dir = tempfile::tempdir().unwrap();
    let state: Shared = Arc::default();
    let url = start_server(state.clone());
    let m = make_manifest(dir.path(), 1, 4096);
    let agent = ureq::agent();
    let created: serde_json::Value = serde_json::from_reader(
        agent
            .post(&format!("{}/api/v1/intake/sessions", url))
            .send_string(&serde_json::json!({"evidence_id": "x", "segments": [{"index": 0, "size": 4096, "sha256": m.segments[0].sha256}]}).to_string())
            .unwrap()
            .into_reader(),
    )
    .unwrap();
    let id = created["session_id"].as_str().unwrap();
    let r = agent
        .put(&format!("{}/api/v1/intake/sessions/{}/segments/0", url, id))
        .set("X-Segment-SHA256", &m.segments[0].sha256)
        .send_bytes(&vec![0u8; 4096]);
    assert!(matches!(r, Err(ureq::Error::Status(422, _))));
}

#[test]
fn https_requires_client_identity_and_plain_http_only_on_loopback() {
    assert!(matches!(
        UploadClient::new("https://intake.example", None),
        Err(AgentError::Tls(_))
    ));
    assert!(matches!(
        UploadClient::new("http://intake.example", None),
        Err(AgentError::Tls(_))
    ));
    assert!(UploadClient::new("http://127.0.0.1:9", None).is_ok());
}
