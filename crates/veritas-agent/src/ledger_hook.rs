//! Custody-ledger entry for an acquisition: hashes, device description, trusted time, tool
//! identity (binary SHA-256 and full command line), signed with the operator key.

use crate::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use veritas_hash::Hashes;
use veritas_ledger::keys::ExaminerKey;
use veritas_ledger::{DeviceInfo, Entry, EntryKind, Ledger, NewEntry, TimeSource, ToolInfo};

/// Default SNTP servers, tried in order.
pub const NTP_SERVERS: &[&str] = &["time.nist.gov", "pool.ntp.org"];
/// `uncertainty_ms` value meaning "unknown" (no reference clock reached).
pub const UNCERTAINTY_UNKNOWN: u64 = u64::MAX;

/// Seconds between 1900-01-01 (NTP era 0) and 1970-01-01.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

fn to_ntp(t: SystemTime) -> u64 {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() + NTP_UNIX_OFFSET;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// NTP timestamp to milliseconds since the Unix epoch (era 0, valid until 2036; era 1 handled by
/// assuming timestamps within 68 years of the local clock).
fn ntp_to_unix_ms(ts: u64, reference_unix_secs: u64) -> i128 {
    let secs = ts >> 32;
    let frac = ts & 0xffff_ffff;
    let mut unix = secs as i128 - NTP_UNIX_OFFSET as i128;
    // Era rollover: pick the era closest to the local clock.
    let era = 1i128 << 32;
    while unix + era / 2 < reference_unix_secs as i128 {
        unix += era;
    }
    unix * 1000 + ((frac as i128 * 1000) >> 32)
}

/// Result of one SNTP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SntpSample {
    /// Local clock minus server clock, milliseconds.
    pub offset_ms: i64,
    /// Round-trip delay, milliseconds.
    pub delay_ms: i64,
    pub stratum: u8,
}

/// Compute offset and delay from the four SNTP timestamps (ms since epoch).
pub fn sntp_offset(t1: i128, t2: i128, t3: i128, t4: i128) -> (i64, i64) {
    let server_minus_local = ((t2 - t1) + (t3 - t4)) / 2;
    let delay = (t4 - t1) - (t3 - t2);
    ((-server_minus_local) as i64, delay.max(0) as i64)
}

/// Parse an SNTP reply (48 bytes) and compute the local-clock offset.
pub fn parse_sntp_reply(reply: &[u8], t1_ms: i128, t4_ms: i128, local_unix_secs: u64) -> std::io::Result<SntpSample> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    if reply.len() < 48 {
        return Err(bad("short SNTP reply"));
    }
    let li = reply[0] >> 6;
    let mode = reply[0] & 0x7;
    let stratum = reply[1];
    if mode != 4 && mode != 5 {
        return Err(bad("not a server reply"));
    }
    if li == 3 || stratum == 0 || stratum > 15 {
        return Err(bad("server unsynchronised or kiss-o'-death"));
    }
    let rd = |o: usize| u64::from_be_bytes([reply[o], reply[o + 1], reply[o + 2], reply[o + 3], reply[o + 4], reply[o + 5], reply[o + 6], reply[o + 7]]);
    let t2 = ntp_to_unix_ms(rd(32), local_unix_secs);
    let t3 = ntp_to_unix_ms(rd(40), local_unix_secs);
    if rd(40) == 0 {
        return Err(bad("zero transmit timestamp"));
    }
    let (offset_ms, delay_ms) = sntp_offset(t1_ms, t2, t3, t4_ms);
    Ok(SntpSample { offset_ms, delay_ms, stratum })
}

fn now_ms() -> i128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i128).unwrap_or(0)
}

/// One SNTP query (RFC 4330 client mode) with a timeout.
pub fn sntp_query(server: &str, timeout: Duration) -> std::io::Result<SntpSample> {
    let addr = (server, 123u16).to_socket_addrs()?.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address"))?;
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    sock.connect(addr)?;
    let mut req = [0u8; 48];
    req[0] = 0x23; // LI 0, version 4, mode 3 (client)
    let t1_sys = SystemTime::now();
    req[40..48].copy_from_slice(&to_ntp(t1_sys).to_be_bytes());
    let t1 = now_ms();
    sock.send(&req)?;
    let mut buf = [0u8; 128];
    let n = sock.recv(&mut buf)?;
    let t4 = now_ms();
    if n >= 48 && buf[24..32] != req[40..48] {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "originate timestamp mismatch"));
    }
    let local_secs = (t4 / 1000) as u64;
    parse_sntp_reply(&buf[..n], t1, t4, local_secs)
}

/// Measure the local clock against the first reachable server; falls back to the system clock
/// with unknown uncertainty.
pub fn measure_time(servers: &[&str], timeout: Duration) -> TimeSource {
    for s in servers {
        if let Ok(sample) = sntp_query(s, timeout) {
            return TimeSource { source: format!("ntp:{}", s), offset_ms: sample.offset_ms, uncertainty_ms: (sample.delay_ms / 2 + 1) as u64 };
        }
    }
    TimeSource { source: "system-clock".into(), offset_ms: 0, uncertainty_ms: UNCERTAINTY_UNKNOWN }
}

/// Tool identity of the running agent: binary SHA-256 and the full command line.
pub fn agent_tool_info() -> ToolInfo {
    let binary_sha256 = std::env::current_exe().ok().and_then(|p| crate::sha256_file(&p).ok());
    let command_line = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>().join(" ");
    ToolInfo { name: crate::AGENT_NAME.into(), version: crate::AGENT_VERSION.into(), binary_sha256, command_line }
}

/// Everything recorded about one acquisition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acquisition {
    pub case_id: String,
    pub evidence_id: String,
    pub actor: String,
    pub purpose: String,
    pub hashes: Hashes,
    pub device: DeviceInfo,
    pub details: BTreeMap<String, serde_json::Value>,
}

/// Append an `Acquire` entry, signed with `key`, to the JSON Lines ledger at `ledger_path`. A new
/// ledger (with its genesis entry) is created when the file does not exist.
///
/// The entry is stamped when it is appended (never earlier than the current chain head, so the
/// verifier's monotonic-time check holds); `acquired_at` is recorded in `details.acquired_at`.
pub fn append_acquisition(ledger_path: &Path, key: &ExaminerKey, acq: &Acquisition, time_source: TimeSource, tool: ToolInfo, acquired_at: DateTime<Utc>) -> Result<Entry> {
    let mut ledger = if ledger_path.exists() {
        Ledger::load(ledger_path)?
    } else {
        let id = uuid::Uuid::new_v4().to_string();
        let l = Ledger::create(&id, &acq.case_id, key, &acq.actor, tool.clone())?;
        l.write_all(ledger_path)?;
        l
    };
    let head_time = ledger.head().map(|e| e.body.timestamp);
    let timestamp = match head_time {
        Some(h) if h > Utc::now() => h,
        _ => Utc::now(),
    };
    let mut details = acq.details.clone();
    details.insert("acquired_at".into(), serde_json::Value::String(acquired_at.to_rfc3339()));
    let new = NewEntry {
        timestamp,
        actor: acq.actor.clone(),
        kind: EntryKind::Acquire,
        evidence_id: Some(acq.evidence_id.clone()),
        hashes: Some(acq.hashes.clone()),
        device: Some(acq.device.clone()),
        time_source: Some(time_source),
        tool,
        purpose: acq.purpose.clone(),
        details,
    };
    let entry = ledger.append(new, key)?.clone();
    ledger.append_to_file(ledger_path)?;
    Ok(entry)
}

/// Convenience: measure time, describe the agent and append.
pub fn record_acquisition(ledger_path: &Path, key: &ExaminerKey, acq: &Acquisition, measure_ntp: bool) -> Result<Entry> {
    let ts = if measure_ntp { measure_time(NTP_SERVERS, Duration::from_secs(2)) } else { TimeSource { source: "system-clock".into(), offset_ms: 0, uncertainty_ms: UNCERTAINTY_UNKNOWN } };
    append_acquisition(ledger_path, key, acq, ts, agent_tool_info(), Utc::now())
}

/// Host description helper for `DeviceInfo.host`.
pub fn host_name() -> Option<String> {
    sysinfo::System::host_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_formula() {
        // Server 500 ms ahead of local, 100 ms symmetric delay.
        let (off, delay) = sntp_offset(1000, 1550, 1550, 1100);
        assert_eq!(off, -500);
        assert_eq!(delay, 100);
    }

    #[test]
    fn reply_parsing_validates_fields() {
        let local = 1_800_000_000u64;
        let mut r = [0u8; 48];
        r[0] = 0x24; // LI 0, v4, mode 4
        r[1] = 2;
        let server_ntp = ((local + NTP_UNIX_OFFSET) << 32) | (1u64 << 31); // +500 ms
        r[32..40].copy_from_slice(&server_ntp.to_be_bytes());
        r[40..48].copy_from_slice(&server_ntp.to_be_bytes());
        let t = local as i128 * 1000;
        let s = parse_sntp_reply(&r, t, t, local).unwrap();
        assert_eq!(s.offset_ms, -500);
        assert_eq!(s.stratum, 2);
        let mut kod = r;
        kod[1] = 0;
        assert!(parse_sntp_reply(&kod, t, t, local).is_err());
        assert!(parse_sntp_reply(&r[..20], t, t, local).is_err());
    }

    #[test]
    fn unreachable_server_falls_back() {
        let ts = measure_time(&["invalid.invalid"], Duration::from_millis(200));
        assert_eq!(ts.source, "system-clock");
        assert_eq!(ts.uncertainty_ms, UNCERTAINTY_UNKNOWN);
    }
}
