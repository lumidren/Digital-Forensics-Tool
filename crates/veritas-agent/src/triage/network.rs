//! Network connection listing: `netstat -ano` (Windows), `/proc/net/{tcp,tcp6,udp,udp6}` (Linux)
//! and `lsof -i -n -P` (macOS). Parsers are pure functions so they are tested on every platform.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub local_address: String,
    pub local_port: Option<u16>,
    pub remote_address: String,
    pub remote_port: Option<u16>,
    pub state: Option<String>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub inode: Option<u64>,
    pub uid: Option<u32>,
}

fn split_host_port(s: &str) -> (String, Option<u16>) {
    if s == "*:*" || s == "*" {
        return ("*".into(), None);
    }
    match s.rfind(':') {
        Some(i) => {
            let host = s[..i]
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            (host, s[i + 1..].parse().ok())
        }
        None => (s.to_string(), None),
    }
}

/// Parse Windows `netstat -ano` output.
pub fn parse_netstat_windows(text: &str) -> Vec<Connection> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let proto = match f.first() {
            Some(p) if p.eq_ignore_ascii_case("TCP") || p.eq_ignore_ascii_case("UDP") => {
                p.to_ascii_uppercase()
            }
            _ => continue,
        };
        let (state, pid) = match (proto.as_str(), f.len()) {
            ("TCP", 5) => (Some(f[3].to_string()), f[4].parse().ok()),
            ("UDP", 4) => (None, f[3].parse().ok()),
            _ => continue,
        };
        let (la, lp) = split_host_port(f[1]);
        let (ra, rp) = split_host_port(f[2]);
        out.push(Connection {
            protocol: proto,
            local_address: la,
            local_port: lp,
            remote_address: ra,
            remote_port: rp,
            state,
            pid,
            process: None,
            inode: None,
            uid: None,
        });
    }
    out
}

fn tcp_state(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0a => "LISTEN",
        0x0b => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn decode_proc_addr(s: &str) -> Option<(String, u16)> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match addr.len() {
        8 => {
            let v = u32::from_str_radix(addr, 16).ok()?;
            let b = v.to_le_bytes();
            Some((
                std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
                port,
            ))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for w in 0..4 {
                let v = u32::from_str_radix(&addr[w * 8..w * 8 + 8], 16).ok()?;
                bytes[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            Some((std::net::Ipv6Addr::from(bytes).to_string(), port))
        }
        _ => None,
    }
}

/// Parse one `/proc/net/{tcp,udp}[6]` table.
pub fn parse_proc_net(text: &str, protocol: &str) -> Vec<Connection> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some((la, lp)), Some((ra, rp))) = (decode_proc_addr(f[1]), decode_proc_addr(f[2]))
        else {
            continue;
        };
        let st = u8::from_str_radix(f[3], 16).unwrap_or(0);
        let state = if protocol.starts_with("tcp") {
            Some(tcp_state(st).to_string())
        } else {
            None
        };
        out.push(Connection {
            protocol: protocol.to_string(),
            local_address: la,
            local_port: Some(lp),
            remote_address: ra,
            remote_port: Some(rp),
            state,
            pid: None,
            process: None,
            uid: f[7].parse().ok(),
            inode: f[9].parse().ok(),
        });
    }
    out
}

/// Parse `lsof -i -n -P` output (macOS and Linux).
pub fn parse_lsof(text: &str) -> Vec<Connection> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 9 {
            continue;
        }
        let proto = f[7].to_ascii_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let name = f[8];
        let state = f
            .get(9)
            .map(|s| s.trim_matches(|c| c == '(' || c == ')').to_string());
        let (local, remote) = match name.split_once("->") {
            Some((l, r)) => (l, r),
            None => (name, "*:*"),
        };
        let (la, lp) = split_host_port(local);
        let (ra, rp) = split_host_port(remote);
        out.push(Connection {
            protocol: proto,
            local_address: la,
            local_port: lp,
            remote_address: ra,
            remote_port: rp,
            state,
            pid: f[1].parse().ok(),
            process: Some(f[0].to_string()),
            inode: None,
            uid: None,
        });
    }
    out
}

/// Attach process ids to Linux sockets by scanning `/proc/<pid>/fd` links (best effort; other
/// users' processes are unreadable without root).
pub fn linux_socket_owners() -> BTreeMap<u64, (u32, String)> {
    let mut map = BTreeMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return map;
    };
    for p in procs.flatten() {
        let Ok(pid) = p.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let comm = std::fs::read_to_string(p.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if let Some(inode) = t
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    map.insert(inode, (pid, comm.clone()));
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_netstat() {
        let text = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1196\n  TCP    [::1]:49670            [::1]:5040             ESTABLISHED     4321\n  UDP    0.0.0.0:5353           *:*                                    2468\n";
        let c = parse_netstat_windows(text);
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].local_port, Some(135));
        assert_eq!(c[0].state.as_deref(), Some("LISTENING"));
        assert_eq!(c[1].local_address, "::1");
        assert_eq!(c[1].pid, Some(4321));
        assert_eq!(c[2].protocol, "UDP");
        assert_eq!(c[2].remote_address, "*");
        assert_eq!(c[2].pid, Some(2468));
    }

    #[test]
    fn proc_net_tcp() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456 1 0000000000000000 100 0 0 10 0\n";
        let c = parse_proc_net(text, "tcp");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].local_address, "127.0.0.1");
        assert_eq!(c[0].local_port, Some(53));
        assert_eq!(c[0].state.as_deref(), Some("LISTEN"));
        assert_eq!(c[0].uid, Some(101));
        assert_eq!(c[0].inode, Some(23456));
        let v6 = "h\n   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 999\n";
        let c = parse_proc_net(v6, "tcp6");
        assert_eq!(c[0].local_address, "::1");
        assert_eq!(c[0].local_port, Some(22));
    }

    #[test]
    fn lsof_output() {
        let text = "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\nrapportd  412 bob    4u  IPv4 0x1      0t0  TCP *:49152 (LISTEN)\nSafari    900 bob   20u  IPv6 0x2      0t0  TCP [::1]:50000->[::1]:443 (ESTABLISHED)\nmDNS      200 root   8u  IPv4 0x3      0t0  UDP *:5353\n";
        let c = parse_lsof(text);
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].local_port, Some(49152));
        assert_eq!(c[0].state.as_deref(), Some("LISTEN"));
        assert_eq!(c[1].remote_port, Some(443));
        assert_eq!(c[1].pid, Some(900));
        assert_eq!(c[2].protocol, "UDP");
    }
}
