//! Network history.
//!
//! - `windows:registry:network` (SOFTWARE): `Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`
//!   (ProfileName, Description, NameType, DateCreated / DateLastConnected as SYSTEMTIME in
//!   *local* time) joined with `NetworkList\Signatures\{Managed,Unmanaged}\*` (DnsSuffix,
//!   DefaultGatewayMac, FirstNetwork) by `ProfileGuid`.
//! - `windows:registry:network_interface` (SYSTEM): `<CCS>\Services\Tcpip\Parameters\Interfaces\{GUID}`
//!   DHCP / static configuration; LeaseObtainedTime and LeaseTerminatesTime are Unix seconds.
use super::{current_control_set, join, Ctx};
use crate::regf::Hive;
use crate::util::u16_at;
use chrono::{NaiveDate, TimeZone, Utc};
use std::collections::BTreeMap;
use veritas_timeline::{desc, unix_secs_to_ns, Event};

pub const NETWORKLIST: &str = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList";

/// Decode a 16-byte SYSTEMTIME into nanoseconds, treating it as UTC (it is local time).
pub fn systemtime_to_ns(raw: &[u8]) -> Option<i64> {
    let y = u16_at(raw, 0).ok()? as i32;
    let mo = u16_at(raw, 2).ok()? as u32;
    let d = u16_at(raw, 6).ok()? as u32;
    let h = u16_at(raw, 8).ok()? as u32;
    let mi = u16_at(raw, 10).ok()? as u32;
    let s = u16_at(raw, 12).ok()? as u32;
    let ms = u16_at(raw, 14).ok()? as u32;
    if y == 0 {
        return None;
    }
    let dt = NaiveDate::from_ymd_opt(y, mo, d)?.and_hms_milli_opt(h, mi, s, ms.min(999))?;
    Utc.from_utc_datetime(&dt).timestamp_nanos_opt()
}

pub fn name_type(t: u32) -> &'static str {
    match t {
        0x06 => "Wired",
        0x17 => "3g",
        0x47 => "Wireless",
        0xF3 => "Mobile broadband",
        _ => "Unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProfile {
    pub guid: String,
    pub key_rel_path: String,
    pub key_offset: u32,
    pub profile_name: String,
    pub description: Option<String>,
    pub name_type: Option<u32>,
    pub category: Option<u32>,
    pub created_ns: Option<i64>,
    pub last_connected_ns: Option<i64>,
    pub dns_suffix: Option<String>,
    pub gateway_mac: Option<String>,
    pub first_network: Option<String>,
    pub signature_source: Option<String>,
    pub last_written_ns: Option<i64>,
}

pub fn profiles(hive: &Hive) -> Vec<NetworkProfile> {
    let mut sigs: BTreeMap<String, (Option<String>, Option<String>, Option<String>, String)> = BTreeMap::new();
    for kind in ["Managed", "Unmanaged"] {
        if let Some(k) = hive.key(&format!("{NETWORKLIST}\\Signatures\\{kind}")) {
            for s in k.subkeys() {
                let Some(g) = s.value_string("ProfileGuid") else { continue };
                let mac = s.value_bytes("DefaultGatewayMac").filter(|m| !m.is_empty()).map(|m| m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"));
                sigs.insert(g.to_uppercase(), (s.value_string("DnsSuffix"), mac, s.value_string("FirstNetwork"), kind.to_string()));
            }
        }
    }
    let rel = format!("{NETWORKLIST}\\Profiles");
    let Some(pk) = hive.key(&rel) else { return vec![] };
    pk.subkeys()
        .into_iter()
        .map(|p| {
            let sig = sigs.get(&p.name.to_uppercase()).cloned();
            NetworkProfile {
                guid: p.name.clone(),
                key_rel_path: join(&rel, &p.name),
                key_offset: p.offset,
                profile_name: p.value_string("ProfileName").unwrap_or_default(),
                description: p.value_string("Description"),
                name_type: p.value_u32("NameType"),
                category: p.value_u32("Category"),
                created_ns: p.value_bytes("DateCreated").and_then(|b| systemtime_to_ns(&b)),
                last_connected_ns: p.value_bytes("DateLastConnected").and_then(|b| systemtime_to_ns(&b)),
                dns_suffix: sig.as_ref().and_then(|s| s.0.clone()),
                gateway_mac: sig.as_ref().and_then(|s| s.1.clone()),
                first_network: sig.as_ref().and_then(|s| s.2.clone()),
                signature_source: sig.map(|s| s.3),
                last_written_ns: p.last_written_ns,
            }
        })
        .collect()
}

pub fn profile_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    for p in profiles(hive) {
        let mk = |d: &str, ts: Option<i64>, local: bool| {
            let nt = p.name_type.map(name_type).unwrap_or("Unknown");
            let mut e = ctx
                .event(
                    "networks",
                    "windows:registry:network",
                    d,
                    ts,
                    format!("SSID: {} Description: {} Connection Type: {} Default Gateway Mac: {} DNS Suffix: {}", p.profile_name, p.description.clone().unwrap_or_default(), nt, p.gateway_mac.clone().unwrap_or_default(), p.dns_suffix.clone().unwrap_or_default()),
                    &p.key_rel_path,
                    p.key_offset,
                )
                .attr("ssid", p.profile_name.clone())
                .attr("profile_guid", p.guid.clone())
                .attr("connection_type", nt);
            for (k, v) in [("description", &p.description), ("dns_suffix", &p.dns_suffix), ("default_gateway_mac", &p.gateway_mac), ("first_network", &p.first_network), ("signature_source", &p.signature_source)] {
                if let Some(v) = v {
                    e = e.attr(k, v.clone());
                }
            }
            if local {
                e.timezone = Some("localtime".into());
            }
            e
        };
        out.push(mk(desc::WRITTEN, p.last_written_ns, false));
        if p.created_ns.is_some() {
            out.push(mk(desc::CREATION, p.created_ns, true));
        }
        if p.last_connected_ns.is_some() {
            out.push(mk("Last Connected Time", p.last_connected_ns, true));
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    pub guid: String,
    pub key_rel_path: String,
    pub key_offset: u32,
    pub values: BTreeMap<String, String>,
    pub lease_obtained_ns: Option<i64>,
    pub lease_terminates_ns: Option<i64>,
    pub last_written_ns: Option<i64>,
}

pub const INTERFACE_VALUES: &[&str] = &[
    "EnableDHCP", "DhcpIPAddress", "DhcpSubnetMask", "DhcpServer", "DhcpDefaultGateway", "DhcpNameServer", "DhcpDomain", "Domain",
    "IPAddress", "SubnetMask", "DefaultGateway", "NameServer",
];

pub fn interfaces(hive: &Hive) -> Vec<NetworkInterface> {
    let Some(ccs) = current_control_set(hive) else { return vec![] };
    let rel = format!("{ccs}\\Services\\Tcpip\\Parameters\\Interfaces");
    let Some(k) = hive.key(&rel) else { return vec![] };
    k.subkeys()
        .into_iter()
        .map(|i| {
            let mut values = BTreeMap::new();
            for n in INTERFACE_VALUES {
                if let Some(v) = i.value(n) {
                    let s = v.as_string().unwrap_or_default();
                    if !s.is_empty() {
                        values.insert(n.to_string(), s);
                    }
                }
            }
            let t = |n: &str| i.value_u32(n).filter(|&v| v != 0).and_then(|v| unix_secs_to_ns(v as i64));
            NetworkInterface {
                guid: i.name.clone(),
                key_rel_path: join(&rel, &i.name),
                key_offset: i.offset,
                lease_obtained_ns: t("LeaseObtainedTime"),
                lease_terminates_ns: t("LeaseTerminatesTime"),
                values,
                last_written_ns: i.last_written_ns,
            }
        })
        .collect()
}

pub fn interface_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    for i in interfaces(hive) {
        let summary: Vec<String> = i.values.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        let mk = |d: &str, ts: Option<i64>| {
            let mut e = ctx.event("network_interfaces", "windows:registry:network_interface", d, ts, format!("[{}] {}", ctx.full_path(&i.key_rel_path), summary.join(" ")), &i.key_rel_path, i.key_offset).attr("interface_guid", i.guid.clone());
            for (k, v) in &i.values {
                e = e.attr(&k.to_ascii_lowercase(), v.clone());
            }
            e
        };
        out.push(mk(desc::WRITTEN, i.last_written_ns));
        if i.lease_obtained_ns.is_some() {
            out.push(mk("Lease Obtained Time", i.lease_obtained_ns));
        }
        if i.lease_terminates_ns.is_some() {
            out.push(mk("Lease Expiration Time", i.lease_terminates_ns));
        }
    }
    out
}
