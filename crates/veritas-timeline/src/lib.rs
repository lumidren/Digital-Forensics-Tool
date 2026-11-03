//! Unified timeline event schema shared by every parser.
//!
//! The field set is Plaso-compatible (`timestamp_desc`, `data_type`, `message`, `source_short`,
//! `source_long`) so that exports load into `psort`, plus provenance fields that tie each event
//! to an evidence object and the parser that produced it.
#![forbid(unsafe_code)]

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Write;

/// Plaso timestamp description vocabulary (subset used by Veritas parsers).
pub mod desc {
    pub const CREATION: &str = "Creation Time";
    pub const MODIFICATION: &str = "Content Modification Time";
    pub const METADATA_MODIFICATION: &str = "Metadata Modification Time";
    pub const ACCESS: &str = "Last Access Time";
    pub const LAST_RUN: &str = "Last Time Executed";
    pub const PREVIOUS_RUN: &str = "Previous Last Time Executed";
    pub const WRITTEN: &str = "Content Modification Time";
    pub const LAST_VISITED: &str = "Last Visited Time";
    pub const LAST_LOGIN: &str = "Last Login Time";
    pub const EVENT: &str = "Event Time";
    pub const INSTALLATION: &str = "Installation Time";
    pub const EXPIRATION: &str = "Expiration Time";
    pub const START: &str = "Start Time";
    pub const END: &str = "End Time";
    pub const ENTRY_MODIFICATION: &str = "Metadata Modification Time";
    pub const NOT_A_TIME: &str = "Not a time";
}

/// One timeline event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Nanoseconds since the Unix epoch, UTC. `None` when the artifact carries no usable time.
    pub timestamp: Option<i64>,
    pub timestamp_desc: String,
    pub data_type: String,
    pub message: String,
    pub source_short: String,
    pub source_long: String,
    /// SHA-256 of the evidence object the event was parsed from.
    pub evidence_sha256: String,
    /// Path of the artifact inside the evidence (file-system path or bundle path).
    pub evidence_path: String,
    /// Byte offset or record index inside the artifact.
    pub offset: i64,
    pub parser: String,
    pub parser_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Original timezone identifier if the source was not UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Clock-skew correction already applied to `timestamp`, in nanoseconds.
    #[serde(default)]
    pub skew_ns: i64,
    /// Parser-specific attributes; BTreeMap keeps key order deterministic.
    #[serde(default)]
    pub attrs: BTreeMap<String, serde_json::Value>,
}

impl Event {
    pub fn new(data_type: &str, timestamp_desc: &str, message: impl Into<String>) -> Self {
        Self {
            timestamp: None,
            timestamp_desc: timestamp_desc.to_string(),
            data_type: data_type.to_string(),
            message: message.into(),
            source_short: String::new(),
            source_long: String::new(),
            evidence_sha256: String::new(),
            evidence_path: String::new(),
            offset: 0,
            parser: String::new(),
            parser_version: String::new(),
            host: None,
            user: None,
            timezone: None,
            skew_ns: 0,
            attrs: BTreeMap::new(),
        }
    }

    pub fn with_time(mut self, ts: Option<i64>) -> Self {
        self.timestamp = ts;
        self
    }

    pub fn attr(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.attrs.insert(key.to_string(), value.into());
        self
    }

    pub fn provenance(mut self, evidence_sha256: &str, evidence_path: &str, offset: i64, parser: &str, parser_version: &str) -> Self {
        self.evidence_sha256 = evidence_sha256.to_string();
        self.evidence_path = evidence_path.to_string();
        self.offset = offset;
        self.parser = parser.to_string();
        self.parser_version = parser_version.to_string();
        self
    }

    pub fn datetime(&self) -> Option<DateTime<Utc>> {
        self.timestamp.and_then(|ns| Utc.timestamp_opt(ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000) as u32).single())
    }

    /// Deterministic ordering key: `(timestamp, data_type, evidence_path, offset, timestamp_desc)`.
    pub fn sort_key(&self) -> (i64, &str, &str, i64, &str) {
        (self.timestamp.unwrap_or(i64::MIN), &self.data_type, &self.evidence_path, self.offset, &self.timestamp_desc)
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

/// Convert a Windows FILETIME (100 ns intervals since 1601-01-01) to epoch nanoseconds.
/// Returns `None` for zero and for values outside the representable range.
pub fn filetime_to_ns(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
    let v = i64::try_from(ft).ok()?;
    let rel = v.checked_sub(EPOCH_DIFF_100NS)?;
    rel.checked_mul(100)
}

/// Unix seconds to epoch nanoseconds.
pub fn unix_secs_to_ns(secs: i64) -> Option<i64> {
    secs.checked_mul(1_000_000_000)
}

/// Unix seconds with a fractional nanosecond part.
pub fn unix_to_ns(secs: i64, nanos: u32) -> Option<i64> {
    secs.checked_mul(1_000_000_000)?.checked_add(nanos as i64)
}

/// Apple Cocoa / Core Foundation absolute time (seconds since 2001-01-01) to epoch nanoseconds.
pub fn cocoa_secs_to_ns(secs: i64) -> Option<i64> {
    secs.checked_add(978_307_200)?.checked_mul(1_000_000_000)
}

/// WebKit / Chrome time (microseconds since 1601-01-01) to epoch nanoseconds.
pub fn webkit_us_to_ns(us: i64) -> Option<i64> {
    if us == 0 {
        return None;
    }
    us.checked_sub(11_644_473_600_000_000)?.checked_mul(1000)
}

/// FAT date/time (local, 2 s resolution) to epoch nanoseconds, treating the value as UTC.
pub fn fat_datetime_to_ns(date: u16, time: u16, tenths: u8) -> Option<i64> {
    let year = 1980 + ((date >> 9) & 0x7f) as i32;
    let month = ((date >> 5) & 0x0f) as u32;
    let day = (date & 0x1f) as u32;
    let hour = ((time >> 11) & 0x1f) as u32;
    let minute = ((time >> 5) & 0x3f) as u32;
    let second = ((time & 0x1f) as u32) * 2 + (tenths as u32) / 100;
    let millis = ((tenths as u32) % 100) * 10;
    let dt = Utc.with_ymd_and_hms(year, month, day, hour, minute, second).single()?;
    Some(dt.timestamp_nanos_opt()? + (millis as i64) * 1_000_000)
}

/// Format epoch nanoseconds as RFC 3339 with microsecond precision (Plaso style).
pub fn format_ns(ns: i64) -> String {
    match Utc.timestamp_opt(ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000) as u32).single() {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
        None => "0000-00-00T00:00:00.000000Z".to_string(),
    }
}

/// Write events as JSON Lines in deterministic order.
pub fn write_jsonl<W: Write>(events: &mut [Event], mut w: W) -> std::io::Result<()> {
    events.sort();
    for e in events.iter() {
        serde_json::to_writer(&mut w, e)?;
        w.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_known_values() {
        // 2009-05-01 00:00:00 UTC = 128852640000000000
        assert_eq!(filetime_to_ns(128_852_640_000_000_000), Some(1_241_136_000_000_000_000));
        assert_eq!(filetime_to_ns(0), None);
        assert_eq!(format_ns(1_241_136_000_000_000_000), "2009-05-01T00:00:00.000000Z");
    }

    #[test]
    fn webkit_and_cocoa() {
        assert_eq!(webkit_us_to_ns(13_000_000_000_000_000), Some((13_000_000_000_000_000i64 - 11_644_473_600_000_000) * 1000));
        assert_eq!(cocoa_secs_to_ns(0), Some(978_307_200_000_000_000));
    }

    #[test]
    fn fat_datetime() {
        // 2012-03-04 05:06:08
        let date = ((2012 - 1980) << 9) | (3 << 5) | 4;
        let time = (5 << 11) | (6 << 5) | 4;
        assert_eq!(format_ns(fat_datetime_to_ns(date, time, 0).unwrap()), "2012-03-04T05:06:08.000000Z");
    }

    #[test]
    fn ordering_is_total_and_deterministic() {
        let a = Event::new("x", desc::CREATION, "a").with_time(Some(5));
        let b = Event::new("x", desc::CREATION, "b").with_time(Some(3));
        let c = Event::new("x", desc::CREATION, "c").with_time(None);
        let mut v = vec![a.clone(), b.clone(), c.clone()];
        let mut out = Vec::new();
        write_jsonl(&mut v, &mut out).unwrap();
        let lines: Vec<&str> = std::str::from_utf8(&out).unwrap().lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"message\":\"c\""));
        assert!(lines[1].contains("\"message\":\"b\""));
    }
}
