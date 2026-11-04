//! Windows Task Scheduler artifacts: legacy `.job` files (MS-TSCH 2.4) and Task Scheduler
//! 2.0 XML task definitions.
use crate::error::{ParseError, Result};
use crate::shellitems::guid_string;
use crate::util::{need, u16_at, u32_at, utf16le};
use serde::Serialize;
use serde_json::json;
use veritas_timeline::{desc, Event};

const MAX_TRIGGERS: usize = 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SystemTime {
    pub year: u16,
    pub month: u16,
    pub weekday: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub millisecond: u16,
}

impl SystemTime {
    /// Interpreted as UTC (the value is local time of the system that wrote it).
    pub fn to_ns(&self) -> Option<i64> {
        if self.year == 0 {
            return None;
        }
        let d =
            chrono::NaiveDate::from_ymd_opt(self.year as i32, self.month as u32, self.day as u32)?;
        let t = d.and_hms_milli_opt(
            self.hour as u32,
            self.minute as u32,
            self.second as u32,
            self.millisecond as u32,
        )?;
        t.and_utc().timestamp_nanos_opt()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Trigger {
    pub begin_year: u16,
    pub begin_month: u16,
    pub begin_day: u16,
    pub end_year: u16,
    pub end_month: u16,
    pub end_day: u16,
    pub start_hour: u16,
    pub start_minute: u16,
    pub duration_minutes: u32,
    pub interval_minutes: u32,
    pub flags: u32,
    pub trigger_type: u32,
    pub trigger_type_name: String,
}

impl Trigger {
    pub fn start_ns(&self) -> Option<i64> {
        let d = chrono::NaiveDate::from_ymd_opt(
            self.begin_year as i32,
            self.begin_month as u32,
            self.begin_day as u32,
        )?;
        d.and_hms_opt(self.start_hour as u32, self.start_minute as u32, 0)?
            .and_utc()
            .timestamp_nanos_opt()
    }
    pub fn end_ns(&self) -> Option<i64> {
        if self.end_year == 0 {
            return None;
        }
        let d = chrono::NaiveDate::from_ymd_opt(
            self.end_year as i32,
            self.end_month as u32,
            self.end_day as u32,
        )?;
        d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_nanos_opt()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JobFile {
    pub product_version: u16,
    pub file_version: u16,
    pub uuid: String,
    pub error_retry_count: u16,
    pub error_retry_interval: u16,
    pub priority: u32,
    pub max_run_time_ms: u32,
    pub exit_code: u32,
    pub status: u32,
    pub flags: u32,
    pub last_run_time: SystemTime,
    pub running_instance_count: u16,
    pub application_name: String,
    pub parameters: String,
    pub working_directory: String,
    pub author: String,
    pub comment: String,
    pub user_data_hex: String,
    pub triggers: Vec<Trigger>,
}

fn trigger_type_name(t: u32) -> &'static str {
    match t {
        0 => "ONCE",
        1 => "DAILY",
        2 => "WEEKLY",
        3 => "MONTHLYDATE",
        4 => "MONTHLYDOW",
        5 => "EVENT_ON_IDLE",
        6 => "EVENT_AT_SYSTEMSTART",
        7 => "EVENT_AT_LOGON",
        _ => "UNKNOWN",
    }
}

fn read_unicode(d: &[u8], p: &mut usize) -> Result<String> {
    let n = u16_at(d, *p)? as usize;
    let s = utf16le(need(d, *p + 2, n * 2)?, true);
    *p += 2 + n * 2;
    Ok(s)
}

pub fn parse_job(d: &[u8]) -> Result<JobFile> {
    need(d, 0, 68)?;
    let fv = u16_at(d, 2)?;
    if fv != 1 {
        return Err(ParseError::BadSignature {
            offset: 2,
            expected: "file version 1".into(),
            found: fv.to_string(),
        });
    }
    let st = |o: usize| -> Result<u16> { u16_at(d, 52 + o * 2) };
    let last = SystemTime {
        year: st(0)?,
        month: st(1)?,
        weekday: st(2)?,
        day: st(3)?,
        hour: st(4)?,
        minute: st(5)?,
        second: st(6)?,
        millisecond: st(7)?,
    };
    let mut p = 68usize;
    let running = u16_at(d, p)?;
    p += 2;
    let application_name = read_unicode(d, &mut p)?;
    let parameters = read_unicode(d, &mut p)?;
    let working_directory = read_unicode(d, &mut p)?;
    let author = read_unicode(d, &mut p)?;
    let comment = read_unicode(d, &mut p)?;
    let ud = u16_at(d, p)? as usize;
    let user_data_hex = hex::encode(need(d, p + 2, ud)?);
    p += 2 + ud;
    let rd = u16_at(d, p)? as usize;
    need(d, p + 2, rd)?;
    p += 2 + rd;
    let n = (u16_at(d, p)? as usize).min(MAX_TRIGGERS);
    p += 2;
    let mut triggers = Vec::new();
    for _ in 0..n {
        let t = need(d, p, 48)?;
        let w = |o: usize| u16::from_le_bytes([t[o], t[o + 1]]);
        let ty = u32_at(t, 32)?;
        triggers.push(Trigger {
            begin_year: w(4),
            begin_month: w(6),
            begin_day: w(8),
            end_year: w(10),
            end_month: w(12),
            end_day: w(14),
            start_hour: w(16),
            start_minute: w(18),
            duration_minutes: u32_at(t, 20)?,
            interval_minutes: u32_at(t, 24)?,
            flags: u32_at(t, 28)?,
            trigger_type: ty,
            trigger_type_name: trigger_type_name(ty).into(),
        });
        p += (w(0) as usize).max(48);
    }
    Ok(JobFile {
        product_version: u16_at(d, 0)?,
        file_version: fv,
        uuid: guid_string(need(d, 4, 16)?).unwrap_or_default(),
        error_retry_count: u16_at(d, 24)?,
        error_retry_interval: u16_at(d, 26)?,
        priority: u32_at(d, 32)?,
        max_run_time_ms: u32_at(d, 36)?,
        exit_code: u32_at(d, 40)?,
        status: u32_at(d, 44)?,
        flags: u32_at(d, 48)?,
        last_run_time: last,
        running_instance_count: running,
        application_name,
        parameters,
        working_directory,
        author,
        comment,
        user_data_hex,
        triggers,
    })
}

fn finish(mut e: Event, sha: &str, path: &str, off: i64, parser: &str) -> Event {
    e.source_short = "JOB".into();
    e.source_long = "Windows Scheduled Task Job".into();
    e.attrs.insert("time_is_local".into(), json!(true));
    e.provenance(sha, path, off, parser, crate::PARSER_VERSION)
}

pub fn job_events(j: &JobFile, sha: &str, path: &str) -> Vec<Event> {
    let msg = format!(
        "Application: {} {} Scheduled by: {} Working directory: {}",
        j.application_name, j.parameters, j.author, j.working_directory
    );
    let base = |d: &str, ts: Option<i64>| {
        Event::new("windows:tasks:job", d, msg.clone())
            .with_time(ts)
            .attr("application", j.application_name.clone())
            .attr("parameters", j.parameters.clone())
            .attr("working_directory", j.working_directory.clone())
            .attr("username", j.author.clone())
            .attr("comment", j.comment.clone())
            .attr("exit_code", j.exit_code)
            .attr("status", format!("0x{:08x}", j.status))
            .attr("uuid", j.uuid.clone())
    };
    let mut out = Vec::new();
    if let Some(t) = j.last_run_time.to_ns() {
        out.push(finish(
            base(desc::LAST_RUN, Some(t)),
            sha,
            path,
            0,
            "taskjob",
        ));
    }
    for (i, tr) in j.triggers.iter().enumerate() {
        if let Some(t) = tr.start_ns() {
            let e = base("Scheduled to start", Some(t))
                .attr("trigger_type", tr.trigger_type_name.clone())
                .attr("trigger_index", i as u64);
            out.push(finish(e, sha, path, 1 + i as i64, "taskjob"));
        }
        if let Some(t) = tr.end_ns() {
            let e = base("Scheduled to end", Some(t))
                .attr("trigger_type", tr.trigger_type_name.clone())
                .attr("trigger_index", i as u64);
            out.push(finish(e, sha, path, 1 + i as i64, "taskjob"));
        }
    }
    out
}

// ---------------------------------------------------------------- Task Scheduler 2.0 XML

#[derive(Debug, Clone, Default, Serialize)]
pub struct XmlAction {
    pub kind: String,
    pub command: Option<String>,
    pub arguments: Option<String>,
    pub working_directory: Option<String>,
    pub class_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct XmlTrigger {
    pub kind: String,
    pub start_boundary: Option<String>,
    pub end_boundary: Option<String>,
    pub enabled: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct XmlTask {
    pub uri: Option<String>,
    pub date: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub user_id: Option<String>,
    pub run_level: Option<String>,
    pub logon_type: Option<String>,
    pub hidden: Option<String>,
    pub triggers: Vec<XmlTrigger>,
    pub actions: Vec<XmlAction>,
}

fn decode_text(d: &[u8]) -> Result<String> {
    if d.starts_with(&[0xff, 0xfe]) {
        return Ok(utf16le(&d[2..], false));
    }
    if d.len() >= 2 && d[1] == 0 && d[0] == b'<' {
        return Ok(utf16le(d, false));
    }
    let d = d.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(d);
    String::from_utf8(d.to_vec()).map_err(|e| ParseError::Invalid {
        offset: e.utf8_error().valid_up_to(),
        reason: "task XML is not UTF-8/UTF-16".into(),
    })
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn txt(n: Option<roxmltree::Node<'_, '_>>) -> Option<String> {
    n.and_then(|n| n.text()).map(|s| s.trim().to_string())
}

pub fn parse_task_xml(d: &[u8]) -> Result<XmlTask> {
    let text = decode_text(d)?;
    // roxmltree rejects an encoding="UTF-16" declaration on already-decoded text only if
    // malformed; strip the declaration to be safe.
    let body = match text.find("?>") {
        Some(i) if text.trim_start().starts_with("<?xml") => &text[i + 2..],
        _ => &text[..],
    };
    let opts = roxmltree::ParsingOptions {
        allow_dtd: false,
        ..Default::default()
    };
    let doc = roxmltree::Document::parse_with_options(body.trim_start_matches('\u{feff}'), opts)
        .map_err(|e| ParseError::Invalid {
            offset: 0,
            reason: format!("XML: {e}"),
        })?;
    let root = doc.root_element();
    if root.tag_name().name() != "Task" {
        return Err(ParseError::BadSignature {
            offset: 0,
            expected: "<Task>".into(),
            found: root.tag_name().name().into(),
        });
    }
    let mut t = XmlTask::default();
    if let Some(ri) = child(root, "RegistrationInfo") {
        t.uri = txt(child(ri, "URI"));
        t.date = txt(child(ri, "Date"));
        t.author = txt(child(ri, "Author"));
        t.description = txt(child(ri, "Description"));
    }
    if let Some(p) = child(root, "Principals").and_then(|p| child(p, "Principal")) {
        t.user_id = txt(child(p, "UserId"));
        t.run_level = txt(child(p, "RunLevel"));
        t.logon_type = txt(child(p, "LogonType"));
    }
    if let Some(s) = child(root, "Settings") {
        t.hidden = txt(child(s, "Hidden"));
    }
    if let Some(trs) = child(root, "Triggers") {
        for tr in trs.children().filter(|c| c.is_element()).take(MAX_TRIGGERS) {
            t.triggers.push(XmlTrigger {
                kind: tr.tag_name().name().to_string(),
                start_boundary: txt(child(tr, "StartBoundary")),
                end_boundary: txt(child(tr, "EndBoundary")),
                enabled: txt(child(tr, "Enabled")),
            });
        }
    }
    if let Some(acts) = child(root, "Actions") {
        for a in acts
            .children()
            .filter(|c| c.is_element())
            .take(MAX_TRIGGERS)
        {
            t.actions.push(XmlAction {
                kind: a.tag_name().name().to_string(),
                command: txt(child(a, "Command")),
                arguments: txt(child(a, "Arguments")),
                working_directory: txt(child(a, "WorkingDirectory")),
                class_id: txt(child(a, "ClassId")),
            });
        }
    }
    Ok(t)
}

/// Parse an XML dateTime (with or without offset / fraction). Values without an offset are
/// local time and are interpreted as UTC.
pub fn parse_xml_datetime(s: &str) -> Option<i64> {
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(s) {
        return d.timestamp_nanos_opt();
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(n) = chrono::NaiveDateTime::parse_from_str(s.trim_end_matches('Z'), f) {
            return n.and_utc().timestamp_nanos_opt();
        }
    }
    None
}

pub fn xml_events(t: &XmlTask, sha: &str, path: &str) -> Vec<Event> {
    let cmd: Vec<String> = t
        .actions
        .iter()
        .map(|a| match (&a.command, &a.class_id) {
            (Some(c), _) => format!("{} {}", c, a.arguments.clone().unwrap_or_default())
                .trim()
                .to_string(),
            (None, Some(cls)) => format!("COM {cls}"),
            _ => a.kind.clone(),
        })
        .collect();
    let msg = format!(
        "Task: {} Author: {} Actions: [{}] User: {} RunLevel: {}",
        t.uri.clone().unwrap_or_default(),
        t.author.clone().unwrap_or_default(),
        cmd.join("; "),
        t.user_id.clone().unwrap_or_default(),
        t.run_level.clone().unwrap_or_default()
    );
    let base = |d: &str, ts: Option<i64>| {
        let first = t.actions.iter().find(|a| a.command.is_some());
        Event::new("windows:tasks:xml", d, msg.clone())
            .with_time(ts)
            .attr("task_name", json!(t.uri))
            .attr("author", json!(t.author))
            .attr("command", json!(first.and_then(|a| a.command.clone())))
            .attr("arguments", json!(first.and_then(|a| a.arguments.clone())))
            .attr("actions", json!(cmd))
            .attr("user_id", json!(t.user_id))
            .attr("run_level", json!(t.run_level))
            .attr("hidden", json!(t.hidden))
    };
    let mut out = Vec::new();
    let reg = t.date.as_deref().and_then(parse_xml_datetime);
    out.push(finish(
        base(
            if reg.is_some() {
                desc::CREATION
            } else {
                desc::NOT_A_TIME
            },
            reg,
        ),
        sha,
        path,
        0,
        "taskxml",
    ));
    for (i, tr) in t.triggers.iter().enumerate() {
        if let Some(ts) = tr.start_boundary.as_deref().and_then(parse_xml_datetime) {
            let e = base("Scheduled to start", Some(ts))
                .attr("trigger_type", tr.kind.clone())
                .attr("trigger_index", i as u64);
            out.push(finish(e, sha, path, 1 + i as i64, "taskxml"));
        }
    }
    out
}
