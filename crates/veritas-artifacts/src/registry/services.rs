//! Services and drivers (`windows:registry:service`).
//!
//! `SYSTEM\<CurrentControlSet>\Services\<name>` with `CurrentControlSet` resolved through
//! `Select\Current`. One event per service, timestamped with the key's last-written time.
use super::{current_control_set, join, Ctx};
use crate::regf::Hive;
use veritas_timeline::{desc, Event};

pub fn service_type(t: u32) -> &'static str {
    match t {
        0x1 => "Kernel device driver",
        0x2 => "File system driver",
        0x4 => "Adapter",
        0x8 => "Recognizer driver",
        0x10 => "Service - Own Process",
        0x20 => "Service - Share Process",
        0x50 => "User Service - Own Process",
        0x60 => "User Service - Share Process",
        0x110 => "Service - Own Process (interactive)",
        0x120 => "Service - Share Process (interactive)",
        _ => "Unknown",
    }
}
pub fn start_type(t: u32) -> &'static str {
    match t {
        0 => "Boot",
        1 => "System",
        2 => "Auto Start",
        3 => "Manual",
        4 => "Disabled",
        _ => "Unknown",
    }
}
pub fn error_control(t: u32) -> &'static str {
    match t {
        0 => "Ignore",
        1 => "Normal",
        2 => "Severe",
        3 => "Critical",
        _ => "Unknown",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub control_set: String,
    pub key_rel_path: String,
    pub key_offset: u32,
    pub last_written_ns: Option<i64>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub image_path: Option<String>,
    pub service_type: Option<u32>,
    pub start: Option<u32>,
    pub error_control: Option<u32>,
    pub object_name: Option<String>,
    pub group: Option<String>,
    pub service_dll: Option<String>,
}

pub fn services(hive: &Hive) -> Vec<Service> {
    let Some(ccs) = current_control_set(hive) else { return vec![] };
    let rel = format!("{ccs}\\Services");
    let Some(k) = hive.key(&rel) else { return vec![] };
    k.subkeys()
        .into_iter()
        .map(|s| Service {
            name: s.name.clone(),
            control_set: ccs.clone(),
            key_rel_path: join(&rel, &s.name),
            key_offset: s.offset,
            last_written_ns: s.last_written_ns,
            display_name: s.value_string("DisplayName"),
            description: s.value_string("Description"),
            image_path: s.value_string("ImagePath"),
            service_type: s.value_u32("Type"),
            start: s.value_u32("Start"),
            error_control: s.value_u32("ErrorControl"),
            object_name: s.value_string("ObjectName"),
            group: s.value_string("Group"),
            service_dll: s.subkey("Parameters").and_then(|p| p.value_string("ServiceDll")).or_else(|| s.value_string("ServiceDll")),
        })
        .collect()
}

pub fn events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    services(hive)
        .into_iter()
        .map(|s| {
            let st = s.service_type.map(service_type).unwrap_or("Unknown");
            let sv = s.start.map(start_type).unwrap_or("Unknown");
            let msg = format!(
                "[{}] Type: {} Start: {} Image path: {} Display name: {}",
                ctx.full_path(&s.key_rel_path),
                st,
                sv,
                s.image_path.clone().unwrap_or_default(),
                s.display_name.clone().unwrap_or_default()
            );
            let mut e = ctx
                .event("services", "windows:registry:service", desc::WRITTEN, s.last_written_ns, msg, &s.key_rel_path, s.key_offset)
                .attr("name", s.name.clone())
                .attr("control_set", s.control_set.clone())
                .attr("service_type", st)
                .attr("start_type", sv);
            for (k, v) in [("display_name", &s.display_name), ("description", &s.description), ("image_path", &s.image_path), ("object_name", &s.object_name), ("group", &s.group), ("service_dll", &s.service_dll)] {
                if let Some(v) = v {
                    e = e.attr(k, v.clone());
                }
            }
            if let Some(t) = s.service_type {
                e = e.attr("service_type_value", t);
            }
            if let Some(t) = s.start {
                e = e.attr("start_value", t);
            }
            if let Some(t) = s.error_control {
                e = e.attr("error_control", error_control(t)).attr("error_control_value", t);
            }
            e
        })
        .collect()
}
