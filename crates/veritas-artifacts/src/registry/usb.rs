//! USB device history.
//!
//! - `windows:registry:usbstor`: `SYSTEM\<CCS>\Enum\USBSTOR\<Disk&Ven_&Prod_&Rev_>\<serial>`
//! - `windows:registry:usb`: `SYSTEM\<CCS>\Enum\USB\VID_xxxx&PID_yyyy\<serial>`
//! - device property times from `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\00NN`
//!   (0064 first install, 0065 install, 0066 last arrival, 0067 last removal). Windows 7 keeps
//!   the FILETIME in `00NN\00000000\Data`; Windows 8+ in the default value of `00NN`.
//! - drive letters / volume GUIDs from `SYSTEM\MountedDevices` matched by serial number;
//! - `windows:registry:windows_portable_devices` from `SOFTWARE\Microsoft\Windows Portable Devices\Devices`;
//! - `windows:registry:mount_points2` from `NTUSER\...\Explorer\MountPoints2` (user association:
//!   join `volume_guid` of a MountPoints2 event with `volume_guids` of a USBSTOR event).
use super::{current_control_set, join, Ctx};
use crate::regf::{Hive, Key};
use crate::util::utf16le;
use serde_json::json;
use veritas_timeline::{desc, filetime_to_ns, Event};

pub const DEVICE_PROPERTIES_GUID: &str = "{83da6326-97a6-4088-9453-a1923f573b29}";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedDevice {
    pub name: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDevice {
    pub data_type: &'static str,
    pub key_rel_path: String,
    pub key_offset: u32,
    pub device_class: String,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub revision: Option<String>,
    pub serial: String,
    pub friendly_name: Option<String>,
    pub device_desc: Option<String>,
    pub last_written_ns: Option<i64>,
    pub first_install_ns: Option<i64>,
    pub install_ns: Option<i64>,
    pub last_arrival_ns: Option<i64>,
    pub last_removal_ns: Option<i64>,
    pub mounted: Vec<MountedDevice>,
}

/// `\??\Volume{...}` / `\DosDevices\X:` entries; data decoded as UTF-16 when it looks like a
/// device path, otherwise hex (MBR signature + offset, GPT GUID).
pub fn mounted_devices(hive: &Hive) -> Vec<MountedDevice> {
    let Some(k) = hive.key("MountedDevices") else { return vec![] };
    k.values()
        .into_iter()
        .map(|v| {
            let s = if v.raw.len() > 24 && v.raw.len() % 2 == 0 && v.raw.get(1) == Some(&0) { utf16le(&v.raw, true) } else { hex::encode(&v.raw) };
            MountedDevice { name: v.name, data: s }
        })
        .collect()
}

fn property_time(inst: &Key<'_>, id: &str) -> Option<i64> {
    // Windows 8+: `{guid}\0064` (default value, type 0xFFFF0010); Windows 7: `{guid}\00000064\00000000\Data`.
    let props = inst
        .path(&format!("Properties\\{DEVICE_PROPERTIES_GUID}\\{id}"))
        .or_else(|| inst.path(&format!("Properties\\{DEVICE_PROPERTIES_GUID}\\0000{id}")))?;
    let raw = props
        .values()
        .into_iter()
        .find(|v| v.raw.len() == 8)
        .map(|v| v.raw)
        .or_else(|| props.subkey("00000000").and_then(|s| s.value_bytes("Data")))?;
    filetime_to_ns(crate::util::u64_at(&raw, 0).ok()?)
}

fn parse_usbstor_class(name: &str) -> (String, Option<String>, Option<String>, Option<String>) {
    let mut class = String::new();
    let (mut ven, mut prod, mut rev) = (None, None, None);
    for (i, part) in name.split('&').enumerate() {
        if i == 0 {
            class = part.to_string();
        } else if let Some(v) = part.strip_prefix("Ven_") {
            ven = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("Prod_") {
            prod = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("Rev_") {
            rev = Some(v.to_string());
        }
    }
    (class, ven, prod, rev)
}

pub fn devices(hive: &Hive) -> Vec<UsbDevice> {
    let mut out = Vec::new();
    let Some(ccs) = current_control_set(hive) else { return out };
    let mounted = mounted_devices(hive);
    for (sub, data_type) in [("USBSTOR", "windows:registry:usbstor"), ("USB", "windows:registry:usb")] {
        let rel = format!("{ccs}\\Enum\\{sub}");
        let Some(enum_key) = hive.key(&rel) else { continue };
        for dev in enum_key.subkeys() {
            let (class, ven, prod, rev) = if sub == "USBSTOR" {
                parse_usbstor_class(&dev.name)
            } else {
                let mut vid = None;
                let mut pid = None;
                for p in dev.name.split('&') {
                    if let Some(v) = p.strip_prefix("VID_") {
                        vid = Some(v.to_string());
                    } else if let Some(v) = p.strip_prefix("PID_") {
                        pid = Some(v.to_string());
                    }
                }
                (dev.name.clone(), vid, pid, None)
            };
            for inst in dev.subkeys() {
                let serial_lc = inst.name.split('&').next().unwrap_or("").to_lowercase();
                let m: Vec<MountedDevice> = if serial_lc.len() >= 4 {
                    mounted.iter().filter(|m| m.data.to_lowercase().contains(&format!("#{serial_lc}"))).cloned().collect()
                } else {
                    vec![]
                };
                out.push(UsbDevice {
                    data_type,
                    key_rel_path: join(&join(&rel, &dev.name), &inst.name),
                    key_offset: inst.offset,
                    device_class: class.clone(),
                    vendor: ven.clone(),
                    product: prod.clone(),
                    revision: rev.clone(),
                    serial: inst.name.clone(),
                    friendly_name: inst.value_string("FriendlyName"),
                    device_desc: inst.value_string("DeviceDesc"),
                    last_written_ns: inst.last_written_ns,
                    first_install_ns: property_time(&inst, "0064"),
                    install_ns: property_time(&inst, "0065"),
                    last_arrival_ns: property_time(&inst, "0066"),
                    last_removal_ns: property_time(&inst, "0067"),
                    mounted: m,
                });
            }
        }
    }
    out
}

pub fn system_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let mut out = Vec::new();
    for d in devices(hive) {
        let label = d.friendly_name.clone().or(d.device_desc.clone()).unwrap_or_else(|| d.device_class.clone());
        let mk = |td: &str, ts: Option<i64>| {
            let letters: Vec<String> = d.mounted.iter().filter(|m| m.name.starts_with("\\DosDevices\\")).map(|m| m.name.trim_start_matches("\\DosDevices\\").to_string()).collect();
            let vols: Vec<String> = d.mounted.iter().filter(|m| m.name.starts_with("\\??\\Volume")).map(|m| m.name.trim_start_matches("\\??\\Volume").to_string()).collect();
            let mut e = ctx
                .event("usb", d.data_type, td, ts, format!("[{}] {} serial: {}", ctx.full_path(&d.key_rel_path), label, d.serial), &d.key_rel_path, d.key_offset)
                .attr("device_class", d.device_class.clone())
                .attr("serial", d.serial.clone())
                .attr("drive_letters", json!(letters))
                .attr("volume_guids", json!(vols));
            for (k, v) in [("vendor", &d.vendor), ("product", &d.product), ("revision", &d.revision), ("friendly_name", &d.friendly_name), ("device_description", &d.device_desc)] {
                if let Some(v) = v {
                    e = e.attr(k, v.clone());
                }
            }
            e
        };
        out.push(mk(desc::WRITTEN, d.last_written_ns));
        if d.first_install_ns.is_some() {
            out.push(mk("First Install Time", d.first_install_ns));
        }
        if d.install_ns.is_some() {
            out.push(mk(desc::INSTALLATION, d.install_ns));
        }
        if d.last_arrival_ns.is_some() {
            out.push(mk("Last Connection Time", d.last_arrival_ns));
        }
        if d.last_removal_ns.is_some() {
            out.push(mk("Last Removal Time", d.last_removal_ns));
        }
    }
    out
}

/// SOFTWARE: Windows Portable Devices.
pub fn software_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let rel = "Microsoft\\Windows Portable Devices\\Devices";
    let Some(k) = hive.key(rel) else { return vec![] };
    k.subkeys()
        .into_iter()
        .map(|d| {
            let fname = d.value_string("FriendlyName").unwrap_or_default();
            let serial = d.name.split('#').rev().nth(1).unwrap_or("").to_string();
            let r = join(rel, &d.name);
            ctx.event("usb", "windows:registry:windows_portable_devices", desc::WRITTEN, d.last_written_ns, format!("[{}] Friendly name: {fname}", ctx.full_path(&r)), &r, d.offset)
                .attr("device_id", d.name.clone())
                .attr("friendly_name", fname)
                .attr("serial", serial)
        })
        .collect()
}

/// NTUSER: MountPoints2 subkeys (volume GUIDs, drive letters, network shares used by the user).
pub fn ntuser_events(hive: &Hive, ctx: &Ctx<'_>) -> Vec<Event> {
    let rel = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2";
    let Some(k) = hive.key(rel) else { return vec![] };
    k.subkeys()
        .into_iter()
        .map(|m| {
            let r = join(rel, &m.name);
            let (kind, attr_key, val) = if m.name.starts_with('{') {
                ("volume", "volume_guid", m.name.clone())
            } else if m.name.starts_with("##") {
                ("remote_drive", "share_name", m.name.replace('#', "\\"))
            } else {
                ("drive", "drive_letter", m.name.clone())
            };
            ctx.event("mountpoints2", "windows:registry:mount_points2", desc::WRITTEN, m.last_written_ns, format!("[{}] Type: {kind} {val}", ctx.full_path(&r)), &r, m.offset)
                .attr("type", kind)
                .attr(attr_key, val)
                .attr("label", m.value_string("_LabelFromReg").unwrap_or_default())
        })
        .collect()
}
