//! `veritas-artifacts-dump <kind> <path> [--json|--events] [--evidence-sha256 X]`
//!
//! Prints parser output as deterministic JSON lines. `--json` (default) prints the parsed
//! structure (one line per record for record-oriented formats); `--events` prints timeline
//! events sorted by `veritas_timeline::write_jsonl`.
use clap::Parser;
use serde_json::{json, Value};
use std::io::Write;
use std::process::ExitCode;
use veritas_artifacts::{
    evtx, journald, jumplist, lnk, olecf, plist, prefetch, regf, registry, shellitems, taskjob,
};
use veritas_timeline::{write_jsonl, Event};

#[derive(Parser, Debug)]
#[command(
    name = "veritas-artifacts-dump",
    about = "Dump Veritas artifact parser output as JSON lines"
)]
struct Args {
    /// evtx | evt | prefetch | lnk | shellitems (hex lines) | jumplist | olecf | journald | plist |
    /// taskjob | taskxml | regf | registry (all plugins) | shimcache | amcache | userassist |
    /// shellbags | services | bam | network | recentdocs | usb | autoruns | sysinfo
    kind: String,
    path: String,
    /// Print the parsed structure (default).
    #[arg(long, conflicts_with = "events")]
    json: bool,
    /// Print timeline events instead.
    #[arg(long)]
    events: bool,
    /// Evidence SHA-256 recorded in events (default: SHA-256 of the input file).
    #[arg(long = "evidence-sha256")]
    evidence_sha256: Option<String>,
}

type Out = (Vec<Value>, Vec<Event>);

fn run(args: &Args) -> Result<Out, String> {
    let data = std::fs::read(&args.path).map_err(|e| format!("read {}: {e}", args.path))?;
    let sha = args
        .evidence_sha256
        .clone()
        .unwrap_or_else(|| veritas_hash::sha256_hex(&data));
    let path = args.path.as_str();
    let want_events = args.events;
    let e = |x: veritas_artifacts::error::ParseError| x.to_string();
    let to = |v: &dyn erased::Ser| v.value();
    Ok(match args.kind.as_str() {
        "evtx" => {
            let f = evtx::parse(&data).map_err(e)?;
            let mut lines = Vec::new();
            if !want_events {
                lines.push(json!({"header": f.header, "chunks": f.chunks.iter().map(|c| json!({"index": c.index, "offset": c.offset, "header_crc_ok": c.header_crc_ok, "data_crc_ok": c.data_crc_ok, "records": c.records, "errors": c.errors})).collect::<Vec<_>>()}));
                for r in &f.records {
                    let mut v = serde_json::to_value(r).map_err(|x| x.to_string())?;
                    v["event_data_map"] = Value::Object(r.event_data_map());
                    v["source_name"] = json!(r.source_name());
                    lines.push(v);
                }
            }
            (
                lines,
                if want_events {
                    evtx::events(&f, &sha, path)
                } else {
                    vec![]
                },
            )
        }
        "evt" => {
            let r = evtx::parse_evt(&data).map_err(e)?;
            (
                r.iter().map(|x| to(x)).collect(),
                if want_events {
                    evtx::evt_events(&r, &sha, path)
                } else {
                    vec![]
                },
            )
        }
        "prefetch" => {
            let p = prefetch::parse(&data).map_err(e)?;
            (
                vec![to(&p)],
                if want_events {
                    prefetch::events(&p, &sha, path)
                } else {
                    vec![]
                },
            )
        }
        "lnk" => {
            let l = lnk::parse(&data).map_err(e)?;
            let mut v = to(&l);
            v["local_path"] = json!(l.local_path());
            v["network_path"] = json!(l.network_path());
            v["link_target_path"] = json!(shellitems::shell_item_path(&l.target_id_list));
            (
                vec![v],
                if want_events {
                    lnk::events(&l, &sha, path, 0)
                } else {
                    vec![]
                },
            )
        }
        "shellitems" => {
            // Input: a text file with one hex-encoded ID list per line (one output line each),
            // or the raw ID list bytes.
            let lists: Vec<Vec<u8>> = match std::str::from_utf8(&data) {
                Ok(s) if s.lines().all(|l| shellitems::parse_hex_input(l).is_ok()) => s
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| shellitems::parse_hex_input(l).unwrap_or_default())
                    .collect(),
                _ => vec![data.clone()],
            };
            let mut lines = Vec::new();
            for b in &lists {
                match shellitems::parse_shell_item_list(b) {
                    Ok(items) => lines
                        .push(json!({"items": items, "path": shellitems::shell_item_path(&items)})),
                    Err(err) => lines.push(json!({"error": err.to_string()})),
                }
            }
            (lines, vec![])
        }
        "jumplist" => {
            if olecf::is_olecf(&data) {
                let a = jumplist::parse_automatic(&data).map_err(e)?;
                let mut v = to(&a);
                if let Some(arr) = v["streams"].as_array_mut() {
                    for (s, src) in arr.iter_mut().zip(&a.streams) {
                        s["local_path"] = json!(src.lnk.as_ref().and_then(|l| l.local_path()));
                    }
                }
                (
                    vec![json!({"type": "automatic", "data": v})],
                    if want_events {
                        jumplist::automatic_events(&a, &sha, path)
                    } else {
                        vec![]
                    },
                )
            } else {
                let c = jumplist::parse_custom(&data).map_err(e)?;
                let mut v = to(&c);
                if let Some(arr) = v["entries"].as_array_mut() {
                    for (s, src) in arr.iter_mut().zip(&c.entries) {
                        s["local_path"] = json!(src.lnk.local_path());
                    }
                }
                (
                    vec![json!({"type": "custom", "data": v})],
                    if want_events {
                        jumplist::custom_events(&c, &sha, path)
                    } else {
                        vec![]
                    },
                )
            }
        }
        "olecf" => {
            let o = olecf::Olecf::parse(&data).map_err(e)?;
            let entries: Vec<Value> = o
                .walk()
                .into_iter()
                .map(|(p, i)| json!({"path": p, "entry": o.entries[i]}))
                .collect();
            (
                vec![json!({"entries": entries, "summary_information": o.summary_information()})],
                vec![],
            )
        }
        "journald" => {
            let j = journald::parse(&data).map_err(e)?;
            let mut lines =
                vec![json!({"header": j.header, "errors": j.errors, "entries": j.entries.len()})];
            if !want_events {
                lines.extend(j.entries.iter().map(|x| to(x)));
            }
            (
                lines,
                if want_events {
                    journald::events(&j, &sha, path)
                } else {
                    vec![]
                },
            )
        }
        "plist" => {
            let p = plist::parse(&data).map_err(e)?;
            let fmt = if data.starts_with(b"bplist") {
                "binary"
            } else {
                "xml"
            };
            let un = plist::unarchive(&p).map(|u| u.to_json());
            (
                vec![json!({"format": fmt, "value": p.to_json(), "unarchived": un})],
                if want_events {
                    plist::events(&p, &sha, path)
                } else {
                    vec![]
                },
            )
        }
        "taskjob" => {
            let j = taskjob::parse_job(&data).map_err(e)?;
            (
                vec![to(&j)],
                if want_events {
                    taskjob::job_events(&j, &sha, path)
                } else {
                    vec![]
                },
            )
        }
        "taskxml" => {
            let t = taskjob::parse_task_xml(&data).map_err(e)?;
            (
                vec![to(&t)],
                if want_events {
                    taskjob::xml_events(&t, &sha, path)
                } else {
                    vec![]
                },
            )
        }
        "regf" => {
            let hive = regf::Hive::parse(&data).map_err(e)?;
            let mut lines = Vec::new();
            for (kp, key) in hive.keys() {
                let _ = &key.name;
                let values: Vec<Value> = key
                    .values()
                    .iter()
                    .map(|v| json!({"name": v.name, "type": v.kind.name(), "data_hex": hex::encode(&v.raw)}))
                    .collect();
                lines.push(
                    json!({"path": kp, "last_written_ns": key.last_written_ns, "values": values}),
                );
            }
            (lines, vec![])
        }
        k => {
            // Dump kind -> registry plugin parser names (events carry `winreg/<plugin>`).
            let plugins: &[(&str, &[&str])] = &[
                ("registry", &[]),
                ("shimcache", &["appcompatcache"]),
                ("appcompatcache", &["appcompatcache"]),
                ("amcache", &["amcache"]),
                ("userassist", &["userassist"]),
                ("shellbags", &["shellbags"]),
                ("services", &["services"]),
                ("bam", &["bam"]),
                ("network", &["network_interfaces", "network"]),
                ("network_interfaces", &["network_interfaces"]),
                ("recentdocs", &["recentdocs", "mrulistex", "mrulist"]),
                ("usb", &["usb"]),
                ("autoruns", &["run", "autoruns"]),
                ("run", &["run"]),
                (
                    "sysinfo",
                    &["sysinfo", "windows_version", "profile_list", "shutdown"],
                ),
                ("winreg_default", &["winreg_default"]),
            ];
            let Some((_, names)) = plugins.iter().find(|(n, _)| *n == k) else {
                return Err(format!("unknown kind '{k}'"));
            };
            let hive = regf::Hive::parse(&data).map_err(e)?;
            let kind = registry::HiveKind::from_file_name(path)
                .unwrap_or_else(|| registry::HiveKind::detect(&hive));
            let prov = registry::Provenance {
                evidence_sha256: sha.clone(),
                evidence_path: path.to_string(),
                ..Default::default()
            };
            let mut evs = registry::events_from_hive(&hive, kind, &prov);
            if k != "registry" {
                evs.retain(|ev| {
                    names
                        .iter()
                        .any(|n| ev.parser.strip_prefix("winreg/").unwrap_or(&ev.parser) == *n)
                });
            }
            if want_events {
                (vec![], evs)
            } else {
                let mut sorted = evs;
                sorted.sort();
                (
                    sorted
                        .iter()
                        .map(|x| serde_json::to_value(x).unwrap_or(Value::Null))
                        .collect(),
                    vec![],
                )
            }
        }
    })
}

/// Small helper so heterogeneous `Serialize` types can be turned into `Value`.
mod erased {
    pub trait Ser {
        fn value(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Ser for T {
        fn value(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok((lines, mut events)) => {
            let stdout = std::io::stdout();
            let mut w = std::io::BufWriter::new(stdout.lock());
            let res = if args.events {
                write_jsonl(&mut events, &mut w)
            } else {
                lines.iter().try_for_each(|l| {
                    serde_json::to_writer(&mut w, l).map_err(std::io::Error::from)?;
                    w.write_all(b"\n")
                })
            };
            if let Err(e) = res.and_then(|_| w.flush()) {
                // Windows reports a closed pipe as ERROR_NO_DATA (232).
                if e.kind() == std::io::ErrorKind::BrokenPipe || e.raw_os_error() == Some(232) {
                    return ExitCode::SUCCESS; // reader went away (e.g. `| head`)
                }
                eprintln!("write error: {e}");
                return ExitCode::from(2);
            }
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(1)
        }
    }
}
