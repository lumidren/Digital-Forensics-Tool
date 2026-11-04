"""Timestomping indicators from NTFS metadata and USN records.

Installers, archive extractors and copy tools set ``$STANDARD_INFORMATION`` times through the same
``SetFileTime`` API that timestomping tools use, so on a real Windows volume thousands of files show
"$SI earlier than $FN" with whole-second precision. Measured on the plaso ``MFT`` reference
extract (Windows XP): 4,294 of 13,064 files match the combined pattern, almost all of them laid
down by installers. Reporting each as "possible timestomping" would bury the real signal, so the
rule grades evidence:

1. **USN contradiction (strong, individual finding).** The USN journal records a data change
   (``DATA_OVERWRITE`` / ``DATA_EXTEND`` / ``DATA_TRUNCATION``) after the ``$SI`` modification time.
   The journal is written by the file-system driver and a user-mode timestomper does not rewrite it.
2. **Isolated $SI/$FN anomaly (medium, individual finding).** ``$SI`` creation earlier than ``$FN``
   creation *and* ``$SI`` creation with zero sub-seconds while ``$FN`` has sub-seconds, for a file
   that sits outside installation trees and whose directory siblings mostly do *not* show the
   pattern. Bulk installs light up whole directories; a single stomped file stands out.
3. **Everything else (low, one aggregate finding per evidence item)** listing the directories with
   the most anomalies, so the examiner can see the volume-wide picture without one finding per file.

The Rust parser adds ``si_*_ns``, ``fn_*_ns`` and ``timestomp_indicators`` to every ``fs:stat:ntfs``
event; this rule recomputes what it needs from those attributes.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

NS = 1_000_000_000
USN_TOLERANCE_NS = 2 * NS
DATA_CHANGE = ("DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION")
INSTALL_TREES = re.compile(r"(?i)^/?(?:p\d+:)?/?(program files( \(x86\))?|programdata|windows|winnt|\$recycle\.bin|system volume information|i386|drivers|msocache|\$windows\.~bt|\$windows\.~ws)(/|$)")
# Files written by Windows Setup at the volume root.
SETUP_ROOT_FILES = re.compile(r"(?i)^/?(?:p\d+:)?/?(ntldr|ntdetect\.com|boot\.ini|bootmgr|bootsect\.bak|io\.sys|msdos\.sys|config\.sys|autoexec\.bat|arcldr\.exe|arcsetup\.exe|pagefile\.sys|hiberfil\.sys|swapfile\.sys)$")
ISOLATION_RATIO = 0.5
MAX_INDIVIDUAL = 200


def _get(attrs, *names):
    for n in names:
        v = attrs.get(n)
        if v is not None:
            return v
    return None


def indicators(attrs: dict) -> list[str]:
    """Indicators derivable from one entry's attributes (kept for API compatibility and tests)."""
    out = set(attrs.get("timestomp_indicators") or [])
    si = {k: _get(attrs, f"si_{k}_ns", f"si_{k}") for k in ("crtime", "mtime", "ctime", "atime")}
    fn = {k: _get(attrs, f"fn_{k}_ns", f"fn_{k}") for k in ("crtime", "mtime", "ctime", "atime")}
    if fn["crtime"] is not None:
        if any(v is not None and v < fn["crtime"] - NS for v in si.values()):
            out.add("si_before_fn")
        si_vals = [v for v in si.values() if v is not None]
        if si_vals and all(v % NS == 0 for v in si_vals) and any(v is not None and v % NS for v in fn.values()):
            out.add("zero_subsecond")
    return sorted(out)


def creation_anomaly(attrs: dict) -> bool:
    si_cr, fn_cr = attrs.get("si_crtime_ns"), attrs.get("fn_crtime_ns")
    return bool(si_cr is not None and fn_cr is not None and si_cr < fn_cr - NS and si_cr % NS == 0 and fn_cr % NS != 0)


def _volume(evidence_path: str) -> str:
    m = re.match(r"^(p\d+):", evidence_path or "")
    return m.group(1) if m else ""


def _parent(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


class TimestompRule:
    name = "timestomp"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        entries: dict[tuple[str, str, str], list[StoredEvent]] = defaultdict(list)
        usn_change: dict[tuple[str, str], int] = {}
        for se in events:
            e = se.event
            a = e.attrs
            if e.data_type == "fs:stat:ntfs" and a.get("file_reference"):
                entries[(e.evidence_sha256, _volume(e.evidence_path), str(a["file_reference"]))].append(se)
            elif e.data_type.startswith("fs:stat") and (a.get("si_crtime_ns") or a.get("timestomp_indicators")):
                entries[(e.evidence_sha256, _volume(e.evidence_path), e.evidence_path)].append(se)
            elif e.data_type == "fs:ntfs:usn_change" and e.timestamp is not None and a.get("file_reference"):
                reasons = str(a.get("update_reason") or a.get("update_reason_flags") or a.get("reason") or "")
                if any(r in reasons for r in DATA_CHANGE):
                    ukey = (_volume(e.evidence_path), str(a["file_reference"]))
                    usn_change[ukey] = max(usn_change.get(ukey, 0), e.timestamp)

        # Per-directory share of entries with the creation anomaly (peer-group context).
        by_dir: dict[tuple[str, str], list[bool]] = defaultdict(list)
        info: dict[tuple, tuple[dict, str, bool]] = {}
        for key, evs in entries.items():
            attrs = evs[0].event.attrs
            path = str(attrs.get("path") or evs[0].event.evidence_path)
            anom = creation_anomaly(attrs)
            info[key] = (attrs, path, anom)
            by_dir[(key[0], _parent(path))].append(anom)

        strong: list[tuple[float, Finding]] = []
        aggregate: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        agg_events: dict[str, list[StoredEvent]] = defaultdict(list)
        for key, (attrs, path, anom) in sorted(info.items()):
            evs = entries[key]
            inds = indicators(attrs)
            si_m = attrs.get("si_mtime_ns")
            usn_t = usn_change.get((key[1], key[2]))
            if si_m is not None and usn_t is not None and usn_t > si_m + USN_TOLERANCE_NS:
                f = mk_finding(
                    self.name, f"Timestamps contradicted by USN journal: {path}",
                    "The USN journal records a data change to this file after its $STANDARD_INFORMATION modification time. "
                    "The journal is maintained by the file-system driver; this combination is a strong indicator that the "
                    "$SI timestamps were set back after the change. Confirm against the MFT record and the USN entries.",
                    "high", 0.85, "anti-forensics", evs, ["T1070.006"],
                    {"path": path, "indicators": sorted(set(inds) | {"usn_after_si_mtime"}), "si_mtime_ns": si_m, "usn_change_ns": usn_t},
                )
                strong.append((0.85, f))
                continue
            if not anom:
                continue
            siblings = by_dir[(key[0], _parent(path))]
            ratio = sum(siblings) / len(siblings)
            if not INSTALL_TREES.search(path) and not SETUP_ROOT_FILES.search(path) and (len(siblings) < 3 or ratio < ISOLATION_RATIO):
                f = mk_finding(
                    self.name, f"Possible timestomping: {path}",
                    f"$STANDARD_INFORMATION creation time precedes $FILE_NAME creation time with whole-second precision, "
                    f"and only {sum(siblings)} of {len(siblings)} files in the same directory show this pattern. "
                    "Installers and copy tools can produce the same pattern; review the file's origin before confirming.",
                    "medium", 0.6, "anti-forensics", evs, ["T1070.006"],
                    {"path": path, "indicators": inds, "directory_anomaly_ratio": f"{ratio:.2f}"},
                )
                strong.append((0.6, f))
            else:
                aggregate[key[0]][_parent(path) or "/"] += 1
                if len(agg_events[key[0]]) < 50:
                    agg_events[key[0]].append(evs[0])

        strong.sort(key=lambda t: (-t[0], t[1].title))
        for _, f in strong[:MAX_INDIVIDUAL]:
            yield f
        if len(strong) > MAX_INDIVIDUAL:
            yield mk_finding(self.name, f"{len(strong) - MAX_INDIVIDUAL} further individual timestamp anomalies not listed",
                             "The individual-finding cap was reached; search the timeline for timestomp_indicators to review the rest.",
                             "low", 0.3, "anti-forensics", [], ["T1070.006"], {"omitted": len(strong) - MAX_INDIVIDUAL})
        for sha, dirs in sorted(aggregate.items()):
            total = sum(dirs.values())
            top = sorted(dirs.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
            yield mk_finding(
                self.name, f"{total} files with $SI/$FN creation-time anomalies in installation or bulk-copied directories",
                "These files show the timestomping pattern, but in directories where most files share it (typical of "
                "installers and archive extraction) or inside installation trees. Listed for context; not individually "
                "suspicious.", "low", 0.2, "anti-forensics", agg_events[sha], ["T1070.006"],
                {"total": total, "top_directories": [{"directory": d, "files": n} for d, n in top]},
            )
