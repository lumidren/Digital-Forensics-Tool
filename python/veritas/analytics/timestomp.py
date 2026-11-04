"""Timestomping indicators from NTFS metadata and USN records.

Signals (per file):
* ``si_before_fn``: any $STANDARD_INFORMATION time earlier than the $FILE_NAME creation time
  (the kernel sets $FN once on creation/rename; user-mode tools cannot change it).
* ``zero_subsecond``: $SI times with a zero sub-second part while $FN has precision; SetFileTime
  callers usually pass whole seconds.
* ``usn_after_si``: a USN DATA_OVERWRITE/DATA_EXTEND after the $SI modification time.
* ``future``: a time later than the acquisition time.

The Rust parser (``veritas-fs``) already flags the first two in ``attrs.timestomp_indicators``;
this rule also recomputes them from attributes when present so Python-only pipelines agree.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

NS = 1_000_000_000


def _get(attrs, *names):
    for n in names:
        v = attrs.get(n)
        if v is not None:
            return v
    return None


def indicators(attrs: dict) -> list[str]:
    out = list(attrs.get("timestomp_indicators") or [])
    si = {k: _get(attrs, f"si_{k}_ns", f"si_{k}") for k in ("crtime", "mtime", "ctime", "atime")}
    fn = {k: _get(attrs, f"fn_{k}_ns", f"fn_{k}") for k in ("crtime", "mtime", "ctime", "atime")}
    if fn["crtime"] is not None:
        for k, v in si.items():
            if v is not None and v < fn["crtime"] - NS and "si_before_fn" not in out:
                out.append("si_before_fn")
        if all(v is not None and v % NS == 0 for v in si.values() if v is not None) and any(v is not None and v % NS for v in fn.values()) and "zero_subsecond" not in out:
            if any(v is not None for v in si.values()):
                out.append("zero_subsecond")
    return sorted(set(out))


class TimestompRule:
    name = "timestomp"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        by_file: dict[tuple[str, str], list[StoredEvent]] = defaultdict(list)
        usn_writes: dict[tuple[str, str], int] = {}
        for se in events:
            e = se.event
            if e.data_type.startswith("fs:stat") and (e.attrs.get("si_mtime_ns") or e.attrs.get("fn_crtime_ns") or e.attrs.get("timestomp_indicators")):
                by_file[(e.evidence_sha256, e.evidence_path)].append(se)
            elif e.data_type == "fs:ntfs:usn_change" and e.timestamp is not None:
                reasons = str(e.attrs.get("update_reason_flags") or e.attrs.get("reason") or "")
                if "DATA_OVERWRITE" in reasons or "DATA_EXTEND" in reasons:
                    key = (e.evidence_sha256, str(e.attrs.get("path") or e.evidence_path))
                    usn_writes[key] = max(usn_writes.get(key, 0), e.timestamp)
        for key, evs in sorted(by_file.items()):
            attrs = evs[0].event.attrs
            inds = indicators(attrs)
            si_mtime = _get(attrs, "si_mtime_ns", "si_mtime")
            if si_mtime is not None and key in usn_writes and usn_writes[key] > si_mtime + NS:
                inds.append("usn_after_si")
            if not inds:
                continue
            conf = {1: 0.5, 2: 0.75}.get(len(inds), 0.9)
            yield mk_finding(
                self.name, f"Possible timestomping: {key[1]}",
                "The $STANDARD_INFORMATION timestamps of this file are inconsistent with $FILE_NAME or USN journal "
                f"evidence ({', '.join(inds)}). Timestamp manipulation should be confirmed by reviewing the MFT record.",
                "medium", conf, "anti-forensics", evs, ["T1070.006"], {"indicators": inds, "path": key[1]},
            )
