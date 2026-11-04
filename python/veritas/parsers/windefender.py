"""Windows Defender artifacts.

* ``DetectionHistory`` files (``ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\
  DetectionHistory\\<nn>\\<GUID>``): a flat sequence of typed values
  ``data_size(u32) data_type(u32) data[data_size]`` padded to 8 bytes. The UTF-16
  ``Magic.Version:1.2`` string starts each of the three value sets; set 2 value 5 is a
  "threat tracking" key/value blob holding ``ThreatTrackingStartTime`` (FILETIME) etc.
  -> ``av:defender:detection_history`` (Recorded Time).
* ``MPLog-*.log`` text logs: lines beginning with an ISO-8601 timestamp; threat/detection
  related lines (``DETECTION``, ``Threat``, ``EMS``, ``SDN``) become ``av:defender:mplog`` events,
  everything else is skipped (MPLog is very chatty).
"""
from __future__ import annotations

import re
import struct
import uuid
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import Desc, Event, filetime_to_ns, iso_to_ns

SIGNATURE = "Magic.Version:1.2"
SIG_BYTES = SIGNATURE.encode("utf-16-le")
MAX_FILE = 16 * 1024 * 1024
DESCRIPTIONS = [
    {0: "Threat identifier", 1: "Identifier"},
    {0: "UnknownMagic1", 1: "Threat name", 4: "Category"},
    {0: "UnknownMagic2", 1: "Resource type", 2: "Resource location", 4: "Threat tracking data size",
     5: "Threat tracking data", 6: "Last threat status change time", 12: "Domain user1", 14: "Process name",
     18: "Initial detection time", 20: "Remediation time", 24: "Domain user2"},
]


def _read_values(data: bytes) -> list[tuple[int, Any]]:
    out = []
    off = 0
    while off + 8 <= len(data):
        size, dtype = struct.unpack_from("<II", data, off)
        start = off + 8
        if start + size > len(data):
            raise ParserError(f"windefender: value at {off} overruns file")
        raw = data[start:start + size]
        if dtype in (0, 5, 6, 8) and size in (1, 2, 4, 8):
            val: Any = int.from_bytes(raw, "little")
        elif dtype == 0x0A and size == 8:
            val = ("filetime", struct.unpack("<Q", raw)[0])
        elif dtype == 0x15:
            val = raw.decode("utf-16-le", "replace").rstrip("\x00")
        elif dtype == 0x1E and size == 16:
            val = str(uuid.UUID(bytes_le=raw))
        else:
            val = raw
        out.append((off, val))
        off = start + size
        off += (-off) % 8
    if 0 < len(data) - off < 8:
        raise ParserError("windefender: trailing partial value header")
    return out


def _tracking(blob: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if len(blob) < 4:
        return out
    first = struct.unpack_from("<I", blob, 0)[0]
    if first != 1:
        off, end = 4, min(first, len(blob))
    else:
        if len(blob) < 20:
            return out
        _ver, hsize, _vsize, total, _ = struct.unpack_from("<5I", blob, 0)
        off, end = hsize + 4, min(total, len(blob))
    count = 0
    while off + 8 <= end and count < 4096:
        count += 1
        ksize = struct.unpack_from("<I", blob, off)[0]
        if off + 4 + ksize + 4 > len(blob):
            break
        key = blob[off + 4:off + 4 + ksize].decode("utf-16-le", "replace").rstrip("\x00")
        p = off + 4 + ksize
        vtype = struct.unpack_from("<I", blob, p)[0]
        p += 4
        if vtype == 7:
            val: Any = blob[p:p + 5].hex()
            p += 5
        elif vtype == 5:
            val = blob[p]
            p += 1
        elif vtype == 3:
            val = struct.unpack_from("<I", blob, p)[0]
            p += 4
        elif vtype == 4:
            val = struct.unpack_from("<Q", blob, p)[0]
            p += 8
        elif vtype == 6:
            vsize = struct.unpack_from("<I", blob, p)[0]
            val = blob[p + 4:p + 4 + vsize].decode("utf-16-le", "replace").rstrip("\x00")
            p += 4 + vsize
        else:
            break
        out[key] = val
        off = p
    return out


class DefenderDetectionHistoryParser(BaseParser):
    name = "windefender_history"
    version = "1.0"
    source_short = "AV"
    source_long = "Windows Defender DetectionHistory"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return head_bytes[0x30:0x30 + len(SIG_BYTES)] == SIG_BYTES

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ParserError("windefender: file too large")
        if data[0x30:0x30 + len(SIG_BYTES)] != SIG_BYTES:
            raise ParserError("windefender: missing Magic.Version signature")
        values = _read_values(data)
        attrs_raw: dict[str, Any] = {}
        resources: list[dict[str, str]] = []
        rtype: str | None = ""
        vset, vidx = 0, 0
        for off, val in values:
            if val == SIGNATURE:
                vset = min(vset + 1, 2)
                vidx = 0
            if (vset, vidx) == (2, 5) and isinstance(val, bytes):
                attrs_raw.update(_tracking(val))
            else:
                desc = DESCRIPTIONS[vset].get(vidx, f"UNKNOWN_{vset}_{vidx}")
                if desc == "Resource type":
                    rtype = str(val)
                elif desc == "Resource location" and rtype is not None:
                    resources.append({"type": rtype, "location": str(val)})
                    rtype = None
                else:
                    attrs_raw[desc] = val
            vidx += 1
        if attrs_raw.get("Threat name") is None and not any(k.startswith("ThreatTracking") for k in attrs_raw):
            raise ParserError("windefender: truncated or incomplete file (no threat name or tracking data)")
        files = [r["location"] for r in resources if r["type"] == "file"]
        if not files:
            files = [",".join(x for x in (attrs_raw.get("CONTEXT_DATA_FILENAME"), attrs_raw.get("CONTEXT_DATA_PROCESS_PPID")) if x)]
        start = attrs_raw.get("ThreatTrackingStartTime")
        ts = filetime_to_ns(start) if isinstance(start, int) and start else None
        attrs = {
            "filename": files[0] if files else "",
            "web_filenames": [r["location"] for r in resources if r["type"] == "webfile"],
            "container_filenames": [r["location"] for r in resources if r["type"] == "containerfile"],
            "additional_filenames": [r["location"] for r in resources if "file" not in r["type"]],
            "threat_name": attrs_raw.get("Threat name"), "host_and_user": attrs_raw.get("Domain user1"),
            "process": attrs_raw.get("Process name"), "sha256": attrs_raw.get("ThreatTrackingSha256"),
            "threat_identifier": attrs_raw.get("Threat identifier") if isinstance(attrs_raw.get("Threat identifier"), str) else None,
        }
        for key in ("ThreatTrackingSigSeq", "ThreatTrackingThreatId", "ThreatTrackingIsEsuSig"):
            if key in attrs_raw and isinstance(attrs_raw[key], (int, str)):
                attrs[key] = attrs_raw[key]
        msg = f"{attrs['threat_name']} detected in {attrs['filename']} by {attrs['process']}"
        yield self.event("av:defender:detection_history", "Recorded Time", msg, ts, offset=0, attrs=attrs,
                         user=attrs["host_and_user"])


MPLOG_LINE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<msg>.*)$")
MPLOG_INTERESTING = re.compile(r"(DETECTION|Threat|threat|EMS|SDN|Detection|Quarantine|RTP)")


class DefenderMpLogParser(TextLogParser):
    name = "windefender_mplog"
    version = "1.0"
    source_short = "AV"
    source_long = "Windows Defender MPLog"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return path.replace("\\", "/").rsplit("/", 1)[-1].lower().startswith("mplog")

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = MPLOG_LINE.match(line.strip())
        if not m or not MPLOG_INTERESTING.search(m.group("msg")):
            return
        ts = iso_to_ns(m.group("ts"))
        yield self.event("av:defender:mplog", Desc.EVENT if ts else Desc.NOT_A_TIME, m.group("msg"), ts,
                         offset=lineno, attrs={"body": m.group("msg")})


PARSERS = [DefenderDetectionHistoryParser, DefenderMpLogParser]
