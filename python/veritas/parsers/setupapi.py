"""Windows ``setupapi.dev.log`` / ``setupapi.setup.log`` (Vista+ text format).

Each install section starts with ``>>>  [<description>]`` followed by
``>>>  Section start yyyy/mm/dd HH:MM:SS.mmm`` and ends with ``<<<  Section end <time>`` and
``<<<  [Exit status: SUCCESS]``. One ``windows:setupapi:log:line`` event is produced for the
section start and one for the section end (plaso's representation). Times are local time of
the machine as written (``attrs.time_is_local``). Device instance IDs (``USB\\VID_...``) are
extracted into ``attrs.device_instance_id`` for USB-history correlation.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser
from veritas.timeline.schema import Desc, Event

SECTION_HEADER = re.compile(r"^>>>\s+\[(?P<desc>.*)\]\s*$")
SECTION_START = re.compile(r"^>>>\s+Section start (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)")
SECTION_END = re.compile(r"^<<<\s+Section end (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)")
EXIT_STATUS = re.compile(r"^<<<\s+\[Exit status:\s*(?P<status>[^\]]*)\]")
DEVICE_ID = re.compile(r"(?:-\s+|\[)?((?:USB|USBSTOR|SWD|PCI|HID|STORAGE|SCSI|ROOT|BTH\w*|WPDBUSENUM|DISPLAY|ACPI|HDAUDIO|SW)\\[^\]\s]+)", re.I)


def _ts(text: str) -> int | None:
    for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return int(dt.timestamp()) * 1_000_000_000 + dt.microsecond * 1000
        except ValueError:
            continue
    return None


class SetupApiParser(TextLogParser):
    name = "setupapi"
    version = "1.0"
    source_short = "LOG"
    source_long = "SetupAPI log"
    head_regex = re.compile(r"\[(Device Install Log|SetupAPI Log)\]")

    def begin(self, prov: Provenance) -> None:
        self.desc: str | None = None
        self.desc_line = 0
        self.start: int | None = None
        self.end: int | None = None
        self.end_line = 0

    def _attrs(self, status: str | None = None) -> dict:
        m = DEVICE_ID.search(self.desc or "")
        return {"entry_type": self.desc or "", "exit_status": status, "time_is_local": True,
                "device_instance_id": m.group(1) if m else None}

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        m = SECTION_HEADER.match(line)
        if m:
            self.desc, self.desc_line, self.start, self.end = m.group("desc"), lineno, None, None
            return
        m = SECTION_START.match(line)
        if m and self.desc is not None:
            self.start = _ts(m.group("ts"))
            yield self.event("windows:setupapi:log:line", "Added Time", f"{self.desc} - Section start",
                             self.start, offset=self.desc_line, attrs=self._attrs())
            return
        m = SECTION_END.match(line)
        if m:
            self.end, self.end_line = _ts(m.group("ts")), lineno
            return
        m = EXIT_STATUS.match(line)
        if m and self.desc is not None:
            status = m.group("status").strip()
            # Same offset as the section start: one install section is one record with two times.
            yield self.event("windows:setupapi:log:line", Desc.END, f"{self.desc} - {status}", self.end,
                             offset=self.desc_line, attrs=self._attrs(status))
            self.desc = None


PARSERS = [SetupApiParser]
