"""Persistence inventory across Windows, Linux and macOS artifacts."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

PERSISTENCE_TYPES = {
    "windows:registry:run": ("run_key", "T1547.001"),
    "windows:registry:service": ("service", "T1543.003"),
    "windows:tasks:job": ("scheduled_task", "T1053.005"),
    "windows:tasks:xml": ("scheduled_task", "T1053.005"),
    "windows:wmi:subscription": ("wmi", "T1546.003"),
    "windows:registry:ifeo": ("ifeo", "T1546.012"),
    "linux:cron:entry": ("cron", "T1053.003"),
    "linux:systemd:unit": ("systemd", "T1543.002"),
    "linux:ssh:authorized_key": ("ssh_key", "T1098.004"),
    "macos:launchd:agent": ("launch_agent", "T1543.001"),
    "macos:launchd:daemon": ("launch_daemon", "T1543.004"),
    "macos:login_items:entry": ("login_item", "T1547.015"),
}

SUSPICIOUS_PATH = re.compile(r"(?i)(\\users\\[^\\]+\\appdata\\(local|roaming)\\temp\\|\\programdata\\[^\\]+\.(exe|dll|ps1|vbs|js|bat)|\\windows\\temp\\|/tmp/|/dev/shm/|\\public\\|%temp%|powershell.*-enc|-encodedcommand|mshta|rundll32.*javascript|regsvr32.*/s.*/i:|wscript|cscript|certutil.*-decode|\.(hta|vbs|js|jse|wsf)\b)")


class PersistenceInventoryRule:
    name = "persistence"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        inventory: dict[str, list[StoredEvent]] = defaultdict(list)
        suspicious: list[StoredEvent] = []
        seen: set[tuple] = set()
        for se in events:
            e = se.event
            kind = PERSISTENCE_TYPES.get(e.data_type)
            if kind is None and e.data_type == "windows:evtx:record" and e.attrs.get("event_identifier") in (7045, 4698, 4702):
                kind = ("service" if e.attrs.get("event_identifier") == 7045 else "scheduled_task", "T1543.003" if e.attrs.get("event_identifier") == 7045 else "T1053.005")
            if kind is None:
                continue
            key = (e.evidence_sha256, e.data_type, e.message)
            if key in seen:
                continue
            seen.add(key)
            inventory[kind[0]].append(se)
            text = " ".join(str(v) for v in e.attrs.values() if isinstance(v, (str, int))) + " " + e.message
            if SUSPICIOUS_PATH.search(text):
                suspicious.append(se)
        for kind_name, evs in sorted(inventory.items()):
            tech = next(t for (k, t) in PERSISTENCE_TYPES.values() if k == kind_name) if any(k == kind_name for k, _ in PERSISTENCE_TYPES.values()) else "T1543"
            yield mk_finding(self.name, f"Persistence inventory: {kind_name} ({len(evs)})", f"{len(evs)} {kind_name} entries were found. This is an inventory for review, not an allegation.", "info", 0.3, "persistence", evs, [tech], {"count": len(evs)})
        if suspicious:
            yield mk_finding(self.name, "Persistence entries with suspicious locations or launchers", "Autostart entries reference temp/public directories, encoded PowerShell or script hosts.", "high", 0.75, "persistence", suspicious, ["T1547.001", "T1059.001"], {"count": len(suspicious)})
