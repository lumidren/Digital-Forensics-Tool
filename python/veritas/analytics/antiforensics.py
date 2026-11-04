"""Anti-forensics indicators: log clearing, record-number gaps, history wiping, wiping tools. THREAT:T9.2"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

LOG_CLEAR_IDS = {("Security", 1102), ("System", 104), ("Security", 1100)}
WIPE_TOOLS = re.compile(r"(?i)\b(sdelete|cipher\.exe\s+/w|bcwipe|eraser\.exe|timestomp|wevtutil\s+cl|clear-eventlog|fsutil\s+usn\s+deletejournal|vssadmin\s+delete\s+shadows|wbadmin\s+delete|auditpol\s+/clear|history\s+-c|shred\s)")
DEFENDER_OFF = re.compile(r"(?i)(set-mpprefer\w*\s+-disable|DisableRealtimeMonitoring|DisableAntiSpyware)")


class AntiForensicsRule:
    name = "antiforensics"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        clears: list[StoredEvent] = []
        tool_runs: list[StoredEvent] = []
        defender: list[StoredEvent] = []
        per_log: dict[tuple[str, str], list[tuple[int, StoredEvent]]] = defaultdict(list)
        history_cleared: list[StoredEvent] = []
        for se in events:
            e = se.event
            a = e.attrs
            if e.data_type in ("windows:evtx:record", "windows:evt:record"):
                eid = a.get("event_identifier")
                chan = str(a.get("channel") or a.get("source_name") or "")
                if (chan.split("/")[-1], eid) in LOG_CLEAR_IDS or eid in (1102, 104) and "Security" in chan or eid == 104:
                    clears.append(se)
                rn = a.get("record_number")
                if isinstance(rn, int):
                    per_log[(e.evidence_sha256, e.evidence_path)].append((rn, se))
                text = " ".join(str(a.get(k) or "") for k in ("command_line", "process_name", "xml_string"))
                if WIPE_TOOLS.search(text):
                    tool_runs.append(se)
                if DEFENDER_OFF.search(text) or (eid in (5001, 5010, 5012) and "Defender" in chan):
                    defender.append(se)
            elif e.data_type in ("windows:prefetch:execution", "windows:registry:appcompatcache", "windows:registry:amcache", "bash:history:entry", "shell:zsh:history", "powershell:history:line", "windows:registry:userassist"):
                text = " ".join(str(a.get(k) or "") for k in ("executable", "path", "command", "value_name", "full_path"))
                if WIPE_TOOLS.search(text) or WIPE_TOOLS.search(e.message):
                    tool_runs.append(se)
            if e.data_type in ("bash:history:entry", "shell:zsh:history") and re.search(r"(?i)(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|rm\s+.*bash_history)", e.message):
                history_cleared.append(se)
        if clears:
            yield mk_finding(self.name, "Windows event log cleared", f"{len(clears)} log-clear event(s) (1102/104) were recorded. Review surrounding activity and the actor SID.", "high", 0.9, "anti-forensics", clears, ["T1070.001"], {"count": len(clears)})
        for key, items in sorted(per_log.items()):
            items.sort(key=lambda t: t[0])
            gaps = []
            for (a_rn, _), (b_rn, b_se) in zip(items, items[1:]):
                if b_rn - a_rn > 1:
                    gaps.append({"after_record": a_rn, "next_record": b_rn, "missing": b_rn - a_rn - 1})
            if gaps and sum(g["missing"] for g in gaps) >= 10:
                yield mk_finding(self.name, f"Record-number gaps in {key[1].rsplit('/', 1)[-1]}", f"{len(gaps)} gap(s) totalling {sum(g['missing'] for g in gaps)} missing record numbers. Gaps occur naturally after log rotation; large gaps inside a retained log suggest selective deletion.", "medium", 0.5, "anti-forensics", [se for _, se in items[:1]], ["T1070.001"], {"gaps": gaps[:50]})
        if tool_runs:
            yield mk_finding(self.name, "Wiping or log-clearing tool executed", "Execution evidence references a known wiping, timestomping or log-clearing command.", "high", 0.8, "anti-forensics", tool_runs, ["T1070.004", "T1070.001", "T1490"], {"count": len(tool_runs)})
        if defender:
            yield mk_finding(self.name, "Endpoint protection disabled", "Commands or events show real-time protection being disabled.", "high", 0.8, "defense-evasion", defender, ["T1562.001"], {})
        if history_cleared:
            yield mk_finding(self.name, "Shell history tampering", "Shell history shows commands that clear or disable history.", "medium", 0.7, "anti-forensics", history_cleared, ["T1070.003"], {})
