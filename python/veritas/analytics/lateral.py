"""Lateral-movement reconstruction from Windows event logs.

Edges are built from: 4624 (logon type 3/10 with source address), 4648 (explicit credentials),
4672 (special privileges after a network logon), 7045 (service installed, PsExec style), 4698
(task created), WMI-Activity 5857/5861, TerminalServices 21/22/25/1149, SMB 5140/5145.
The result is a directed graph ``source -> destination`` with per-edge technique labels.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

RDP_IDS = {21: "T1021.001", 22: "T1021.001", 25: "T1021.001", 1149: "T1021.001", 131: "T1021.001"}
SERVICE_NAMES = {"psexesvc", "paexec", "remcom", "csexec", "winexesvc", "bhsvc"}


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    user: str
    technique: str
    kind: str
    event_ids: list[int] = field(default_factory=list)
    first_ns: int | None = None
    last_ns: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"src": self.src, "dst": self.dst, "user": self.user, "technique": self.technique, "kind": self.kind, "count": len(self.event_ids), "event_ids": sorted(self.event_ids), "first_ns": self.first_ns, "last_ns": self.last_ns}


def _ed(a: dict, *keys: str) -> str:
    ed = a.get("event_data") or {}
    for k in keys:
        v = a.get(k)
        if v in (None, "", "-"):
            v = ed.get(k)
        if v not in (None, "", "-"):
            return str(v)
    return ""


def build_graph(events: Iterable[StoredEvent]) -> list[Edge]:
    edges: dict[tuple, Edge] = {}

    def add(src: str, dst: str, user: str, tech: str, kind: str, se: StoredEvent) -> None:
        if not dst:
            return
        key = (src.lower(), dst.lower(), user.lower(), tech, kind)
        ed = edges.get(key)
        if ed is None:
            ed = edges[key] = Edge(src, dst, user, tech, kind)
        ed.event_ids.append(se.id)
        t = se.event.timestamp
        if t is not None:
            ed.first_ns = t if ed.first_ns is None else min(ed.first_ns, t)
            ed.last_ns = t if ed.last_ns is None else max(ed.last_ns, t)

    for se in events:
        e = se.event
        if e.data_type not in ("windows:evtx:record", "windows:evt:record"):
            continue
        a = e.attrs
        eid = a.get("event_identifier")
        dst = e.host or str(a.get("computer_name") or "")
        prov = str(a.get("source_name") or a.get("provider") or "")
        if eid == 4624:
            lt = _ed(a, "logon_type", "LogonType")
            src = _ed(a, "ip_address", "IpAddress", "WorkstationName")
            user = _ed(a, "target_user_name", "TargetUserName")
            if lt in ("3", "10", "8", "9") and src not in ("", "::1", "127.0.0.1", "-"):
                add(src, dst, user, "T1021.001" if lt == "10" else "T1021.002" if lt == "3" else "T1078", f"logon_type_{lt}", se)
            if _ed(a, "logon_process_name", "LogonProcessName").lower() == "ntlmssp" and lt == "3" and _ed(a, "authentication_package_name", "AuthenticationPackageName").upper() == "NTLM" and src:
                add(src, dst, user, "T1550.002", "ntlm_network_logon", se)
        elif eid == 4648:
            target_server = _ed(a, "target_server_name", "TargetServerName")
            user = _ed(a, "target_user_name", "TargetUserName")
            if target_server and target_server.lower() not in ("localhost", dst.lower()):
                add(dst, target_server, user, "T1078", "explicit_credentials", se)
        elif eid == 7045:
            svc = _ed(a, "service_name", "ServiceName").lower()
            img = _ed(a, "image_path", "ImagePath").lower()
            if svc in SERVICE_NAMES or any(s in img for s in SERVICE_NAMES) or "\\\\" in img or "admin$" in img:
                add("remote", dst, _ed(a, "user_sid", "AccountName"), "T1569.002", "remote_service_install", se)
        elif eid == 4698:
            add("remote", dst, _ed(a, "subject_user_name", "SubjectUserName"), "T1053.005", "scheduled_task_created", se)
        elif eid in (5857, 5861) and "WMI" in prov:
            add("remote", dst, e.user or "", "T1047", "wmi_subscription" if eid == 5861 else "wmi_provider_load", se)
        elif eid in RDP_IDS and ("TerminalServices" in prov or "RemoteDesktop" in prov or "RdpCoreTS" in prov):
            src = _ed(a, "address", "Address", "ClientIP", "ip_address")
            add(src, dst, _ed(a, "user", "User", "Param1"), RDP_IDS[eid], f"rdp_{eid}", se)
        elif eid in (5140, 5145):
            share = _ed(a, "share_name", "ShareName")
            src = _ed(a, "ip_address", "IpAddress")
            if share.upper().endswith(("ADMIN$", "C$", "IPC$")) and src:
                add(src, dst, _ed(a, "subject_user_name", "SubjectUserName"), "T1021.002", f"admin_share_{share.split(chr(92))[-1].lower()}", se)
        elif eid == 4625:
            src = _ed(a, "ip_address", "IpAddress")
            if src:
                add(src, dst, _ed(a, "target_user_name", "TargetUserName"), "T1110", "failed_logon", se)
    return sorted(edges.values(), key=lambda e: (e.first_ns or 0, e.src, e.dst, e.kind))


class LateralMovementRule:
    name = "lateral_movement"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        cached = list(events)
        by_id = {se.id: se for se in cached}
        edges = build_graph(cached)
        by_pair: dict[tuple[str, str], list[Edge]] = defaultdict(list)
        for ed in edges:
            by_pair[(ed.src, ed.dst)].append(ed)
        for (src, dst), eds in sorted(by_pair.items()):
            kinds = sorted({e.kind for e in eds})
            if kinds == ["failed_logon"]:
                n = sum(len(e.event_ids) for e in eds)
                if n >= 20:
                    evs = [by_id[i] for e in eds for i in e.event_ids[:200] if i in by_id]
                    yield mk_finding(self.name, f"Password guessing from {src} against {dst}", f"{n} failed logons (4625) from one source.", "medium", 0.7, "credential-access", evs, ["T1110"], {"source": src, "destination": dst, "attempts": n})
                continue
            strong = [e for e in eds if e.kind in ("remote_service_install", "scheduled_task_created", "wmi_subscription", "explicit_credentials", "ntlm_network_logon") or e.kind.startswith("rdp_") or e.kind.startswith("admin_share")]
            if not strong and not any(e.kind == "logon_type_10" for e in eds):
                continue
            evs = [by_id[i] for e in eds for i in e.event_ids[:200] if i in by_id]
            techs = sorted({e.technique for e in eds})
            yield mk_finding(self.name, f"Lateral movement {src} -> {dst}", f"Observed: {', '.join(kinds)}; users: {', '.join(sorted({e.user for e in eds if e.user}))}.", "high" if strong else "medium", 0.8 if strong else 0.6, "lateral-movement", evs, techs, {"edges": [e.to_dict() for e in eds]})
