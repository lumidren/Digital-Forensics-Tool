"""Per-user activity reconstruction: sessions, documents, folders, programs, browsing."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Iterator

from ..timeline.store import StoredEvent
from .findings import Finding, mk_finding

CATEGORIES = {
    "windows:evtx:record": None,  # handled by event id
    "windows:shellbags": "folders_browsed",
    "windows:registry:mrulistex": "recent_documents",
    "windows:registry:mrulist": "commands_run",
    "windows:registry:userassist": "programs_launched",
    "windows:lnk:link": "files_opened",
    "windows:jump_list:automatic_destination": "files_opened",
    "windows:jump_list:custom_destination": "files_opened",
    "chrome:history:page_visited": "web_history",
    "firefox:places:page_visited": "web_history",
    "chrome:history:file_downloaded": "downloads",
    "firefox:downloads:download": "downloads",
    "windows:registry:typedurls": "web_history",
    "windows:timeline:generic": "programs_launched",
    "powershell:history:line": "commands_run",
    "bash:history:entry": "commands_run",
    "shell:zsh:history": "commands_run",
    "macos:knowledgec:application": "programs_launched",
    "windows:registry:usbstor": "removable_media",
    "windows:registry:usb": "removable_media",
}


def reconstruct(events: Iterable[StoredEvent]) -> dict[str, dict[str, Any]]:
    users: dict[str, dict[str, Any]] = defaultdict(lambda: {"logons": [], "categories": defaultdict(list), "first_ns": None, "last_ns": None, "hosts": set()})
    for se in events:
        e = se.event
        cat = CATEGORIES.get(e.data_type)
        user = e.user
        if e.data_type == "windows:evtx:record":
            eid = e.attrs.get("event_identifier")
            ed = e.attrs.get("event_data") or {}
            if eid in (4624, 4634, 4647, 4800, 4801, 4802, 4803):
                user = str(e.attrs.get("target_user_name") or ed.get("TargetUserName") or user or "")
                cat = "logons"
            elif eid in (21, 22, 23, 24, 25):
                user = str(e.attrs.get("user") or ed.get("User") or user or "")
                cat = "logons"
        if not cat or not user or user.endswith("$") or user.upper() in ("SYSTEM", "ANONYMOUS LOGON", "-"):
            continue
        u = users[user]
        u["categories"][cat].append(se.id)
        if e.host:
            u["hosts"].add(e.host)
        if e.timestamp is not None:
            u["first_ns"] = e.timestamp if u["first_ns"] is None else min(u["first_ns"], e.timestamp)
            u["last_ns"] = e.timestamp if u["last_ns"] is None else max(u["last_ns"], e.timestamp)
    return {
        k: {"first_ns": v["first_ns"], "last_ns": v["last_ns"], "hosts": sorted(v["hosts"]), "categories": {c: sorted(ids) for c, ids in sorted(v["categories"].items())}}
        for k, v in sorted(users.items())
    }


class UserActivityRule:
    name = "user_activity"

    def run(self, events: Iterable[StoredEvent]) -> Iterator[Finding]:
        cached = list(events)
        by_id = {se.id: se for se in cached}
        for user, summary in reconstruct(cached).items():
            ids = [i for ids in summary["categories"].values() for i in ids]
            evs = [by_id[i] for i in ids[:500] if i in by_id]
            cats = ", ".join(f"{c}={len(ids)}" for c, ids in summary["categories"].items())
            yield mk_finding(self.name, f"User activity profile: {user}", f"Activity categories: {cats}. Hosts: {', '.join(summary['hosts']) or 'n/a'}.", "info", 0.3, "user-activity", evs, [], {"user": user, **summary})
