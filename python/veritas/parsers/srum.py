"""System Resource Usage Monitor database (``SRUDB.dat``, ESE).

Tables (extension GUIDs):

* ``{DD6636C4-8929-4683-974E-22C046A43763}`` network connectivity -> ``windows:srum:network_connectivity``
* ``{973F5D5C-1D90-4944-BE8E-24B94231A174}`` network data usage   -> ``windows:srum:network_usage``
* ``{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`` application resource usage -> ``windows:srum:application_usage``
* ``{5C8CF1C7-7257-4F13-B223-970EF592EFED}`` (Win10 1607+) and ``...970EF5939312`` (older builds)
  application timeline -> ``windows:srum:app_timeline``
* ``{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}`` and its ``LT`` variant energy usage -> ``windows:srum:energy_usage``

``TimeStamp`` is an OLE Automation date (UTC) and becomes the "Sample Time" event;
``ConnectStartTime``/``EndTime``/``EventTimestamp`` are FILETIMEs. ``AppId``/``UserId`` are
resolved through ``SruDbIdMapTable`` (IdType 3 = binary SID, others UTF-16LE strings).
"""
from __future__ import annotations

import struct
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.parsers.esedb_safe import get_table, is_esedb, iter_rows, ole_date_to_ns, open_esedb, table_names
from veritas.timeline.schema import Desc, Event, filetime_to_ns

SAMPLE = "Recorded Time"  # plaso vocabulary for the TimeStamp sample
TABLES = {
    "{DD6636C4-8929-4683-974E-22C046A43763}": "windows:srum:network_connectivity",
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "windows:srum:network_usage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "windows:srum:application_usage",
    "{5C8CF1C7-7257-4F13-B223-970EF592EFED}": "windows:srum:app_timeline",
    "{5C8CF1C7-7257-4F13-B223-970EF5939312}": "windows:srum:app_timeline",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "windows:srum:energy_usage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": "windows:srum:energy_usage",
}
FILETIME_COLUMNS = {"ConnectStartTime": "Last Connection Time", "EndTime": Desc.END, "EventTimestamp": Desc.EVENT}
MAX_IDMAP = 2_000_000
SKIP_COLUMNS = {"AutoIncId", "TimeStamp", "AppId", "UserId"}


def sid_to_str(blob: bytes) -> str | None:
    if not blob or len(blob) < 8:
        return None
    rev, count = blob[0], blob[1]
    if len(blob) < 8 + 4 * count:
        return None
    auth = int.from_bytes(blob[2:8], "big")
    subs = struct.unpack_from(f"<{count}I", blob, 8)
    return "S-" + "-".join([str(rev), str(auth)] + [str(s) for s in subs])


def _ft(v: Any) -> int | None:
    if not isinstance(v, int) or v <= 0 or v >= 2_650_467_743_999_999_999:
        return None
    return filetime_to_ns(v)


class SrumParser(BaseParser):
    name = "srum"
    version = "1.0"
    source_short = "REG"
    source_long = "SRUM"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_esedb(head_bytes) and "srudb" in path.replace("\\", "/").rsplit("/", 1)[-1].lower()

    def _id_map(self, db) -> dict[int, str]:
        out: dict[int, str] = {}
        table = get_table(db, "SruDbIdMapTable")
        if table is None:
            self.warn("SruDbIdMapTable missing; AppId/UserId left numeric")
            return out
        for _, row in iter_rows(table, self.warn):
            if len(out) >= MAX_IDMAP:
                self.warn("SruDbIdMapTable truncated")
                break
            idx, blob, typ = row.get("IdIndex"), row.get("IdBlob"), row.get("IdType")
            if idx is None or not isinstance(blob, (bytes, bytearray)):
                continue
            if typ == 3:
                out[idx] = sid_to_str(bytes(blob)) or blob.hex()
            else:
                out[idx] = bytes(blob).decode("utf-16-le", "replace").rstrip("\x00")
        return out

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_esedb(path) as db:
            names = table_names(db)
            if "SruDbIdMapTable" not in names and not any(n in TABLES for n in names):
                raise ParserError("srum: no SRUM tables")
            idmap = self._id_map(db)
            for tname in sorted(n for n in names if n in TABLES):
                dtype = TABLES[tname]
                for r, row in iter_rows(get_table(db, tname), self.warn):
                    try:
                        app_id, user_id = row.get("AppId"), row.get("UserId")
                        attrs = {
                            "table": tname, "identifier": row.get("AutoIncId"),
                            "application_identifier": app_id, "application": idmap.get(app_id) if app_id is not None else None,
                            "user_identifier": idmap.get(user_id) if user_id is not None else None, "user_id": user_id,
                        }
                        for k, v in row.items():
                            if k in SKIP_COLUMNS or k in FILETIME_COLUMNS:
                                continue
                            if isinstance(v, (bytes, bytearray)):
                                v = bytes(v[:256]).hex()
                            elif isinstance(v, float):
                                v = int(v)
                            attrs[_snake(k)] = v
                        msg = f"{dtype.rsplit(':', 1)[-1]}: {attrs['application'] or app_id} user {attrs['user_identifier'] or user_id}"
                        oid = row.get("AutoIncId") or r
                        ts = ole_date_to_ns(row.get("TimeStamp"))
                        yield self.event(dtype, SAMPLE, msg, ts, offset=oid, attrs=attrs, user=attrs["user_identifier"])
                        for col_name, desc in FILETIME_COLUMNS.items():
                            t2 = _ft(row.get(col_name))
                            if t2 is not None:
                                yield self.event(dtype, desc, msg, t2, offset=oid, attrs=attrs, user=attrs["user_identifier"])
                    except Exception as exc:  # noqa: BLE001
                        self.warn(f"{tname}[{r}]: {exc}")


def _snake(name: str) -> str:
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and (not name[i - 1].isupper() or (i + 1 < len(name) and name[i + 1].islower())):
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


PARSERS = [SrumParser]
