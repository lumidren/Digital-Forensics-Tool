"""macOS / iOS Messages (``chat.db`` / ``sms.db``).

``message`` LEFT JOIN ``handle`` (handle_id -> phone/e-mail). ``date``/``date_read``/
``date_delivered`` are seconds since 2001 on older releases and nanoseconds since 2001 from
High Sierra / iOS 11 (values > 1e11 are treated as ns). Text comes from ``text`` (falls back to
the plain string inside ``attributedBody`` when ``text`` is NULL, as on Ventura+).
-> ``imessage:event:chat`` (Creation Time = sent/received ``date``; Read Time; Delivered Time).
"""
from __future__ import annotations

import pathlib
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip, cocoa_ns_or_s_to_ns
from veritas.parsers.sqlite_safe import col, columns, has_table, is_sqlite, open_sqlite, rows, to_int
from veritas.timeline.schema import Desc, Event



def _attributed_text(blob: Any) -> str | None:
    """Best-effort extraction of the message string from a typedstream ``attributedBody``."""
    if not isinstance(blob, (bytes, bytearray)):
        return None
    blob = bytes(blob[:65536])
    i = blob.find(b"NSString")
    if i < 0:
        return None
    j = blob.find(b"+", i)
    if j < 0 or j + 2 > len(blob):
        return None
    n = blob[j + 1]
    start = j + 2
    if n == 0x81:
        n = int.from_bytes(blob[j + 2:j + 4], "little")
        start = j + 4
    elif n == 0x82:
        n = int.from_bytes(blob[j + 2:j + 6], "little")
        start = j + 6
    return blob[start:start + n].decode("utf-8", "replace")


class IMessageParser(BaseParser):
    name = "imessage"
    version = "1.0"
    source_short = "SMS"
    source_long = "iMessage"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        n = pathlib.Path(path).name.lower()
        return is_sqlite(head_bytes) and (n.endswith("chat.db") or n == "sms.db")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_sqlite(path) as conn:
            if not has_table(conn, "message"):
                raise ParserError("imessage: no message table")
            mcols = set(columns(conn, "message"))
            join = "LEFT JOIN handle ON message.handle_id = handle.ROWID" if has_table(conn, "handle") else ""
            hsel = "handle.id AS handle_value, handle.service AS handle_service" if join else "NULL AS handle_value, NULL AS handle_service"
            sql = f"SELECT message.*, {hsel} FROM message {join} ORDER BY message.ROWID"  # nosec B608 - fragments are code constants chosen by schema checks
            for idx, row in enumerate(rows(conn, sql), 1):
                try:
                    text = col(row, "text")
                    if text is None and "attributedBody" in mcols:
                        text = _attributed_text(row["attributedBody"])
                    from_me = bool(to_int(col(row, "is_from_me"), 0))
                    attrs = {
                        "text": clip(text), "imessage_id": col(row, "handle_value"), "service": col(row, "service"),
                        "is_from_me": from_me, "message_type": to_int(col(row, "type")), "read_receipt": bool(to_int(col(row, "is_read"), 0)),
                        "is_delivered": bool(to_int(col(row, "is_delivered"), 0)), "guid": col(row, "guid"),
                        "account": col(row, "account"), "attachment": bool(to_int(col(row, "cache_has_attachments"), 0)),
                        "message_identifier": to_int(col(row, "ROWID")),
                    }
                    direction = "Sent to" if from_me else "Received from"
                    msg = f"{direction} {attrs['imessage_id']} [{attrs['service']}]: {text or ''}"
                    rid = attrs["message_identifier"] or idx
                    emitted = False
                    for column, desc in (("date", Desc.CREATION), ("date_read", "Read Time"), ("date_delivered", "Delivered Time")):
                        v = col(row, column)
                        ts = cocoa_ns_or_s_to_ns(v) if v else None
                        if ts is not None:
                            emitted = True
                            yield self.event("imessage:event:chat", desc, msg, ts, offset=rid, attrs=attrs)
                    if not emitted:
                        yield self.event("imessage:event:chat", Desc.NOT_A_TIME, msg, None, offset=rid, attrs=attrs)
                except Exception as exc:  # noqa: BLE001
                    self.warn(f"message {idx}: {exc}")


PARSERS = [IMessageParser]
