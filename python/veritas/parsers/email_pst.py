"""Outlook PST/OST via ``pypff`` (libpff).

Walks the folder tree depth-first in on-disk order and emits, per message, one
``pst:message`` event per available time: delivery (Received Time), client submit (Sent
Time), creation (Creation Time) and modification (Content Modification Time).

Attributes: folder path, subject, sender name, From/To/Cc/Message-ID/Date taken from the
transport headers (header block capped at 16 KiB), body text (plain text, else HTML/RTF stripped
of nothing, first 4 KiB), attachment count and names (``PR_ATTACH_LONG_FILENAME`` 0x3707,
falling back to ``PR_ATTACH_FILENAME`` 0x3704). Folder/message recursion is bounded.
"""
from __future__ import annotations

import email.parser
import email.policy
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.timeline.schema import Desc, Event, filetime_to_ns

PST_MAGIC = b"!BDN"
BODY_LIMIT = 4096
HEADER_LIMIT = 16 * 1024
MAX_DEPTH = 64
MAX_MESSAGES = 2_000_000
ATTACH_NAME_TYPES = (0x3707, 0x3704)
TIMES = (("get_delivery_time_as_integer", Desc.RECEIVED), ("get_client_submit_time_as_integer", Desc.SENT),
         ("get_creation_time_as_integer", Desc.CREATION), ("get_modification_time_as_integer", Desc.MODIFICATION))


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return default


def _text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value[:limit * 4]
        for codec in ("utf-8", "cp1252"):
            try:
                value = value.decode(codec)
                break
            except UnicodeDecodeError:
                continue
        else:
            value = value.decode("latin-1")
    return clip(str(value), limit)


def _attachment_name(att) -> str | None:
    for rs_i in range(_safe(lambda: att.number_of_record_sets, 0) or 0):
        rs = _safe(lambda: att.get_record_set(rs_i))
        if rs is None:
            continue
        for want in ATTACH_NAME_TYPES:
            for e_i in range(_safe(lambda: rs.number_of_entries, 0) or 0):
                entry = _safe(lambda: rs.get_entry(e_i))
                if entry is not None and _safe(lambda: entry.entry_type) == want:
                    s = _safe(entry.get_data_as_string)
                    if s:
                        return clip(s, 1024)
    return None


class PstParser(BaseParser):
    name = "pst"
    version = "1.0"
    source_short = "EMAIL"
    source_long = "Outlook PST/OST"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return head_bytes[:4] == PST_MAGIC

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        try:
            import pypff  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ParserError("pst: pypff (libpff-python) not installed") from exc
        with open(path, "rb") as fh:
            if fh.read(4) != PST_MAGIC:
                raise ParserError("pst: bad signature")
            fh.seek(0)
            pff = pypff.file()
            try:
                pff.open_file_object(fh)
            except Exception as exc:  # noqa: BLE001
                raise ParserError(f"pst: cannot open: {exc}") from exc
            try:
                root = pff.get_root_folder()
                if root is None:
                    raise ParserError("pst: no root folder")
                self._count = 0
                yield from self._folder(root, "", 0)
            finally:
                _safe(pff.close)

    def _folder(self, folder, parent: str, depth: int) -> Iterator[Event]:
        if depth > MAX_DEPTH:
            self.warn(f"folder depth limit at {parent}")
            return
        name = _safe(lambda: folder.name) or ""
        path = f"{parent}/{name}" if depth else (name or "")
        n_msgs = _safe(lambda: folder.number_of_sub_messages, 0) or 0
        for i in range(n_msgs):
            if self._count >= MAX_MESSAGES:
                self.warn("message cap reached")
                return
            msg = _safe(lambda: folder.get_sub_message(i))
            if msg is None:
                self.warn(f"{path}: message {i} unreadable")
                continue
            self._count += 1
            try:
                yield from self._message(msg, path, i)
            except Exception as exc:  # noqa: BLE001
                self.warn(f"{path}: message {i}: {exc}")
        for j in range(_safe(lambda: folder.number_of_sub_folders, 0) or 0):
            sub = _safe(lambda: folder.get_sub_folder(j))
            if sub is None:
                self.warn(f"{path}: sub folder {j} unreadable")
                continue
            yield from self._folder(sub, path, depth + 1)

    def _message(self, msg, folder_path: str, index: int) -> Iterator[Event]:
        headers_text = _text(_safe(lambda: msg.transport_headers), HEADER_LIMIT) or ""
        hdr: Any = email.parser.HeaderParser(policy=email.policy.compat32).parsestr(headers_text) if headers_text else {}
        body = _text(_safe(lambda: msg.plain_text_body), BODY_LIMIT)
        if not body:
            body = _text(_safe(lambda: msg.html_body), BODY_LIMIT)
        attachments = []
        for a in range(min(_safe(lambda: msg.number_of_attachments, 0) or 0, 1000)):
            att = _safe(lambda: msg.get_attachment(a))
            attachments.append((_attachment_name(att) if att is not None else None) or f"attachment_{a}")
        get = (lambda k: clip(str(hdr.get(k)), 4096) if hdr and hdr.get(k) is not None else None)
        subject = _text(_safe(lambda: msg.subject), 4096) or ""
        sender = _text(_safe(lambda: msg.sender_name), 1024)
        ident = _safe(lambda: msg.identifier)
        attrs = {
            "folder": folder_path, "subject": subject, "sender_name": sender, "from": get("From"), "to": get("To"),
            "cc": get("Cc"), "bcc": get("Bcc"), "message_id": get("Message-ID"), "date_header": get("Date"),
            "body": body, "attachment_count": len(attachments), "attachment_names": attachments,
            "conversation_topic": _text(_safe(lambda: msg.conversation_topic), 1024), "identifier": ident,
            "headers": headers_text or None,
        }
        text = f"[{folder_path}] From: {sender or attrs['from'] or ''} Subject: {subject}"
        emitted = False
        for getter, desc in TIMES:
            fn = getattr(msg, getter, None)  # generic pypff.item (e.g. Freebusy) lacks message getters
            ft = _safe(fn) if fn is not None else None
            if ft:
                emitted = True
                yield self.event("pst:message", desc, text, filetime_to_ns(ft), offset=ident or index, attrs=attrs)
        if not emitted:
            yield self.event("pst:message", Desc.NOT_A_TIME, text, None, offset=ident or index, attrs=attrs)


PARSERS = [PstParser]
