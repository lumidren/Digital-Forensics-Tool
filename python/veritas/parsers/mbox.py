"""RFC 4155 mbox mailboxes (``mailbox`` + ``email`` stdlib).

Messages are streamed by scanning for ``From `` separator lines ourselves (``mailbox.mbox``
builds a full table of contents first, which is fine, but message bodies are only ever read
in bounded chunks here). For each message: ``Date`` header -> ``Sent Time``; the ``From ``
separator line's asctime date -> ``Received Time`` (the delivery agent's view, UTC assumed).
Attributes: From, To, Cc, Subject, Message-ID, first 4 KiB of the first text/plain part,
attachment file names. Data type ``mbox:message``.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import re
from datetime import datetime, timezone
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.parsers.text_log import open_binary
from veritas.timeline.schema import NS, Desc, Event

SEPARATOR = re.compile(rb"^From \S*\s+(?P<date>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) .+?)\s*$")
MAX_MESSAGE = 32 * 1024 * 1024
BODY_LIMIT = 4096


def _asctime(text: str) -> int | None:
    text = " ".join(text.split())
    for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S %z %Y", "%a %b %d %H:%M %Y"):
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp()) * NS
    return None


class MboxParser(BaseParser):
    name = "mbox"
    version = "1.0"
    source_short = "EMAIL"
    source_long = "mbox mailbox"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return SEPARATOR.match(head_bytes.split(b"\n", 1)[0].rstrip(b"\r")) is not None

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_binary(path) as fh:
            first = fh.readline(4096)
            if not SEPARATOR.match(first.rstrip(b"\r\n")):
                raise ParserError("mbox: first line is not a From_ separator")
            current = first
            buf: list[bytes] = []
            size = 0
            start_offset = 0
            offset = len(first)
            index = 0
            for line in iter(lambda: fh.readline(1024 * 1024), b""):
                if line.startswith(b"From ") and SEPARATOR.match(line.rstrip(b"\r\n")):
                    yield from self._emit(current, b"".join(buf), index, start_offset)
                    index += 1
                    current, buf, size, start_offset = line, [], 0, offset
                elif size < MAX_MESSAGE:
                    buf.append(line)
                    size += len(line)
                    if size >= MAX_MESSAGE:
                        self.warn(f"message {index}: truncated at {MAX_MESSAGE} bytes")
                offset += len(line)
            yield from self._emit(current, b"".join(buf), index, start_offset)

    def _emit(self, sep: bytes, raw: bytes, index: int, offset: int) -> Iterator[Event]:
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.compat32)
            m = SEPARATOR.match(sep.rstrip(b"\r\n"))
            received = _asctime(m.group("date").decode("latin-1")) if m else None
            sent = None
            date_hdr = msg.get("Date")
            if date_hdr:
                try:
                    dt = email.utils.parsedate_to_datetime(str(date_hdr))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    sent = int(dt.timestamp()) * NS
                except (TypeError, ValueError, IndexError, OverflowError):
                    self.warn(f"message {index}: unparsable Date header")
            body = None
            attachments = []
            for part in msg.walk() if msg.is_multipart() else [msg]:
                fn = part.get_filename()
                if fn:
                    attachments.append(clip(str(fn), 1024))
                elif body is None and part.get_content_type() == "text/plain":
                    payload: bytes = part.get_payload(decode=True) or b""  # type: ignore[assignment]
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body = payload[:BODY_LIMIT * 4].decode(charset, "replace")[:BODY_LIMIT]
                    except LookupError:
                        body = payload[:BODY_LIMIT].decode("latin-1")
            hdr = (lambda k: clip(str(msg.get(k)), 4096) if msg.get(k) is not None else None)
            attrs = {"from": hdr("From"), "to": hdr("To"), "cc": hdr("Cc"), "subject": hdr("Subject"),
                     "message_id": hdr("Message-ID"), "date_header": hdr("Date"), "body": body,
                     "attachment_names": attachments, "message_index": index,
                     "envelope_sender": sep.split(b" ", 2)[1].decode("latin-1", "replace") if b" " in sep else None}
            text = f"From: {attrs['from']} To: {attrs['to']} Subject: {attrs['subject']}"
            if sent is not None:
                yield self.event("mbox:message", Desc.SENT, text, sent, offset=offset, attrs=attrs)
            if received is not None:
                yield self.event("mbox:message", Desc.RECEIVED, text, received, offset=offset, attrs=attrs)
            if sent is None and received is None:
                yield self.event("mbox:message", Desc.NOT_A_TIME, text, None, offset=offset, attrs=attrs)
        except Exception as exc:  # noqa: BLE001
            self.warn(f"message {index}: {exc}")


PARSERS = [MboxParser]
