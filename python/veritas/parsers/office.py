"""Microsoft Office document metadata.

OOXML (docx/xlsx/pptx/docm/...): ``docProps/core.xml`` (creator, lastModifiedBy, revision,
created, modified, lastPrinted, title, subject, keywords) and ``docProps/app.xml``
(Application, AppVersion, Company, Template, TotalTime, Pages, Words). Zip members are read
with a 4 MiB cap and XML containing a DOCTYPE is refused (entity-expansion defence).
-> ``office:ooxml:metadata`` (Creation / Content Modification / Last Printed Time).

Legacy OLE2 (doc/xls/ppt): ``\\x05SummaryInformation`` and ``\\x05DocumentSummaryInformation``
property-set streams (MS-OLEPS) parsed directly from the stream bytes obtained via pyolecf.
-> ``olecf:summary_info`` (Creation Time / Last Saved Time / Last Printed Time) and
``olecf:document_summary_info`` (Not a time inventory of company/manager/category...).
"""
from __future__ import annotations

import struct
import zipfile
from typing import Any, Iterator
from xml.etree import ElementTree

import defusedxml.ElementTree as SafeET

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.timeline.schema import Desc, Event, filetime_to_ns, iso_to_ns

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"
MAX_MEMBER = 4 * 1024 * 1024
LAST_PRINTED = "Document Last Printed Time"
LAST_SAVED = "Document Last Save Time"

SUMMARY_IDS = {2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments", 7: "template",
               8: "last_saved_by", 9: "revision_number", 10: "edit_time", 11: "last_printed_time",
               12: "creation_time", 13: "last_save_time", 14: "number_of_pages", 15: "number_of_words",
               16: "number_of_characters", 18: "application", 19: "security"}
DOC_SUMMARY_IDS = {2: "category", 3: "presentation_format", 4: "number_of_bytes", 5: "number_of_lines",
                   6: "number_of_paragraphs", 7: "number_of_slides", 8: "number_of_notes", 9: "number_of_hidden_slides",
                   10: "number_of_clips", 11: "scale", 14: "manager", 15: "company", 16: "links_up_to_date",
                   23: "application_version", 26: "content_type", 27: "content_status", 28: "language", 29: "document_version"}


def parse_property_set(data: bytes) -> dict[int, Any]:
    """Parse the first section of an MS-OLEPS property set stream into ``{prop_id: value}``."""
    if len(data) < 48 or data[:2] != b"\xfe\xff":
        raise ValueError("not a property set stream")
    nsec = struct.unpack_from("<I", data, 24)[0]
    if nsec < 1:
        return {}
    sec_off = struct.unpack_from("<I", data, 28 + 16)[0]
    if sec_off + 8 > len(data):
        raise ValueError("section offset out of range")
    sec_size, nprops = struct.unpack_from("<II", data, sec_off)
    sec_end = min(len(data), sec_off + sec_size)
    props: dict[int, Any] = {}
    codepage = "cp1252"
    entries = []
    for i in range(min(nprops, 4096)):
        p = sec_off + 8 + 8 * i
        if p + 8 > sec_end:
            break
        entries.append(struct.unpack_from("<II", data, p))
    for pid, poff in entries:
        if pid == 1:
            o = sec_off + poff
            if o + 6 <= sec_end:
                cp = struct.unpack_from("<H", data, o + 4)[0]
                codepage = {1200: "utf-16-le", 65001: "utf-8", 1252: "cp1252"}.get(cp, f"cp{cp}")
    for pid, poff in entries:
        o = sec_off + poff
        if o + 4 > sec_end:
            continue
        vt = struct.unpack_from("<H", data, o)[0]
        v = o + 4
        try:
            if vt == 2:
                val: Any = struct.unpack_from("<h", data, v)[0]
            elif vt in (3, 22):
                val = struct.unpack_from("<i", data, v)[0]
            elif vt in (19, 23):
                val = struct.unpack_from("<I", data, v)[0]
            elif vt == 11:
                val = struct.unpack_from("<H", data, v)[0] != 0
            elif vt == 64:
                val = ("filetime", struct.unpack_from("<Q", data, v)[0])
            elif vt == 30:
                n = struct.unpack_from("<I", data, v)[0]
                raw = data[v + 4:v + 4 + min(n, 65536)]
                try:
                    val = raw.decode(codepage, "replace")
                except LookupError:
                    val = raw.decode("cp1252", "replace")
                val = val.split("\x00", 1)[0]
            elif vt == 31:
                n = struct.unpack_from("<I", data, v)[0]
                val = data[v + 4:v + 4 + 2 * min(n, 32768)].decode("utf-16-le", "replace").split("\x00", 1)[0]
            else:
                continue
        except struct.error:
            continue
        props[pid] = val
    return props


def _xml(data: bytes) -> ElementTree.Element:
    if b"<!DOCTYPE" in data[:4096].upper() or b"<!ENTITY" in data.upper():
        raise ValueError("refusing XML with DOCTYPE/ENTITY declarations")
    return SafeET.fromstring(data)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class OoxmlParser(BaseParser):
    name = "ooxml"
    version = "1.0"
    source_short = "META"
    source_long = "OOXML document properties"
    EXTS = (".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".pptx", ".pptm", ".potx", ".ppsx", ".vsdx")

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return head_bytes.startswith(ZIP_MAGIC) and path.lower().endswith(self.EXTS)

    def _read(self, zf: zipfile.ZipFile, name: str) -> bytes | None:
        try:
            info = zf.getinfo(name)
        except KeyError:
            return None
        if info.file_size > MAX_MEMBER:
            self.warn(f"{name}: member larger than {MAX_MEMBER} bytes skipped")
            return None
        with zf.open(info) as fh:
            return fh.read(MAX_MEMBER + 1)[:MAX_MEMBER]

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        try:
            zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            raise ParserError(f"ooxml: not a zip: {exc}") from exc
        with zf:
            core = self._read(zf, "docProps/core.xml")
            app = self._read(zf, "docProps/app.xml")
            if core is None and app is None:
                raise ParserError("ooxml: no docProps/core.xml or app.xml")
            attrs: dict[str, Any] = {}
            times: dict[str, str] = {}
            for blob, label in ((core, "core"), (app, "app")):
                if blob is None:
                    continue
                try:
                    root = _xml(blob)
                except (ElementTree.ParseError, ValueError) as exc:
                    self.warn(f"{label}.xml: {exc}")
                    continue
                for el in root:
                    tag = _local(el.tag)
                    if len(el):
                        continue  # vectors (HeadingPairs/TitlesOfParts) skipped
                    text = clip((el.text or "").strip(), 4096)
                    if tag in ("created", "modified", "lastPrinted"):
                        times[tag] = text
                    else:
                        attrs[_snake(tag)] = int(text) if text.isdigit() and tag not in ("AppVersion",) else text
        msg = (f"Creator: {attrs.get('creator')} Last modified by: {attrs.get('last_modified_by')} "
               f"Application: {attrs.get('application')} Revision: {attrs.get('revision')}")
        emitted = False
        for key, desc in (("created", Desc.CREATION), ("modified", Desc.MODIFICATION), ("lastPrinted", LAST_PRINTED)):
            ts = iso_to_ns(times.get(key, ""))
            if ts is not None:
                emitted = True
                yield self.event("office:ooxml:metadata", desc, msg, ts, attrs=attrs)
        if not emitted:
            yield self.event("office:ooxml:metadata", Desc.NOT_A_TIME, msg, None, attrs=attrs)


def _snake(name: str) -> str:
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and not name[i - 1].isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


class OlecfSummaryParser(BaseParser):
    name = "olecf_summary"
    version = "1.0"
    source_short = "META"
    source_long = "OLECF Summary Info"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        # Jump lists are OLE files too but belong to the Rust jump-list parser.
        return head_bytes.startswith(OLE_MAGIC) and not path.lower().endswith("destinations-ms")

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        try:
            import pyolecf  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ParserError("olecf: pyolecf not installed") from exc
        with open(path, "rb") as fh:
            ole = pyolecf.file()
            try:
                ole.open_file_object(fh)
            except Exception as exc:  # noqa: BLE001
                raise ParserError(f"olecf: cannot open: {exc}") from exc
            try:
                root = ole.root_item
                streams = {}
                for i in range(min(root.number_of_sub_items, 4096)):
                    item = root.get_sub_item(i)
                    if item.name in ("\x05SummaryInformation", "\x05DocumentSummaryInformation"):
                        size = item.size
                        if size > MAX_MEMBER:
                            self.warn(f"{item.name!r}: stream too large")
                            continue
                        streams[item.name] = item.read(size)
                if not streams:
                    raise ParserError("olecf: no summary information streams")
            finally:
                try:
                    ole.close()
                except Exception:  # noqa: BLE001
                    pass
        if "\x05SummaryInformation" in streams:
            try:
                yield from self._summary(parse_property_set(streams["\x05SummaryInformation"]))
            except ValueError as exc:
                self.warn(f"SummaryInformation: {exc}")
        if "\x05DocumentSummaryInformation" in streams:
            try:
                props = parse_property_set(streams["\x05DocumentSummaryInformation"])
                attrs = {DOC_SUMMARY_IDS.get(k, f"property_{k}"): v for k, v in props.items()
                         if k != 1 and not isinstance(v, tuple)}
                yield self.event("olecf:document_summary_info", Desc.NOT_A_TIME,
                                 f"Company: {attrs.get('company')} Manager: {attrs.get('manager')}", None,
                                 offset=1, attrs=attrs)
            except ValueError as exc:
                self.warn(f"DocumentSummaryInformation: {exc}")

    def _summary(self, props: dict[int, Any]) -> Iterator[Event]:
        attrs: dict[str, Any] = {}
        times: dict[str, int] = {}
        for pid, val in props.items():
            if pid == 1:
                continue
            key = SUMMARY_IDS.get(pid, f"property_{pid}")
            if isinstance(val, tuple):
                if key == "edit_time":
                    attrs["total_edit_time_seconds"] = val[1] // 10_000_000
                elif val[1]:
                    times[key] = val[1]
            else:
                attrs[key] = val
        msg = f"Title: {attrs.get('title')} Author: {attrs.get('author')} Last saved by: {attrs.get('last_saved_by')}"
        emitted = False
        for key, desc in (("creation_time", "Document Creation Time"), ("last_save_time", LAST_SAVED),
                          ("last_printed_time", LAST_PRINTED)):
            if key in times:
                emitted = True
                yield self.event("olecf:summary_info", desc, msg, filetime_to_ns(times[key]), attrs=attrs)
        if not emitted:
            yield self.event("olecf:summary_info", Desc.NOT_A_TIME, msg, None, attrs=attrs)


PARSERS = [OoxmlParser, OlecfSummaryParser]
