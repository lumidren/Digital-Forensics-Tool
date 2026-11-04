"""Internet Explorer / legacy Edge caches.

``index.dat`` (MSIE Cache File, "Client UrlCache MMF Ver 4.7/5.2")
    Parsed directly. Records live in 128-byte blocks starting at 0x4000. Records referenced
    from the HASH table chain are "allocated"; every other ``URL ``/``LEAK``/``REDR`` record
    found by a block-aligned scan is emitted with ``attrs.recovered = true`` (same idea as
    libmsiecf's recovered items). Each record's block count bounds the read so a record never
    reads past its own allocation or the file.

``WebCacheV01.dat`` (ESE, IE10+/legacy Edge)
    ``Containers`` table -> ``msie:webcache:containers``; ``Partitions`` -> ``msie:webcache:partitions``; every
    ``Container_<id>`` table -> ``msie:webcache:container`` events (Url, Filename, access count,
    response headers, six FILETIMEs). ``LeakFiles`` -> ``msie:webcache:leak_file``.
"""
from __future__ import annotations

import pathlib
import struct
from typing import Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.parsers.esedb_safe import get_table, is_esedb, iter_rows, open_esedb, table_names
from veritas.timeline.schema import Desc, Event, filetime_to_ns

MSIECF_MAGIC = b"Client UrlCache MMF Ver "
BLOCK = 0x80
FIRST_BLOCK = 0x4000
MAX_FILETIME = 2_650_467_743_999_999_999  # 9999-12-31


def ft(value) -> int | None:
    """FILETIME -> ns; 0, pre-1970 (not a wall-clock value in these caches) and > 9999 are ignored."""
    if not value or not isinstance(value, int) or value < 116_444_736_000_000_000 or value >= MAX_FILETIME:
        return None
    return filetime_to_ns(value)


def fat_datetime_to_ns(value: int) -> int | None:
    """FAT date (low 16 bits) + time (high 16 bits) -> ns (no timezone; as recorded)."""
    if not value:
        return None
    date, time = value & 0xFFFF, value >> 16
    day, month, year = date & 0x1F, (date >> 5) & 0x0F, ((date >> 9) & 0x7F) + 1980
    sec, minute, hour = (time & 0x1F) * 2, (time >> 5) & 0x3F, (time >> 11) & 0x1F
    if not (1 <= day <= 31 and 1 <= month <= 12 and hour < 24 and minute < 60 and sec < 60):
        return None
    import datetime as _dt

    try:
        dt = _dt.datetime(year, month, day, hour, minute, sec, tzinfo=_dt.timezone.utc)
    except ValueError:
        return None
    return int(dt.timestamp()) * 1_000_000_000


def _cstr(buf: bytes, off: int, end: int) -> str:
    if off <= 0 or off >= end:
        return ""
    stop = buf.find(b"\x00", off, end)
    if stop < 0:
        stop = end
    return buf[off:stop].decode("latin-1")


class MsiecfParser(BaseParser):
    name = "msiecf"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "MSIE Cache File"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return head_bytes.startswith(MSIECF_MAGIC)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        data = pathlib.Path(path).read_bytes() if pathlib.Path(path).stat().st_size <= 512 * 1024 * 1024 else None
        if data is None:
            raise ParserError("msiecf: file larger than 512 MiB")
        if not data.startswith(MSIECF_MAGIC) or len(data) < 0x50:
            raise ParserError("msiecf: bad signature")
        fmt_version = data[24:27].decode("ascii", "replace")
        file_size, hash_off = struct.unpack_from("<II", data, 0x1C)
        end = min(len(data), file_size or len(data))
        ndirs = struct.unpack_from("<I", data, 0x48)[0]
        dirs = []
        for i in range(min(ndirs, 64)):
            o = 0x4C + 12 * i
            if o + 12 > len(data):
                break
            dirs.append(data[o + 4:o + 12].decode("latin-1", "replace"))
        cache_type = "history" if b"Visited:" in data[FIRST_BLOCK:FIRST_BLOCK + 0x20000] or "MSHist" in path else "cache"

        allocated = set()
        seen_tables = set()
        off = hash_off
        while 0 < off < end - 16 and off not in seen_tables and len(seen_tables) < 4096:
            seen_tables.add(off)
            if data[off:off + 4] != b"HASH":
                self.warn(f"hash table at {off:#x} has no HASH signature")
                break
            nblocks, nxt = struct.unpack_from("<II", data, off + 4)
            tend = min(end, off + max(nblocks, 1) * BLOCK)
            for e in range(off + 16, tend - 7, 8):
                h, roff = struct.unpack_from("<II", data, e)
                if roff in (0, 3) or h in (0x3, 0x1) or roff >= end:
                    continue
                if data[roff:roff + 4] in (b"URL ", b"LEAK", b"REDR"):
                    allocated.add(roff)
            off = nxt

        pos = FIRST_BLOCK
        while pos + 8 <= end:
            sig = data[pos:pos + 4]
            if sig in (b"URL ", b"LEAK", b"REDR", b"HASH"):
                nblocks = struct.unpack_from("<I", data, pos + 4)[0]
                rec_end = min(end, pos + max(nblocks, 1) * BLOCK)
                if sig != b"HASH":
                    try:
                        yield from self._record(data, pos, rec_end, sig, pos not in allocated, fmt_version, dirs, cache_type)
                    except Exception as exc:  # noqa: BLE001
                        self.warn(f"record at {pos:#x}: {exc}")
                pos += max(nblocks, 1) * BLOCK if 0 < nblocks < 0x10000 else BLOCK
            else:
                pos += BLOCK

    def _record(self, data: bytes, pos: int, end: int, sig: bytes, recovered: bool, fmt_version: str,
                dirs: list[str], cache_type: str) -> Iterator[Event]:
        rec = data[pos:end]
        if sig == b"REDR":
            url = _cstr(rec, 0x10, len(rec))
            yield self.event("msiecf:redirected", Desc.NOT_A_TIME, f"Location: {url}", None, offset=pos,
                             attrs={"url": url, "recovered": recovered})
            return
        if len(rec) < 0x60:
            raise ValueError("truncated URL record")
        secondary, primary = struct.unpack_from("<QQ", rec, 8)
        if fmt_version.startswith("4.7"):
            expiration = ft(struct.unpack_from("<Q", rec, 0x18)[0])
        else:
            expiration = fat_datetime_to_ns(struct.unpack_from("<I", rec, 0x18)[0])
        cached_size = struct.unpack_from("<I", rec, 0x20)[0]
        loc_off, dir_idx = struct.unpack_from("<IB", rec, 0x34)
        fname_off, flags, data_off, data_size = struct.unpack_from("<IIII", rec, 0x3C)
        last_checked = fat_datetime_to_ns(struct.unpack_from("<I", rec, 0x50)[0])
        hits = struct.unpack_from("<I", rec, 0x54)[0]
        url = _cstr(rec, loc_off, len(rec))
        filename = _cstr(rec, fname_off, len(rec))
        headers = ""
        if 0 < data_off < len(rec) and data_size:
            headers = rec[data_off:min(len(rec), data_off + data_size)].split(b"\x00", 1)[0].decode("latin-1")
        dtype = "msiecf:url" if sig == b"URL " else "msiecf:leak"
        attrs = {
            "url": url, "cached_filename": filename, "cache_directory_index": dir_idx if dir_idx < 0xFE else None,
            "cache_directory_name": dirs[dir_idx] if dir_idx < len(dirs) else None, "number_of_hits": hits,
            "cached_file_size": cached_size, "cache_entry_flags": flags, "http_headers": clip(headers, 4096),
            "recovered": recovered, "cache_type": cache_type, "format_version": fmt_version,
        }
        msg = f"Location: {url}" + (f" Cached file: {filename}" if filename else "") + f" Number of hits: {hits}"
        if recovered:
            msg += " (recovered)"
        primary_desc = Desc.LAST_VISITED if cache_type == "history" else Desc.ACCESS
        emitted = False
        for ts, desc in ((ft(primary), primary_desc), (ft(secondary), Desc.MODIFICATION),
                         (expiration, Desc.EXPIRATION), (last_checked, "Last Checked Time")):
            if ts is not None:
                emitted = True
                yield self.event(dtype, desc, msg, ts, offset=pos, attrs=attrs)
        if not emitted:
            yield self.event(dtype, Desc.NOT_A_TIME, msg, None, offset=pos, attrs=attrs)


WEBCACHE_TIMES = (
    ("AccessedTime", Desc.ACCESS), ("CreationTime", Desc.CREATION), ("ExpiryTime", Desc.EXPIRATION),
    ("ModifiedTime", Desc.MODIFICATION), ("PostCheckTime", "Post Check Time"), ("SyncTime", "Synchronization Time"),
)


class WebCacheParser(BaseParser):
    name = "msie_webcache"
    version = "1.0"
    source_short = "WEBHIST"
    source_long = "MSIE WebCache"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return is_esedb(head_bytes) and "webcache" in pathlib.Path(path).name.lower()

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        with open_esedb(path) as db:
            names = set(table_names(db))
            if "Containers" not in names:
                raise ParserError("msie_webcache: no Containers table")
            containers = []
            for r, row in iter_rows(get_table(db, "Containers"), self.warn):
                cid = row.get("ContainerId")
                name = (row.get("Name") or "").strip()
                directory = row.get("Directory") or ""
                containers.append((cid, name, directory))
                attrs = {"container_identifier": cid, "name": name, "directory": directory,
                         "set_identifier": row.get("SetId")}
                msg = f"Container identifier: {cid} Name: {name} Directory: {directory}"
                for col_name, desc in (("LastAccessTime", Desc.ACCESS), ("LastScavengeTime", "Last Scavenge Time")):
                    ts = ft(row.get(col_name))
                    if ts is not None:
                        yield self.event("msie:webcache:containers", desc, msg, ts, offset=r, attrs=attrs)
            for cid, cname, directory in sorted(containers, key=lambda c: (c[0] or 0)):
                tname = f"Container_{cid}"
                if tname not in names:
                    continue
                for r, row in iter_rows(get_table(db, tname), self.warn):
                    try:
                        url = row.get("Url") or ""
                        headers = row.get("ResponseHeaders")
                        if isinstance(headers, bytes):
                            headers = headers[:4096].decode("latin-1", "replace")
                        attrs = {
                            "container_identifier": cid, "container_name": cname, "directory": directory,
                            "entry_identifier": row.get("EntryId"), "url": url, "cached_filename": row.get("Filename"),
                            "file_extension": row.get("FileExtension"), "access_count": row.get("AccessCount"),
                            "cached_file_size": row.get("FileSize"), "response_headers": headers,
                            "redirect_url": row.get("RedirectUrl"), "cache_identifier": row.get("CacheId"),
                        }
                        msg = f"URL: {url} Access count: {row.get('AccessCount')} Container: {cname} ({cid})"
                        for col_name, desc in WEBCACHE_TIMES:
                            ts = ft(row.get(col_name))
                            if ts is not None:
                                # offset: container id in the high bits keeps (data_type, offset) unique per row.
                                yield self.event("msie:webcache:container", desc, msg, ts, offset=(cid or 0) * 1_000_000 + r,
                                                 attrs=attrs)
                    except Exception as exc:  # noqa: BLE001
                        self.warn(f"{tname}[{r}]: {exc}")
            if "Partitions" in names:
                for r, row in iter_rows(get_table(db, "Partitions"), self.warn):
                    attrs = {"partition_identifier": row.get("PartitionId"), "partition_type": row.get("PartitionType"),
                             "directory": row.get("Directory"), "table_identifier": row.get("TableId")}
                    ts = ft(row.get("LastScavengeTime"))
                    yield self.event("msie:webcache:partitions", "Last Scavenge Time" if ts else Desc.NOT_A_TIME,
                                     f"Partition: {attrs['partition_identifier']} Directory: {attrs['directory']}", ts,
                                     offset=r, attrs=attrs)
            if "LeakFiles" in names:
                for r, row in iter_rows(get_table(db, "LeakFiles"), self.warn):
                    attrs = {"leak_identifier": row.get("LeakId"), "cached_filename": row.get("Filename")}
                    ts = ft(row.get("CreationTime"))
                    yield self.event("msie:webcache:leak_file", Desc.CREATION, f"Leak file: {attrs['cached_filename']}",
                                     ts, offset=r, attrs=attrs)


PARSERS = [MsiecfParser, WebCacheParser]
