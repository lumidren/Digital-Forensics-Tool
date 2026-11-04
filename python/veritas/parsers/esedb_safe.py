"""Thin, defensive wrapper over ``pyesedb`` (libesedb) for ESE databases (SRUM, WebCache).

* Files are opened through a Python file object (``open_file_object``) so path quirks on
  Windows (libcfile rejects mixed separators behind the ``\\\\?\\`` prefix) do not matter and the
  evidence is only ever opened ``rb``.
* Values are converted by column type; long values (LV) are read through
  ``get_value_data_as_long_value`` and capped at 64 KiB.
* Any libesedb failure while reading one record is reported to the caller's ``warn`` and the
  record is skipped.
"""
from __future__ import annotations

import contextlib
import struct
from typing import Any, Callable, Iterator

from veritas.parsers.base import MAX_STRING, ParserError

ESE_MAGIC = b"\xef\xcd\xab\x89"  # at offset 4 of the file header

# libesedb column types
T_BOOL, T_I8, T_I16, T_I32, T_CURRENCY, T_FLOAT, T_DOUBLE, T_DATETIME = 1, 2, 3, 4, 5, 6, 7, 8
T_BINARY, T_TEXT, T_LBINARY, T_LTEXT, T_SLV, T_U32, T_I64, T_GUID, T_U16 = 9, 10, 11, 12, 13, 14, 15, 16, 17
INT_TYPES = {T_BOOL, T_I8, T_I16, T_I32, T_CURRENCY, T_U32, T_I64, T_U16}
TEXT_TYPES = {T_TEXT, T_LTEXT}


def is_esedb(head: bytes) -> bool:
    return len(head) >= 8 and head[4:8] == ESE_MAGIC


@contextlib.contextmanager
def open_esedb(path: str):
    try:
        import pyesedb  # type: ignore
    except ImportError as exc:  # pragma: no cover - dependency is declared in pyproject
        raise ParserError("esedb: pyesedb (libesedb-python) is not installed") from exc
    fh = open(path, "rb")
    db = pyesedb.file()
    try:
        try:
            db.open_file_object(fh)
        except Exception as exc:  # noqa: BLE001
            raise ParserError(f"esedb: cannot open {path}: {exc}") from exc
        yield db
    finally:
        with contextlib.suppress(Exception):
            db.close()
        fh.close()


def table_names(db) -> list[str]:
    out = []
    for i in range(db.number_of_tables):
        with contextlib.suppress(Exception):
            out.append(db.get_table(i).name)
    return out


def get_table(db, name: str):
    try:
        return db.get_table_by_name(name)
    except Exception:  # noqa: BLE001
        return None


def _raw(record, idx: int) -> bytes | None:
    try:
        if record.is_long_value(idx):
            lv = record.get_value_data_as_long_value(idx)
            if lv is None:
                return None
            data = lv.get_data()
            return data[:MAX_STRING] if data is not None else None
    except Exception:  # noqa: BLE001 - fall through to inline data
        pass
    data = record.get_value_data(idx)
    return data[:MAX_STRING] if data is not None else None


def value(record, idx: int, ctype: int) -> Any:
    if ctype in INT_TYPES:
        data = record.get_value_data(idx)
        if data is None:
            return None
        if ctype == T_BOOL:
            return bool(data[0]) if data else None
        return record.get_value_data_as_integer(idx)
    if ctype in (T_FLOAT, T_DOUBLE, T_DATETIME):
        data = record.get_value_data(idx)
        if data is None:
            return None
        if ctype == T_DATETIME and len(data) == 8:
            return struct.unpack("<d", data)[0]
        return record.get_value_data_as_floating_point(idx)
    if ctype in TEXT_TYPES:
        raw = _raw(record, idx)
        if raw is None:
            return None
        codec = "utf-16-le" if (len(raw) >= 2 and raw[1:2] == b"\x00") or len(raw) % 2 == 0 and b"\x00" in raw else "utf-8"
        try:
            text = record.get_value_data_as_string(idx) if not record.is_long_value(idx) else raw.decode(codec, "replace")
        except Exception:  # noqa: BLE001
            text = raw.decode(codec, "replace")
        return text.rstrip("\x00")[:MAX_STRING] if text is not None else None
    if ctype == T_GUID:
        data = record.get_value_data(idx)
        if not data or len(data) != 16:
            return None
        import uuid

        return str(uuid.UUID(bytes_le=bytes(data)))
    return _raw(record, idx)


def iter_rows(table, warn: Callable[[str], None] | None = None, columns: list[str] | None = None) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(record_index, {column: value})``; unreadable records are skipped with a warning."""
    try:
        cols = [(table.get_column(i).name, table.get_column(i).type) for i in range(table.number_of_columns)]
        n = table.number_of_records
    except Exception as exc:  # noqa: BLE001
        raise ParserError(f"esedb: table unreadable: {exc}") from exc
    wanted = set(columns) if columns else None
    for r in range(n):
        try:
            rec = table.get_record(r)
            row = {}
            for i, (name, ctype) in enumerate(cols):
                if wanted is not None and name not in wanted:
                    continue
                try:
                    row[name] = value(rec, i, ctype)
                except Exception as exc:  # noqa: BLE001
                    row[name] = None
                    if warn:
                        warn(f"{table.name}[{r}].{name}: {exc}")
            yield r, row
        except Exception as exc:  # noqa: BLE001
            if warn:
                warn(f"{getattr(table, 'name', '?')}[{r}]: {exc}")


OLE_EPOCH_DAYS = 25569  # 1899-12-30 -> 1970-01-01


def ole_date_to_ns(days: float | None) -> int | None:
    """OLE Automation date (days since 1899-12-30, fractional) -> ns, rounded to the microsecond."""
    if days is None or days != days or days == 0:
        return None
    us = round((days - OLE_EPOCH_DAYS) * 86_400_000_000)
    return int(us) * 1000
