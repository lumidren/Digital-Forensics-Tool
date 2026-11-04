"""Reference-tool driver used only by the parity tests (``python/tests/parity/test_py_*.py``).

Runs a plaso parser (optionally restricted to one plugin) in-process on a single file and
returns the produced event data as plain dicts. Modern plaso parsers emit *event data*
containers whose date-time attributes are ``dfdatetime`` objects; events are derived from them
later by the timeliner. Parity therefore compares, per plaso ``data_type``, the multiset of
date-time values (as microseconds since the epoch) and selected attributes.

Nothing in the production parsers imports this module; plaso is an optional dependency.
"""
from __future__ import annotations

import os
from typing import Any


def plaso_available() -> bool:
    try:
        import plaso  # noqa: F401
        from plaso.parsers import manager  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def plaso_version() -> str:
    import plaso

    return f"plaso {plaso.__version__}"


def _get_parser(parser_name: str, plugin: str | None):
    import plaso.parsers  # noqa: F401  (registers every parser and plugin)
    from plaso.parsers import manager

    expression = parser_name if plugin is None else f"{parser_name}/{plugin}"
    objects = manager.ParsersManager.GetParserObjects(parser_filter_expression=expression)
    if parser_name not in objects:
        raise KeyError(expression)
    return objects[parser_name]


def run_plaso(path: str, parser_name: str, plugin: str | None = None, gzip: bool = False) -> list[dict[str, Any]]:
    """Return ``[{data_type, times: {attr: us}, time_strings: {attr: str}, attrs: {...}}]`` for one file.

    ``gzip=True`` wraps the OS path spec in a dfVFS GZIP path spec (plaso reads FSEvents pages that way).
    ``time_strings`` keeps ``CopyToDateTimeString()`` so year-less (relative-year) values can be compared
    on their month..microsecond part.
    """
    from dfvfs.lib import definitions as dfvfs_definitions
    from dfvfs.path import factory as path_spec_factory
    from dfvfs.resolver import resolver as path_spec_resolver
    from plaso.parsers import mediator as parsers_mediator
    from plaso.storage.fake import writer as fake_writer

    parser = _get_parser(parser_name, plugin)
    storage_writer = fake_writer.FakeStorageWriter()
    storage_writer.Open()
    med = parsers_mediator.ParserMediator()
    med.SetStorageWriter(storage_writer)
    path_spec = path_spec_factory.Factory.NewPathSpec(dfvfs_definitions.TYPE_INDICATOR_OS, location=os.path.abspath(path))
    if gzip:
        path_spec = path_spec_factory.Factory.NewPathSpec(dfvfs_definitions.TYPE_INDICATOR_GZIP, parent=path_spec)
    file_entry = path_spec_resolver.Resolver.OpenFileEntry(path_spec)
    med.SetFileEntry(file_entry)
    from plaso.parsers import interface as parsers_interface

    if isinstance(parser, parsers_interface.FileEntryParser):
        parser.Parse(med)
    else:
        file_object = file_entry.GetFileObject()
        parser.Parse(med, file_object)
    out = []
    for ed in storage_writer.GetAttributeContainers("event_data"):
        times: dict[str, int] = {}
        time_strings: dict[str, str] = {}
        attrs: dict[str, Any] = {}
        for name, val in ed.GetAttributes():
            if name.startswith("_"):
                continue
            if hasattr(val, "GetPlasoTimestamp"):
                try:
                    time_strings[name] = val.CopyToDateTimeString()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    ts = val.GetPlasoTimestamp()
                except Exception:  # noqa: BLE001
                    ts = None
                if ts is not None:
                    times[name] = int(ts)
            elif isinstance(val, (str, int, bool)) or val is None:
                attrs[name] = val
            elif isinstance(val, (list, tuple)):
                attrs[name] = [v for v in val if isinstance(v, (str, int))]
        attrs.pop("query", None)
        out.append({"data_type": getattr(ed, "data_type", ""), "times": times, "time_strings": time_strings, "attrs": attrs})
    storage_writer.Close()
    return out


def times_multiset(records: list[dict[str, Any]], data_types: set[str] | None = None) -> list[int]:
    vals: list[Any] = []
    for r in records:
        if data_types and r["data_type"] not in data_types:
            continue
        vals.extend(v for v in r["times"].values() if v)
    return sorted(vals)


def multiset_agreement(ours: list[int], ref: list[int]) -> tuple[int, int]:
    """Return ``(agree, total)`` where ``agree`` counts matched values in the two multisets."""
    from collections import Counter

    a, b = Counter(ours), Counter(ref)
    agree = sum(min(a[k], b[k]) for k in a)
    return agree, max(sum(a.values()), sum(b.values()))
