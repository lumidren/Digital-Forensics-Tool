"""Child-side entry point for sandboxed parser runs.

``python -m veritas.pipeline.runner <parser> <evidence_path> <evidence_sha256> <logical_path> [args...]``

Parsers are resolved from :data:`PARSERS`: names starting with ``rust:`` run the matching
``veritas-artifacts-dump`` / ``fs-tool`` subcommand (Rust binaries found in ``VERITAS_BIN_DIR`` or
``target/release``); other names map to Python parser callables. Events go to stdout as JSON Lines,
sorted for determinism; diagnostics go to stderr as JSON lines.
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable

from ..timeline.schema import Event, sorted_events

# name -> (module, attribute) for Python parsers; the callable takes (path, provenance) and yields Events.
PY_PARSERS: dict[str, tuple[str, str]] = {
    "chromium": ("veritas.parsers.browsers.chromium", "parse"),
    "firefox": ("veritas.parsers.browsers.firefox", "parse"),
    "auto": ("veritas.parsers.registry", "parse_auto"),
    "cloud": ("veritas.cloud.registry", "parse_auto"),
    "ios_backup": ("veritas.mobile.ios_backup", "parse"),
    "android_backup": ("veritas.mobile.android_backup", "parse"),
    "pcap": ("veritas.network.pcap", "parse"),
    "pe": ("veritas.malware.static", "parse"),
    "yara": ("veritas.malware.yara_scan", "parse"),
    "memory": ("veritas.memory.volatility", "parse"),
}

RUST_KINDS = {"evtx", "evt", "prefetch", "lnk", "jumplist", "journald", "plist", "taskjob", "taskxml", "regf-events"}
FS_KINDS = {"fs-events", "mft", "usn", "logfile"}


def _log(level: str, msg: str) -> None:
    # Bytes, not text: the child runs with ``python -I`` (which ignores PYTHONIOENCODING) and may
    # inherit a legacy console code page; diagnostics must never fail to encode.
    sys.stderr.buffer.write((json.dumps({"level": level, "msg": msg}) + "\n").encode("utf-8"))
    sys.stderr.buffer.flush()


def find_binary(name: str) -> str | None:
    exe = name + (".exe" if os.name == "nt" else "")
    for d in filter(None, [os.environ.get("VERITAS_BIN_DIR"), str(Path(__file__).resolve().parents[3] / "target" / "release"), str(Path(__file__).resolve().parents[3] / "target" / "debug")]):
        p = Path(d) / exe
        if p.exists():
            return str(p)
    return shutil.which(name)


def _rust(binary: str, args: list[str]) -> Iterable[Event]:
    exe = find_binary(binary)
    if exe is None:
        raise FileNotFoundError(f"{binary} not found; build with cargo build --release or set VERITAS_BIN_DIR")
    proc = subprocess.run([exe, *args], capture_output=True, timeout=None)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace")[-2000:])
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if line.strip():
            yield Event.from_dict(json.loads(line))


def resolve(parser: str) -> Callable[[str, str, str, list[str]], Iterable[Event]]:
    if parser in RUST_KINDS:
        kind = "registry" if parser == "regf-events" else parser
        return lambda path, sha, logical, extra: _rust("veritas-artifacts-dump", [kind, path, "--events", "--evidence-sha256", sha, *extra])
    if parser in FS_KINDS:
        sub = {"fs-events": "events"}.get(parser, parser)
        flags = [] if sub == "events" else ["--events"]
        return lambda path, sha, logical, extra: _rust("fs-tool", [sub, path, *flags, *extra])
    if parser in PY_PARSERS:
        mod, attr = PY_PARSERS[parser]

        def run(path: str, sha: str, logical: str, extra: list[str]) -> Iterable[Event]:
            fn = getattr(importlib.import_module(mod), attr)
            from ..parsers.base import Provenance  # local import keeps the child lean

            return fn(path, Provenance(evidence_sha256=sha, evidence_path=logical or path))

        return run
    raise KeyError(f"unknown parser {parser}")


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        _log("error", "usage: runner <parser> <path> <sha256> <logical_path> [args]")
        return 2
    parser, path, sha, logical, extra = argv[0], argv[1], argv[2], argv[3], argv[4:]
    try:
        fn = resolve(parser)
        events = list(fn(path, sha, logical, extra))
    except MemoryError:
        _log("error", "MemoryError: parser exceeded its memory limit")
        return 3
    except Exception as exc:  # parser failure is reported, never propagated to the platform
        _log("error", f"{type(exc).__name__}: {exc}"[:2000])
        return 1
    # Single-artifact parsers record the path they were handed (a temporary plaintext copy);
    # replace it with the artifact's logical path. Image parsers keep their in-image paths.
    relabel = parser not in FS_KINDS
    try:
        out = sys.stdout.buffer
        for e in sorted_events(events):
            if not e.evidence_sha256:
                e.evidence_sha256 = sha
            if relabel and logical and (not e.evidence_path or e.evidence_path == path or Path(e.evidence_path) == Path(path)):
                e.evidence_path = logical
            out.write(e.to_json().encode("utf-8"))
            out.write(b"\n")
        out.flush()
    except Exception as exc:
        _log("error", f"writing events failed: {type(exc).__name__}: {exc}"[:2000])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
