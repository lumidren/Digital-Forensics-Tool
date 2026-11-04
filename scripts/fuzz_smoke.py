#!/usr/bin/env python3
"""Run every cargo-fuzz target for a fixed time, seeded from the reference corpus.

    python scripts/fuzz_smoke.py --seconds 60 [--only prefetch,mft]

Seeds come from testdata/corpus so libFuzzer starts from valid structures and mutates inward.
Exit status is non-zero if any target finds a crash, leak, timeout or out-of-memory; the
reproducer is left in crates/<crate>/fuzz/artifacts/<target>/. On Windows the MSVC
AddressSanitizer runtime directory is added to PATH automatically when found.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
C = ROOT / "testdata" / "corpus"

TARGETS: dict[tuple[str, str], list[str]] = {
    ("veritas-artifacts", "evtx"): ["plaso/evtx/*.evtx"],
    ("veritas-artifacts", "prefetch"): ["plaso/winprefetch/*.pf"],
    ("veritas-artifacts", "lnk"): ["plaso/*.lnk"],
    ("veritas-artifacts", "shellitems"): [],
    ("veritas-artifacts", "olecf"): ["plaso/automaticDestinations-ms/*", "plaso/Document.doc"],
    ("veritas-artifacts", "journald"): ["plaso/systemd/journal/*"],
    ("veritas-artifacts", "plist"): ["plaso/plist/*.plist"],
    ("veritas-artifacts", "regf"): ["plaso/regf/*.hiv", "plaso/NTUSER-WIN7.DAT"],
    ("veritas-fs", "image"): ["dfvfs/fat12.raw", "dfvfs/ext2.raw", "dfvfs/mbr.raw", "dfvfs/gpt.raw"],
    ("veritas-fs", "mft"): [],
    ("veritas-fs", "usn"): ["plaso/UsnJrnl.raw"],
    ("veritas-fs", "logfile"): [],
    ("veritas-fs", "vss"): [],
    ("veritas-fs", "carve"): ["plaso/test_pe.exe", "plaso/Document.docx"],
}
MAX_SEED = 1 << 20  # libFuzzer handles small inputs best; larger seeds are truncated copies


def asan_dir() -> str | None:
    if platform.system() != "Windows":
        return None
    for base in (r"C:\Program Files\Microsoft Visual Studio", r"C:\Program Files (x86)\Microsoft Visual Studio"):
        hits = sorted(glob.glob(base + r"\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll"))
        if hits:
            return str(pathlib.Path(hits[-1]).parent)
    return None


def seed(crate: str, target: str, patterns: list[str]) -> pathlib.Path:
    d = ROOT / "crates" / crate / "fuzz" / "corpus" / target
    d.mkdir(parents=True, exist_ok=True)
    for pat in patterns:
        for f in sorted(C.glob(pat))[:16]:
            if f.is_file():
                (d / f.name).write_bytes(f.read_bytes()[:MAX_SEED])
    if target == "mft" and (C / "plaso" / "MFT").exists():
        (d / "mft_head").write_bytes((C / "plaso" / "MFT").read_bytes()[: 1024 * 64])
    return d


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--only", default="")
    ap.add_argument("--json", default=str(ROOT / "fuzz-results.json"))
    args = ap.parse_args()
    env = dict(os.environ)
    a = asan_dir()
    if a:
        env["PATH"] = a + os.pathsep + env.get("PATH", "")
        # The MSVC ASan runtime cannot hook a few CRT functions in binaries built by rustc nightly;
        # without this flag it aborts before the first input. Instrumentation for coverage and
        # memory-safety checks of instrumented code stay active.
        env.setdefault("ASAN_WIN_CONTINUE_ON_INTERCEPTION_FAILURE", "1")
    if not shutil.which("cargo"):
        print("cargo not found", file=sys.stderr)
        return 2
    only = {t for t in args.only.split(",") if t}
    results = []
    for (crate, target), pats in TARGETS.items():
        if only and target not in only:
            continue
        corpus = seed(crate, target, pats)
        t0 = time.time()
        proc = subprocess.run(
            ["cargo", "+nightly", "fuzz", "run", target, str(corpus), "--", f"-max_total_time={args.seconds}", "-rss_limit_mb=4096", "-timeout=25", "-print_final_stats=1"],
            cwd=ROOT / "crates" / crate, env=env, capture_output=True, text=True, errors="replace",
        )
        log = proc.stderr
        runs = next((l.split(":")[-1].strip() for l in log.splitlines() if l.startswith("stat::number_of_executed_units")), "?")
        cov = next((l.split("cov:")[-1].split()[0] for l in reversed(log.splitlines()) if "cov:" in l), "?")
        ok = proc.returncode == 0
        results.append({"crate": crate, "target": target, "ok": ok, "executions": runs, "coverage_edges": cov, "seconds": round(time.time() - t0)})
        print(f"{'OK  ' if ok else 'FAIL'} {crate}/{target}: {runs} executions, cov {cov}")
        if not ok:
            print("\n".join(log.splitlines()[-30:]))
    pathlib.Path(args.json).write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    failed = [r for r in results if not r["ok"]]
    print(f"fuzz smoke: {len(results) - len(failed)}/{len(results)} targets clean")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
