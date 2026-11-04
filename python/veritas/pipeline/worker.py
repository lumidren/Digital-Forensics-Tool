"""Sandboxed parser worker.

Every parser run happens in a child process so that a hostile evidence file can at worst crash
or exhaust that child. Limits applied to the child:

* wall-clock timeout (parent kills the process tree);
* address-space / job-memory cap (Linux: ``RLIMIT_AS``; Windows: a Job Object with
  ``JOB_OBJECT_LIMIT_PROCESS_MEMORY`` via ``ctypes``);
* CPU-time cap (Linux ``RLIMIT_CPU``);
* no network: the child environment sets proxies to an unroutable address and, on Linux, the
  worker is launched under ``unshare --net`` when available (or gVisor ``runsc`` in the cluster
  profile; see deploy/helm). ``socket.socket`` is also replaced inside the child before any parser
  import, so a parser bug cannot open connections even where kernel isolation is unavailable;
* input is the single evidence object path handed over on argv; the working directory is a fresh
  temporary directory.

Output is JSON Lines events on stdout; diagnostics are JSON lines on stderr.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..timeline.schema import Event

DEFAULT_TIMEOUT_S = 3600
DEFAULT_MEMORY_MB = 4096


@dataclass(slots=True)
class Limits:
    timeout_s: int = DEFAULT_TIMEOUT_S
    memory_mb: int = DEFAULT_MEMORY_MB
    cpu_s: int | None = None
    allow_network: bool = False


@dataclass(slots=True)
class WorkerResult:
    ok: bool
    exit_code: int | None
    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
    killed: str | None = None  # "timeout" | "memory" | None


_CHILD_BOOTSTRAP = r"""
import json, os, socket, sys
# THREAT:T3.4 no network inside the parser child, independent of kernel isolation.
class _NoNet(socket.socket):
    def __init__(self, *a, **k):
        raise PermissionError("network access is disabled in parser workers")
socket.socket = _NoNet
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(PermissionError("network disabled"))
if sys.platform.startswith("linux"):
    import resource
    mem = int(os.environ.get("VERITAS_MEM_BYTES", "0"))
    if mem:
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    cpu = int(os.environ.get("VERITAS_CPU_S", "0"))
    if cpu:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
from veritas.pipeline.runner import main
sys.exit(main(sys.argv[1:]))
"""


def _apply_windows_job_limit(proc: subprocess.Popen, memory_mb: int) -> bool:
    """Put the child in a Job Object with a per-process memory cap and kill-on-close."""
    if platform.system() != "Windows":
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectExtendedLimitInformation = 9
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return False
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    info.ProcessMemoryLimit = memory_mb * 1024 * 1024
    if not kernel32.SetInformationJobObject(job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
        return False
    hproc = kernel32.OpenProcess(0x1F0FFF, False, proc.pid)
    ok = bool(hproc and kernel32.AssignProcessToJobObject(job, hproc))
    proc._veritas_job = job  # keep the handle alive for the lifetime of the process
    return ok


def run_parser(parser: str, evidence_path: str | Path, evidence_sha256: str, logical_path: str = "", limits: Limits | None = None, extra_args: list[str] | None = None) -> WorkerResult:
    """Run one parser over one evidence object in an isolated child. THREAT:T3.3"""
    limits = limits or Limits()
    start = time.monotonic()
    workdir = tempfile.mkdtemp(prefix="veritas-worker-")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "TZ": "UTC",
        "HTTP_PROXY": "http://0.0.0.0:9", "HTTPS_PROXY": "http://0.0.0.0:9", "NO_PROXY": "",
        "VERITAS_MEM_BYTES": str(limits.memory_mb * 1024 * 1024),
        "VERITAS_CPU_S": str(limits.cpu_s or 0),
        "VERITAS_WORKDIR": workdir,
    }
    for k in ("VERITAS_BIN_DIR", "TEMP", "TMP", "LOCALAPPDATA"):
        if k in os.environ:
            env[k] = os.environ[k]
    cmd = [sys.executable, "-I", "-X", "utf8", "-c", _CHILD_BOOTSTRAP, parser, str(evidence_path), evidence_sha256, logical_path, *(extra_args or [])]
    if platform.system() == "Linux" and not limits.allow_network and shutil.which("unshare"):
        probe = subprocess.run(["unshare", "--net", "--map-root-user", "true"], capture_output=True)
        if probe.returncode == 0:
            cmd = ["unshare", "--net", "--map-root-user", *cmd]
    # -I ignores PYTHONPATH; pass the import path explicitly instead.
    cmd[cmd.index("-c") + 1] = "import sys; sys.path[:0] = " + json.dumps([p for p in sys.path if p]) + "\n" + _CHILD_BOOTSTRAP
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=workdir, env=env)
    _apply_windows_job_limit(proc, limits.memory_mb)
    killed = None
    try:
        out, err = proc.communicate(timeout=limits.timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        killed = "timeout"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    events: list[Event] = []
    warnings: list[str] = []
    error: str | None = None
    for line in out.decode("utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                events.append(Event.from_dict(json.loads(line)))
            except (ValueError, KeyError) as exc:
                warnings.append(f"bad event line: {exc}")
    for line in err.decode("utf-8", errors="replace").splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            if line.strip():
                warnings.append(line.strip()[:500])
            continue
        if d.get("level") == "error":
            error = d.get("msg")
        elif d.get("level") == "warning":
            warnings.append(str(d.get("msg"))[:500])
    if proc.returncode not in (0, None) and killed is None:
        if error is None:
            error = f"parser exited with code {proc.returncode}"
        if proc.returncode in (-9, 137, 3221225477, -1073741571, 3221226505) or "MemoryError" in (error or ""):
            killed = "memory" if "MemoryError" in (error or "") else killed
    ok = killed is None and proc.returncode == 0
    return WorkerResult(ok=ok, exit_code=proc.returncode, events=events if ok else events, warnings=warnings, error=error or (f"killed: {killed}" if killed else None), duration_ms=int((time.monotonic() - start) * 1000), killed=killed)


def run() -> None:  # console entry point: veritas-worker
    from .queue import main as queue_main

    queue_main()


def describe_limits(limits: Limits) -> dict[str, Any]:
    return {"timeout_s": limits.timeout_s, "memory_mb": limits.memory_mb, "cpu_s": limits.cpu_s, "network": limits.allow_network, "platform": platform.system()}
