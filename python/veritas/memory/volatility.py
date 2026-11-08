"""Volatility 3 driver.

Runs a configurable set of Volatility 3 plugins against a memory image and normalises every
output row into :class:`veritas.timeline.schema.Event`.

Two backends produce the *same* intermediate row shape (the shape of Volatility's own ``-r json``
renderer, flattened):

``inprocess``  Uses ``volatility3.framework`` directly (contexts, automagic, ``construct_plugin``).
               Values are converted with Volatility's own JSON type renderers so the rows are
               byte-for-byte what the CLI would print.
``subprocess`` Runs ``vol -q -r json -f IMAGE PLUGIN`` (or a configured command) per plugin, with a
               timeout. Used when the in-process framework is unavailable, or on request, so a
               crashing plugin cannot take the worker down with it.

Symbols: Volatility resolves Windows kernel symbols from its ISF cache and, unless ``offline`` is
set, downloads PDB-derived ISF files from the symbol server. ``symbol_dirs`` adds local ISF
directories (an air-gapped worker sets ``offline=True`` and ships a pre-populated symbol dir;
see docs/THREAT_MODEL.md T3.4, workers have no network egress).

Determinism: plugin order is fixed by the configuration, rows keep Volatility's order, events are
sorted with :func:`veritas.timeline.schema.sorted_events`. Timestamps come only from the image.
A plugin that fails is a counted warning, never an exception.
"""
from __future__ import annotations

import datetime as _dt
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.timeline.schema import Desc, Event, iso_to_ns, sorted_events

log = logging.getLogger(__name__)

VERSION = "1.0"
MAX_ROWS_DEFAULT = 2_000_000


# --------------------------------------------------------------------------- plugin sets
@dataclass(frozen=True, slots=True)
class PluginSpec:
    """One logical plugin step.

    ``candidates`` are tried in order: the first one that exists *and* succeeds wins. This covers
    renamed plugins (``windows.malware.malfind`` vs ``windows.malfind``) and functional fallbacks
    (``windows.netscan`` then ``windows.netstat``). ``optional`` steps that are not present in the
    installed Volatility are skipped without a warning.
    """

    candidates: tuple[str, ...]
    optional: bool = False
    args: tuple[tuple[str, Any], ...] = ()

    @classmethod
    def of(cls, *names: str, optional: bool = False, **args: Any) -> "PluginSpec":
        return cls(tuple(names), optional, tuple(sorted(args.items())))

    @property
    def label(self) -> str:
        return self.candidates[0]


WINDOWS_PLUGINS: tuple[PluginSpec, ...] = (
    PluginSpec.of("windows.info"),
    PluginSpec.of("windows.pslist"),
    PluginSpec.of("windows.pstree"),
    PluginSpec.of("windows.psscan"),
    PluginSpec.of("windows.cmdline"),
    PluginSpec.of("windows.dlllist"),
    PluginSpec.of("windows.handles"),
    PluginSpec.of("windows.netscan", "windows.netstat"),
    PluginSpec.of("windows.malware.malfind", "windows.malfind"),
    PluginSpec.of("windows.malware.ldrmodules", "windows.ldrmodules"),
    PluginSpec.of("windows.malware.hollowprocesses", "windows.hollowprocesses", optional=True),
    PluginSpec.of("windows.malware.svcscan", "windows.svcscan"),
    PluginSpec.of("windows.getsids"),
)

LINUX_PLUGINS: tuple[PluginSpec, ...] = (
    PluginSpec.of("linux.pslist"),
    PluginSpec.of("linux.pstree"),
    PluginSpec.of("linux.psscan", optional=True),
    PluginSpec.of("linux.psaux"),
    PluginSpec.of("linux.bash"),
    PluginSpec.of("linux.sockstat"),
    PluginSpec.of("linux.lsmod"),
    PluginSpec.of("linux.malware.malfind", "linux.malfind"),
)

MAC_PLUGINS: tuple[PluginSpec, ...] = (
    PluginSpec.of("mac.pslist"),
    PluginSpec.of("mac.pstree"),
    PluginSpec.of("mac.psaux"),
    PluginSpec.of("mac.bash"),
    PluginSpec.of("mac.netstat"),
    PluginSpec.of("mac.lsmod"),
    PluginSpec.of("mac.malware.malfind", "mac.malfind"),
)

PLUGIN_SETS: dict[str, tuple[PluginSpec, ...]] = {
    "windows": WINDOWS_PLUGINS,
    "linux": LINUX_PLUGINS,
    "mac": MAC_PLUGINS,
}


@dataclass(slots=True)
class VolatilityConfig:
    os: str = "windows"
    plugins: Sequence[PluginSpec] | None = None  # None -> PLUGIN_SETS[os]
    backend: str = "auto"  # auto | inprocess | subprocess
    vol_command: Sequence[str] | None = None  # subprocess command prefix; default: `vol`
    symbol_dirs: Sequence[str] = ()
    offline: bool = False
    cache_dir: str | None = None
    remote_isf_url: str | None = None
    timeout_s: int = 3600  # per plugin, subprocess backend
    max_rows: int = MAX_ROWS_DEFAULT  # per plugin

    def plugin_specs(self) -> tuple[PluginSpec, ...]:
        if self.plugins is not None:
            return tuple(self.plugins)
        try:
            return PLUGIN_SETS[self.os]
        except KeyError as exc:
            raise ParserError(f"unknown memory OS profile {self.os!r}") from exc

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, **overrides: Any) -> "VolatilityConfig":
        """Build from ``VERITAS_VOL_*`` environment variables (used by the pipeline worker)."""
        env = dict(os.environ if env is None else env)
        cfg = cls(
            os=env.get("VERITAS_VOL_OS", "windows"),
            backend=env.get("VERITAS_VOL_BACKEND", "auto"),
            symbol_dirs=tuple(p for p in env.get("VERITAS_VOL_SYMBOL_DIRS", "").split(os.pathsep) if p),
            offline=env.get("VERITAS_VOL_OFFLINE", "0").lower() in ("1", "true", "yes"),
            cache_dir=env.get("VERITAS_VOL_CACHE_DIR") or None,
            timeout_s=int(env.get("VERITAS_VOL_TIMEOUT", "3600")),
        )
        if env.get("VERITAS_VOL_COMMAND"):
            cfg.vol_command = tuple(json.loads(env["VERITAS_VOL_COMMAND"]))
        for k, v in overrides.items():
            setattr(cfg, k, v)
        return cfg


@dataclass(slots=True)
class PluginResult:
    requested: str
    plugin: str | None = None  # the candidate that actually ran
    ok: bool = False
    skipped: bool = False
    rows: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False


@dataclass(slots=True)
class MemoryReport:
    image: str
    backend: str
    results: dict[str, PluginResult] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    warning_count: int = 0

    def rows(self, short: str) -> list[dict[str, Any]]:
        """Rows of the step whose plugin short name (``pslist``, ``malfind`` ...) matches."""
        for res in self.results.values():
            name = res.plugin or res.requested
            if res.ok and short_name(name) == short:
                return res.rows
        return []

    def rows_by_short(self) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {}
        for res in self.results.values():
            if res.ok:
                out[short_name(res.plugin or res.requested)] = res.rows
        return out


# --------------------------------------------------------------------------- row helpers
def short_name(plugin: str) -> str:
    """``windows.malware.malfind`` -> ``malfind``; ``windows.pslist.PsList`` -> ``pslist``."""
    parts = [p for p in plugin.split(".") if p]
    if len(parts) >= 2 and parts[-1][:1].isupper():
        parts = parts[:-1]
    return parts[-1].lower() if parts else plugin.lower()


def flatten_tree(nodes: Any, max_rows: int = MAX_ROWS_DEFAULT) -> tuple[list[dict[str, Any]], bool]:
    """Flatten Volatility's JSON tree (``__children`` lists) depth-first into rows.

    Each row gets ``_depth`` and ``_parent`` (index of the parent row or -1). Non-dict nodes are
    ignored. Returns ``(rows, truncated)``. Iterative, so hostile nesting depth cannot recurse.
    """
    rows: list[dict[str, Any]] = []
    if not isinstance(nodes, list):
        return rows, False
    stack: list[tuple[Any, int, int]] = [(n, 0, -1) for n in reversed(nodes)]
    while stack:
        node, depth, parent = stack.pop()
        if not isinstance(node, dict):
            continue
        if len(rows) >= max_rows:
            return rows, True
        row = {str(k): v for k, v in node.items() if k != "__children"}
        row["_depth"] = depth
        row["_parent"] = parent
        idx = len(rows)
        rows.append(row)
        children = node.get("__children")
        if isinstance(children, list):
            stack.extend((c, depth + 1, idx) for c in reversed(children))
    return rows, False


def parse_vol_json(text: str, max_rows: int = MAX_ROWS_DEFAULT) -> tuple[list[dict[str, Any]], bool]:
    """Parse ``vol -r json`` output. Floats are kept as decimal text to stay deterministic."""
    text = text.strip()
    if not text:
        return [], False
    data = json.loads(text, parse_float=lambda s: s)
    if isinstance(data, dict):  # some renderers emit a single object
        data = [data]
    return flatten_tree(data, max_rows)


# --------------------------------------------------------------------------- event mapping
DATA_TYPES: dict[str, str] = {
    "info": "memory:system_info",
    "pslist": "memory:process",
    "pstree": "memory:process",
    "psscan": "memory:process",
    "psaux": "memory:process:cmdline",
    "cmdline": "memory:process:cmdline",
    "dlllist": "memory:module",
    "ldrmodules": "memory:module",
    "lsmod": "memory:kernel_module",
    "modules": "memory:kernel_module",
    "handles": "memory:handle",
    "lsof": "memory:handle",
    "netscan": "memory:network:connection",
    "netstat": "memory:network:connection",
    "sockstat": "memory:network:connection",
    "malfind": "memory:injection",
    "hollowprocesses": "memory:injection",
    "svcscan": "memory:service",
    "getsids": "memory:process:sid",
    "bash": "memory:shell_history",
    "vadyarascan": "memory:yara_match",
    "vmayarascan": "memory:yara_match",
    "yarascan": "memory:yara_match",
}

TIME_COLUMNS: dict[str, str] = {
    "CreateTime": Desc.CREATION,
    "Created": Desc.CREATION,
    "Start Time": Desc.START,
    "StartTime": Desc.START,
    "ExitTime": Desc.END,
    "LoadTime": Desc.START,
    "CommandTime": Desc.EVENT,
    "SystemTime": Desc.EVENT,
}

# Keys shown in messages, in this order, when present in a row.
MESSAGE_KEYS: tuple[str, ...] = (
    "Variable", "Value",
    "ImageFileName", "Process", "COMM", "Name", "PID", "TID", "PPID",
    "Path", "MappedPath", "FullDllName", "Args", "ARGS", "Command", "Binary", "Display",
    "Type", "HandleValue", "GrantedAccess",
    "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "Owner",
    "Start VPN", "Protection", "Base", "InLoad", "InInit", "InMem",
    "Rule", "Component", "SID", "Notes",
)

OFFSET_KEYS = ("Offset(V)", "Offset(P)", "Offset", "Base")


def _row_offset(row: dict[str, Any], index: int) -> int:
    for key in OFFSET_KEYS:
        v = row.get(key)
        if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**63:
            return v
    return index


def _fmt(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "true" if v else "false"
    return clip(str(v), 256)


def row_message(short: str, row: dict[str, Any]) -> str:
    parts = [f"{k}={_fmt(row[k])}" for k in MESSAGE_KEYS if k in row and row[k] not in (None, "")]
    return f"[{short}] " + " ".join(parts) if parts else f"[{short}] row"


def _attrs(plugin: str, row: dict[str, Any]) -> dict[str, Any]:
    attrs: dict[str, Any] = {"plugin": plugin}
    for k, v in row.items():
        if k in ("_depth", "_parent"):
            continue
        if k in ("Hexdump", "Disasm") and isinstance(v, str):
            v = v[:4096]
        attrs[k] = v
    if row.get("_depth"):
        attrs["tree_depth"] = row["_depth"]
    return attrs


def rows_to_events(driver: BaseParser, plugin: str, rows: Iterable[dict[str, Any]]) -> Iterator[Event]:
    """Normalise plugin rows to events: one event per populated time column, else ``Not a time``."""
    short = short_name(plugin)
    data_type = DATA_TYPES.get(short, f"memory:volatility:{short}")
    is_info = short == "info"
    for index, row in enumerate(rows):
        try:
            attrs = _attrs(plugin, row)
            offset = _row_offset(row, index)
            msg = row_message(short, row)
            emitted = False
            if is_info:
                # windows.info is a Variable/Value table; SystemTime is the capture-time clock.
                if row.get("Variable") == "SystemTime":
                    ts = iso_to_ns(str(row.get("Value") or "")) if row.get("Value") else None
                    if ts is not None:
                        yield driver.event(data_type, Desc.EVENT, msg, ts, offset=index, attrs=attrs)
                        emitted = True
                if not emitted:
                    yield driver.event(data_type, Desc.NOT_A_TIME, msg, None, offset=index, attrs=attrs)
                continue
            for col, desc in TIME_COLUMNS.items():
                v = row.get(col)
                if not isinstance(v, str) or not v:
                    continue
                ts = iso_to_ns(v)
                if ts is None:
                    driver.warn(f"{plugin}: row {index}: unparseable {col} {v[:64]!r}")
                    continue
                yield driver.event(data_type, desc, msg, ts, offset=offset, attrs=attrs)
                emitted = True
            if not emitted:
                yield driver.event(data_type, Desc.NOT_A_TIME, msg, None, offset=offset, attrs=attrs)
        except Exception as exc:  # noqa: BLE001 - record-level problem
            driver.warn(f"{plugin}: row {index}: {type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- in-process backend
_FRAMEWORK_LOCK = threading.Lock()
_PLUGIN_LIST: dict[str, Any] | None = None


def framework_available() -> bool:
    try:
        import volatility3.framework  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def available_plugins() -> dict[str, Any]:
    """Map of Volatility plugin names (``windows.pslist.PsList``) to classes; cached."""
    global _PLUGIN_LIST
    with _FRAMEWORK_LOCK:
        if _PLUGIN_LIST is None:
            from volatility3 import framework
            import volatility3.plugins

            framework.require_interface_version(2, 0, 0)
            framework.import_files(volatility3.plugins, True)
            _PLUGIN_LIST = dict(framework.list_plugins())
        return _PLUGIN_LIST


def resolve_plugin(name: str, plugin_list: dict[str, Any]) -> str | None:
    """``windows.pslist`` -> ``windows.pslist.PsList`` (exact module match only)."""
    if name in plugin_list:
        return name
    matches = sorted(k for k in plugin_list if k.rsplit(".", 1)[0] == name)
    return matches[0] if matches else None


def _to_jsonable(value: Any) -> Any:
    """Final scrub after Volatility's JSON type renderers (mirrors json.dumps of the CLI)."""
    from volatility3.framework import interfaces

    if isinstance(value, interfaces.renderers.BaseAbsentValue):
        return None
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        # Volatility's objects.String subclasses str but cannot be copied or pickled; normalise.
        return str.__str__(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return repr(value)  # floats are not allowed in canonical output
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return " ".join(f"{b:02x}" for b in value)
    return str(value)


def _apply_symbol_settings(cfg: VolatilityConfig) -> None:
    from volatility3.framework import constants
    import volatility3.symbols

    constants.OFFLINE = bool(cfg.offline)
    if cfg.remote_isf_url:
        constants.REMOTE_ISF_URL = cfg.remote_isf_url
    if cfg.cache_dir:
        os.makedirs(cfg.cache_dir, exist_ok=True)
        constants.CACHE_PATH = cfg.cache_dir
    extra = [os.path.abspath(p) for p in cfg.symbol_dirs]
    current = list(volatility3.symbols.__path__)
    for p in reversed(extra):
        if p not in current:
            current.insert(0, p)
    volatility3.symbols.__path__ = current  # type: ignore[attr-defined]


def _run_inprocess(image: str, plugin_name: str, args: dict[str, Any], cfg: VolatilityConfig) -> list[dict[str, Any]]:
    from volatility3.cli import text_renderer
    from volatility3.framework import automagic, contexts, interfaces, plugins as fw_plugins
    from volatility3.framework.automagic import stacker
    from volatility3.framework.configuration import requirements

    plugin_list = available_plugins()
    resolved = resolve_plugin(plugin_name, plugin_list)
    if resolved is None:
        raise LookupError(f"plugin {plugin_name} not available")
    plugin_cls = plugin_list[resolved]

    with _FRAMEWORK_LOCK:  # Volatility keeps module-level state (symbol paths, constants)
        _apply_symbol_settings(cfg)
        ctx = contexts.Context()
        automagics = automagic.choose_automagic(automagic.available(ctx), plugin_cls)
        ctx.config["automagic.LayerStacker.single_location"] = requirements.URIRequirement.location_from_file(
            os.path.abspath(image)
        )
        ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin_cls)
        base = "plugins"
        plugin_path = interfaces.configuration.path_join(base, plugin_cls.__name__)
        for key, value in args.items():
            if key.endswith("_file") and isinstance(value, str) and "://" not in value:
                value = requirements.URIRequirement.location_from_file(os.path.abspath(value))
            ctx.config[interfaces.configuration.path_join(plugin_path, key)] = value

        class _DiscardHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
            """Plugins must not write extracted files into the worker; discard them."""

            def __init__(self, filename: str):
                io.BytesIO.__init__(self)
                interfaces.plugins.FileHandlerInterface.__init__(self, filename)

        constructed = fw_plugins.construct_plugin(
            ctx, automagics, plugin_cls, base, lambda *a, **k: None, _DiscardHandler
        )
        grid = constructed.run()

    renderers = text_renderer.JsonRenderer._type_renderers
    columns = list(grid.columns)
    rows: list[dict[str, Any]] = []
    truncated = False

    def visitor(node, acc):
        nonlocal truncated
        if len(acc) >= cfg.max_rows:
            truncated = True
            return acc
        values = list(node.values)
        row: dict[str, Any] = {}
        for i, col in enumerate(columns):
            render = renderers.get(col.type, renderers["default"])
            try:
                row[col.name] = _to_jsonable(render(values[i]))
            except Exception as exc:  # noqa: BLE001 - value-level problem
                row[col.name] = None
                log.debug("value render failed in %s column %s: %s", resolved, col.name, type(exc).__name__)
        depth = max(int(getattr(node, "path_depth", 1)) - 1, 0)
        row["_depth"] = depth
        parent = node.parent
        row["_parent"] = index_by_path.get(parent.path, -1) if parent is not None else -1
        index_by_path[node.path] = len(acc)
        acc.append(row)
        return acc

    index_by_path: dict[str, int] = {}
    grid.populate(visitor, rows)
    if truncated:
        rows.append({"_truncated": True, "_depth": 0, "_parent": -1})
    return rows


# --------------------------------------------------------------------------- subprocess backend
def default_vol_command() -> list[str]:
    """The ``vol`` of this interpreter's environment first, so the CLI and in-process backends run
    the same Volatility build; a ``vol`` elsewhere on PATH may be a different version."""
    scripts = Path(sys.executable).parent
    for cand in ("vol.exe", "vol"):
        p = scripts / cand
        if p.is_file():
            return [str(p)]
    exe = shutil.which("vol")
    if exe:
        return [exe]
    return [sys.executable, "-c", "from volatility3.cli import main; main()"]


def _cli_flag(key: str) -> str:
    return "--" + key.replace("_", "-")


def build_vol_args(image: str, plugin: str, args: dict[str, Any], cfg: VolatilityConfig, outdir: str) -> list[str]:
    cmd = list(cfg.vol_command or default_vol_command())
    cmd += ["-q", "-r", "json", "-o", outdir]
    if cfg.offline:
        cmd.append("--offline")
    if cfg.symbol_dirs:
        cmd += ["-s", ";".join(os.path.abspath(p) for p in cfg.symbol_dirs)]
    if cfg.cache_dir:
        cmd += ["--cache-path", cfg.cache_dir]
    if cfg.remote_isf_url:
        cmd += ["-u", cfg.remote_isf_url]
    cmd += ["-f", os.path.abspath(image), plugin]
    for key, value in sorted(args.items()):
        if isinstance(value, bool):
            if value:
                cmd.append(_cli_flag(key))
        elif isinstance(value, (list, tuple)):
            cmd.append(_cli_flag(key))
            cmd += [str(v) for v in value]
        else:
            cmd += [_cli_flag(key), str(value)]
    return cmd


def _run_subprocess(image: str, plugin: str, args: dict[str, Any], cfg: VolatilityConfig) -> tuple[list[dict[str, Any]], bool]:
    with tempfile.TemporaryDirectory(prefix="veritas-vol-") as outdir:
        cmd = build_vol_args(image, plugin, args, cfg, outdir)
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            cmd,
            cwd=outdir,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=cfg.timeout_s,
            check=False,
        )
    stdout = proc.stdout.decode("utf-8", "replace")
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
        raise RuntimeError(f"vol exited {proc.returncode}: {' | '.join(tail)[:400]}")
    return parse_vol_json(stdout, cfg.max_rows)


# --------------------------------------------------------------------------- driver
MEMORY_MAGICS = (b"PAGEDU64", b"PAGEDUMP", b"EMiL", b"hibr", b"HIBR", b"wake", b"WAKE", b"MDMP")
MEMORY_EXTS = (".raw", ".mem", ".vmem", ".dmp", ".lime", ".img", ".bin", ".core", ".vmss", ".vmsn")


class VolatilityDriver(BaseParser):
    name = "volatility3"
    version = VERSION
    source_short = "MEMORY"
    source_long = "Volatility 3"

    def __init__(self, config: VolatilityConfig | None = None) -> None:
        super().__init__()
        self.config = config or VolatilityConfig()

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if any(head_bytes.startswith(m) for m in MEMORY_MAGICS):
            return True
        return path.lower().endswith(MEMORY_EXTS)

    def _backend(self) -> str:
        b = self.config.backend
        if b == "auto":
            return "inprocess" if framework_available() else "subprocess"
        if b not in ("inprocess", "subprocess"):
            raise ParserError(f"unknown volatility backend {b!r}")
        return b

    def run_plugin(self, image: str, plugin: str, args: dict[str, Any] | None = None) -> PluginResult:
        """Run a single plugin, returning rows or the error (never raises for plugin failures)."""
        return self._run_spec(image, PluginSpec.of(plugin, **(args or {})), self._backend())

    def _run_spec(self, image: str, spec: PluginSpec, backend: str) -> PluginResult:
        res = PluginResult(requested=spec.label)
        args = dict(spec.args)
        plugin_list = available_plugins() if backend == "inprocess" else None
        tried = False
        for cand in spec.candidates:
            if plugin_list is not None and resolve_plugin(cand, plugin_list) is None:
                continue
            tried = True
            try:
                if backend == "inprocess":
                    rows = _run_inprocess(image, cand, args, self.config)
                    truncated = bool(rows and rows[-1].get("_truncated"))
                    if truncated:
                        rows = rows[:-1]
                else:
                    rows, truncated = _run_subprocess(image, cand, args, self.config)
            except subprocess.TimeoutExpired:
                res.errors.append(f"{cand}: timeout after {self.config.timeout_s}s")
                continue
            except Exception as exc:  # noqa: BLE001 - one plugin must not abort the run
                detail = str(exc)
                unsatisfied = getattr(exc, "unsatisfied", None)
                if isinstance(unsatisfied, dict) and unsatisfied:
                    detail = "unsatisfied requirements: " + ", ".join(sorted(str(k) for k in unsatisfied))
                res.errors.append(f"{cand}: {type(exc).__name__}: {clip(detail, 400)}")
                continue
            res.plugin, res.ok, res.rows, res.truncated = cand, True, rows, truncated
            return res
        if not tried:
            res.skipped = True
            res.errors.append(f"{spec.label}: not available in this Volatility build")
        return res

    def run(self, image: str, provenance: Provenance | None = None) -> MemoryReport:
        self.warnings, self.warning_count = [], 0
        self._prov = provenance or Provenance(evidence_path=os.path.basename(image))
        if not os.path.isfile(image):
            raise ParserError(f"memory image not found: {image}")
        backend = self._backend()
        report = MemoryReport(image=image, backend=backend)
        events: list[Event] = []
        for spec in self.config.plugin_specs():
            res = self._run_spec(image, spec, backend)
            report.results[spec.label] = res
            if res.skipped and spec.optional:
                continue
            for err in res.errors if not res.ok else []:
                self.warn(err)
            if res.truncated:
                self.warn(f"{res.plugin}: output truncated at {self.config.max_rows} rows")
            if res.ok:
                events.extend(rows_to_events(self, res.plugin or spec.label, res.rows))
        report.events = sorted_events(events)
        report.warnings, report.warning_count = list(self.warnings), self.warning_count
        return report

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        report = self.run(path, prov)
        yield from report.events


def _as_provenance(p: Any) -> Provenance | None:
    if p is None or isinstance(p, Provenance):
        return p
    return Provenance(evidence_sha256=getattr(p, "evidence_sha256", ""), evidence_path=getattr(p, "evidence_path", ""))


def parse(path: str, provenance: Any = None, config: VolatilityConfig | None = None) -> Iterator[Event]:
    """Pipeline contract: run the configured plugin set (``VERITAS_VOL_*`` env) and yield events."""
    yield from VolatilityDriver(config or VolatilityConfig.from_env()).parse(path, _as_provenance(provenance))
