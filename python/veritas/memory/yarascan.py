"""YARA over memory.

``ProcessMemoryYara`` scans *process* memory through Volatility: it runs ``windows.vadyarascan``
(Windows, walks each process VAD tree through the process's virtual layer) or
``linux.vmayarascan`` (Linux VMAs) with the curated rule file, so hits carry PID, process name
and virtual address. It needs kernel symbols like any other Volatility plugin.

``LayerYara`` scans any readable layer in overlapping windows. A layer is anything with
``read(offset, length)`` and ``maximum_address`` (a Volatility ``DataLayerInterface`` from
``context.layers`` qualifies, so does :class:`FileLayer` over the raw image). It needs no
symbols and is the fallback when symbol resolution fails; hits carry physical offsets.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterator, Protocol

from veritas.malware.yara_scan import CompiledRules, YaraMatch, YaraScanner, compile_rules, rules_dir
from veritas.memory.volatility import PluginSpec, VolatilityConfig, VolatilityDriver, rows_to_events
from veritas.parsers.base import BaseParser, Provenance
from veritas.timeline.schema import Desc, Event, sorted_events

VERSION = "1.0"

YARA_PLUGINS = {
    "windows": ("windows.vadyarascan",),
    "linux": ("linux.vmayarascan",),
    "mac": (),
}


class ProcessMemoryYara:
    """Run Volatility's process-memory YARA plugin and normalise hits."""

    def __init__(self, config: VolatilityConfig | None = None) -> None:
        self.config = config or VolatilityConfig()

    def build_combined_rules(self, out_path: str, rule_paths: list[str] | None = None) -> str:
        """Write the curated rule set as one file (imports hoisted) for ``--yara-file``."""
        from veritas.malware.yara_scan import _collect

        imports: set[str] = set()
        bodies: list[str] = []
        for ns, f in _collect(rule_paths or [rules_dir()]):
            text = f.read_text(encoding="utf-8", errors="replace")
            lines = []
            for line in text.splitlines():
                if line.strip().startswith("import "):
                    imports.add(line.strip())
                else:
                    lines.append(line)
            bodies.append(f"// ---- {ns}\n" + "\n".join(lines))
        content = "\n".join(sorted(imports)) + "\n\n" + "\n\n".join(bodies) + "\n"
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        compile_rules([out_path])  # validate
        return out_path

    def scan(self, image: str, rule_file: str, pids: list[int] | None = None,
             provenance: Provenance | None = None) -> tuple[list[Event], list[str]]:
        driver = VolatilityDriver(self.config)
        driver._prov = provenance or Provenance(evidence_path=os.path.basename(image))
        args: dict[str, Any] = {"yara_file": rule_file}
        if pids:
            args["pid"] = list(pids)
        names = YARA_PLUGINS.get(self.config.os, ())
        if not names:
            return [], [f"no process-memory YARA plugin for os {self.config.os}"]
        spec = PluginSpec(names, False, tuple(sorted(args.items())))
        res = driver._run_spec(image, spec, driver._backend())
        if not res.ok:
            return [], list(res.errors)
        events = list(rows_to_events(driver, res.plugin or names[0], res.rows))
        return sorted_events(events), list(driver.warnings)


class Layer(Protocol):
    maximum_address: int

    def read(self, offset: int, length: int, pad: bool = False) -> bytes: ...


@dataclass
class FileLayer:
    """Raw/physical image as a layer (``maximum_address`` is inclusive like Volatility's)."""

    path: str

    def __post_init__(self) -> None:
        self._size = os.path.getsize(self.path)
        self.maximum_address = max(self._size - 1, 0)

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(length)
        if pad and len(data) < length:
            data += b"\0" * (length - len(data))
        return data


class LayerYara(BaseParser):
    name = "memory_yara"
    version = VERSION
    source_short = "MEMORY"
    source_long = "YARA over memory layer"

    def __init__(self, rules: CompiledRules | None = None, *, chunk: int = 32 * 1024 * 1024,
                 overlap: int = 64 * 1024, timeout_s: int = 120) -> None:
        super().__init__()
        if overlap >= chunk:
            raise ValueError("overlap must be smaller than chunk")
        self.scanner = YaraScanner(rules, timeout_s=timeout_s)
        self.chunk, self.overlap = chunk, overlap

    def scan_layer(self, layer: Any, label: str = "layer") -> list[YaraMatch]:
        end = int(layer.maximum_address) + 1
        seen: dict[tuple, YaraMatch] = {}
        pos = 0
        while pos < end:
            length = min(self.chunk + self.overlap, end - pos)
            try:
                data = layer.read(pos, length, pad=True)
            except Exception as exc:  # noqa: BLE001 - unreadable/paged-out region
                self.warn(f"{label}: read failed at 0x{pos:x}: {type(exc).__name__}")
                pos += self.chunk
                continue
            for m in self.scanner.scan_bytes(data, label, base_offset=pos):
                seen.setdefault((m.namespace, m.rule, m.first_offset), m)
            pos += self.chunk
        for w in self.scanner.warnings:
            self.warn(w)
        self.scanner.warnings.clear()
        return [seen[k] for k in sorted(seen)]

    def to_events(self, matches: list[YaraMatch], provenance: Provenance | None = None) -> list[Event]:
        if provenance is not None:
            self._prov = provenance
        out = []
        for m in matches:
            out.append(self.event(
                "memory:yara_match", Desc.NOT_A_TIME,
                f"YARA rule {m.namespace}.{m.rule} matched physical offset 0x{m.first_offset:x}",
                None, offset=m.first_offset,
                attrs={**m.to_dict(), "severity": str(m.meta.get("severity", "")),
                       "rules_fingerprint": self.scanner.rules.fingerprint, "address_space": "physical"},
            ))
        return sorted_events(out)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        yield from self.to_events(self.scan_layer(FileLayer(path), os.path.basename(path)), prov)
