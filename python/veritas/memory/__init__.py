"""Memory analysis: Volatility 3 driver, heuristics and YARA over memory.

End to end::

    from veritas.memory import analyze_image, VolatilityConfig
    result = analyze_image("mem.raw", VolatilityConfig(os="windows", offline=True,
                                                       symbol_dirs=["/opt/isf"]))
    result.events    # plugin rows + proposed findings as Events, sorted
    result.findings  # MemoryFinding objects
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from veritas.memory.analysis import MemoryAnalyzer, MemoryFinding
from veritas.memory.volatility import (
    PLUGIN_SETS,
    MemoryReport,
    PluginResult,
    PluginSpec,
    VolatilityConfig,
    VolatilityDriver,
)
from veritas.parsers.base import Provenance
from veritas.timeline.schema import Event, sorted_events

__all__ = [
    "PLUGIN_SETS", "MemoryReport", "PluginResult", "PluginSpec", "VolatilityConfig", "VolatilityDriver",
    "MemoryAnalyzer", "MemoryFinding", "MemoryAnalysisResult", "analyze_image",
]


@dataclass(slots=True)
class MemoryAnalysisResult:
    report: MemoryReport
    findings: list[MemoryFinding] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def analyze_image(image: str, config: VolatilityConfig | None = None,
                  provenance: Provenance | None = None, *, yara_physical: bool = False) -> MemoryAnalysisResult:
    """Run the plugin set, the heuristics and (optionally) a symbol-free physical YARA sweep."""
    prov = provenance or Provenance(evidence_path=os.path.basename(image))
    driver = VolatilityDriver(config)
    report = driver.run(image, prov)
    analyzer = MemoryAnalyzer()
    findings = analyzer.analyze(report.rows_by_short())
    events = list(report.events) + analyzer.to_events(findings, prov)
    warnings = list(report.warnings) + list(analyzer.warnings)
    if yara_physical:
        from veritas.memory.yarascan import FileLayer, LayerYara

        ly = LayerYara()
        events += ly.to_events(ly.scan_layer(FileLayer(image), os.path.basename(image)), prov)
        warnings += ly.warnings
    return MemoryAnalysisResult(report, findings, sorted_events(events), warnings)
