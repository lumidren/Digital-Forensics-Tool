"""Structured logging, Prometheus metrics, OpenTelemetry tracing and the progress hub."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import time
from importlib import metadata
from pathlib import Path
from typing import Any

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

REQUESTS = Counter("veritas_http_requests_total", "HTTP requests", ["method", "route", "status"])
REQUEST_LATENCY = Histogram("veritas_http_request_seconds", "HTTP request latency", ["route"])
SEARCH_LATENCY = Histogram("veritas_search_latency_seconds", "Timeline search latency", buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5))
QUEUE_DEPTH = Gauge("veritas_queue_depth", "Pending and running processing jobs")
PARSER_EVENTS = Counter("veritas_parser_events_total", "Events produced by parsers", ["parser"])
PARSER_ERRORS = Counter("veritas_parser_errors_total", "Parser failures", ["parser"])
BYTES_PROCESSED = Counter("veritas_bytes_processed_total", "Evidence bytes processed")
STORE_BYTES = Gauge("veritas_store_bytes", "Bytes held in the evidence store")
STORE_OBJECTS = Gauge("veritas_store_objects", "Objects held in the evidence store")
TIMELINE_EVENTS = Gauge("veritas_timeline_events", "Timeline events per case", ["case_id"])

# Order matters: whole-token patterns run before key=value so "Authorization: Bearer <t>" loses <t>.
_TOKEN_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]
_KV_PATTERN = re.compile(r"(?i)\b(password|passphrase|secret|token|access_token|api[_-]?key|client_secret)(\"?\s*[:=]\s*\"?)([^\s\"&,]+)")


def scrub_text(s: str) -> str:
    """Remove secret-looking values before a log line is written."""
    for p in _TOKEN_PATTERNS:
        s = p.sub("[redacted]", s)
    return _KV_PATTERN.sub(lambda m: m.group(1) + m.group(2) + "[redacted]", s)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        d: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(), "logger": record.name, "msg": scrub_text(record.getMessage()),
        }
        try:
            from opentelemetry import trace

            span = trace.get_current_span().get_span_context()
            if span.is_valid:
                d["trace_id"], d["span_id"] = f"{span.trace_id:032x}", f"{span.span_id:016x}"
        except Exception:
            pass
        if record.exc_info:
            d["exc"] = scrub_text(self.formatException(record.exc_info))
        return json.dumps(d, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(level)


def configure_tracing(service: str, endpoint: str | None) -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": service}))
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint.rstrip("/") + "/v1/traces")))
        except ImportError:
            logging.getLogger("veritas").warning("OTLP exporter not installed; traces stay local")
    trace.set_tracer_provider(provider)


class ProgressHub:
    """Fan-out of pipeline progress to WebSocket subscribers. Thread-safe publish from workers."""

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self._subs: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def publish(self, msg: dict[str, Any]) -> None:
        if msg.get("state") == "failed":
            PARSER_ERRORS.labels(msg.get("step", "?")).inc()
        if self.loop is None:
            return
        for q in list(self._subs):
            self.loop.call_soon_threadsafe(_put, q, msg)


def _put(q: asyncio.Queue, msg: dict[str, Any]) -> None:
    if not q.full():
        q.put_nowait(msg)


def install(app, ctx, jobs) -> None:
    from fastapi import Request
    from fastapi.responses import Response

    configure_tracing("veritas-api", ctx.settings.otel_endpoint)
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except ImportError:
        pass

    @app.middleware("http")
    async def metrics_mw(request: Request, call_next):
        t0 = time.perf_counter()
        resp = await call_next(request)
        route = request.scope.get("route").path if request.scope.get("route") else "unmatched"
        REQUESTS.labels(request.method, route, str(resp.status_code)).inc()
        REQUEST_LATENCY.labels(route).observe(time.perf_counter() - t0)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/metrics")
    def metrics():
        QUEUE_DEPTH.set(jobs.queue_depth())
        try:
            objs = ctx.store.list()
            STORE_OBJECTS.set(len(objs))
            STORE_BYTES.set(sum(ctx.store.meta(a).hashes.length for a in objs[:100000]))
        except Exception:
            pass
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _sha256_file(p: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def tool_inventory() -> list[dict[str, Any]]:
    """Versions and hashes of every tool that can touch evidence; reported in methodology."""
    from .. import __version__

    root = Path(__file__).resolve().parents[3]
    tools = [{"name": "veritas (python)", "version": __version__, "sha256": None}]
    for name in ("veritas", "veritas-verify", "fs-tool", "veritas-artifacts-dump", "veritas-agent"):
        for d in filter(None, [os.environ.get("VERITAS_BIN_DIR"), str(root / "target" / "release")]):
            p = Path(d) / (name + (".exe" if os.name == "nt" else ""))
            if p.exists():
                tools.append({"name": name, "version": __version__, "sha256": _sha256_file(p)})
                break
    for pkg in ("volatility3", "yara-python", "pefile", "lief", "dpkt", "libpff-python", "libesedb-python", "reportlab", "python-docx"):
        try:
            tools.append({"name": pkg, "version": metadata.version(pkg), "sha256": None})
        except metadata.PackageNotFoundError:
            pass
    return tools


def parity_summary() -> list[dict[str, Any]]:
    root = Path(__file__).resolve().parents[3] / "parity" / "results"
    out = []
    for p in sorted(root.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            continue
        agree = sum(f["agree"] for f in d.get("fields", {}).values())
        total = sum(f["total"] for f in d.get("fields", {}).values())
        out.append({"parser": d.get("parser", p.stem), "reference": d.get("reference", ""), "fields": len(d.get("fields", {})), "agreement": f"{(100.0 * agree / total) if total else 0:.2f}%"})
    return out
