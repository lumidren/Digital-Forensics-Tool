"""Zeek adapter: run ``zeek -r`` on a capture and normalise its logs into Events.

Zeek has no Windows build, so this is a subprocess integration with a native fallback:
if no ``zeek`` binary is found (``ZeekConfig.binary``, ``$VERITAS_ZEEK``, then ``PATH``) or it
fails, :class:`ZeekAdapter` runs :class:`veritas.network.pcap.PcapParser` instead and records a
warning, so the pipeline always produces network events.

* Invocation: ``zeek -C -r <pcap> [scripts...] LogAscii::use_json=T`` in a fresh temporary
  directory, argv list (no shell), timeout, stdin closed, and an environment stripped of any
  variable that looks like a credential.
* Logs read: conn, dns, http, ssl, files, x509; both the JSON and the default TSV writer formats.
* Timestamps are converted from Zeek's decimal text with :class:`decimal.Decimal`, never through
  a float, so nanosecond values are exact and reproducible.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Iterator, Sequence

from veritas.network.pcap import PcapParser
from veritas.parsers.base import BaseParser, ParserError, Provenance
from veritas.timeline.schema import Desc, Event, iso_to_ns, sorted_events

VERSION = "1.0"
LOGS = ("conn", "dns", "http", "ssl", "files", "x509")
DEFAULT_SCRIPTS = ("frameworks/files/hash-all-files",)
_SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)", re.I)
NS = Decimal(1_000_000_000)
_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")


@dataclass(slots=True)
class ZeekConfig:
    binary: str | None = None
    scripts: Sequence[str] = DEFAULT_SCRIPTS
    timeout_s: int = 3600
    fallback: bool = True
    max_rows_per_log: int = 5_000_000


@dataclass(slots=True)
class ZeekReport:
    path: str
    backend: str  # "zeek" or "native"
    events: list[Event] = field(default_factory=list)
    logs: dict[str, int] = field(default_factory=dict)  # log name -> rows read
    warnings: list[str] = field(default_factory=list)
    warning_count: int = 0


def find_zeek(cfg: ZeekConfig | None = None) -> str | None:
    cfg = cfg or ZeekConfig()
    for cand in (cfg.binary, os.environ.get("VERITAS_ZEEK")):
        if cand:
            return cand if os.path.isfile(cand) else shutil.which(cand)
    return shutil.which("zeek")


def scrubbed_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not _SECRET_ENV.search(k)}


# --------------------------------------------------------------------------- value helpers
def zeek_time_ns(v: Any) -> int | None:
    if v is None or v == "-" or v == "":
        return None
    if isinstance(v, Decimal):
        d = v
    elif isinstance(v, int) and not isinstance(v, bool):
        d = Decimal(v)
    elif isinstance(v, str):
        if "T" in v:
            return iso_to_ns(v)
        try:
            d = Decimal(v)
        except InvalidOperation:
            return None
    else:
        return None
    if not d.is_finite():
        return None
    return int((d * NS).to_integral_value())


def _plain(v: Any) -> Any:
    """Make a parsed Zeek value JSON-safe and float-free (Decimal -> canonical text)."""
    if isinstance(v, Decimal):
        return format(v, "f")
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    return v


def _tsv_value(raw: str, ztype: str, unset: str, empty: str, set_sep: str) -> Any:
    if raw == unset:
        return None
    if raw == empty:
        return [] if ztype.startswith(("set[", "vector[")) else ""
    if ztype.startswith(("set[", "vector[")):
        inner = ztype[ztype.index("[") + 1:-1]
        return [_tsv_value(x, inner, unset, empty, set_sep) for x in raw.split(set_sep)]
    if ztype in ("count", "int", "port"):
        try:
            return int(raw)
        except ValueError:
            return raw
    if ztype in ("time", "interval", "double"):
        try:
            return Decimal(raw)
        except InvalidOperation:
            return raw
    if ztype == "bool":
        return raw == "T"
    return _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), raw) if "\\x" in raw else raw


def read_log(path: str, warn, max_rows: int) -> Iterator[dict[str, Any]]:
    """Yield rows of a Zeek log written by either the JSON or the TSV ASCII writer."""
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        first = fh.readline()
        fh.seek(0)
        n = 0
        if first.lstrip().startswith("{"):
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                if n >= max_rows:
                    warn(f"{os.path.basename(path)}: row cap {max_rows} reached")
                    return
                try:
                    row = json.loads(line, parse_float=Decimal)
                except ValueError as exc:
                    warn(f"{os.path.basename(path)}:{lineno}: bad JSON: {exc}")
                    continue
                if isinstance(row, dict):
                    n += 1
                    yield row
            return
        sep, set_sep, empty, unset = "\t", ",", "(empty)", "-"
        fields: list[str] = []
        types: list[str] = []
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\r\n")
            if line.startswith("#"):
                key, _, val = line[1:].partition(sep if not line.startswith("#separator") else " ")
                if key == "separator":
                    try:
                        sep = val.strip().encode().decode("unicode_escape") or "\t"
                    except UnicodeDecodeError:
                        sep = "\t"
                elif key == "set_separator":
                    set_sep = val
                elif key == "empty_field":
                    empty = val
                elif key == "unset_field":
                    unset = val
                elif key == "fields":
                    fields = val.split(sep)
                elif key == "types":
                    types = val.split(sep)
                continue
            if not line or not fields:
                continue
            if n >= max_rows:
                warn(f"{os.path.basename(path)}: row cap {max_rows} reached")
                return
            parts = line.split(sep)
            if len(parts) != len(fields):
                warn(f"{os.path.basename(path)}:{lineno}: {len(parts)} columns, expected {len(fields)}")
                continue
            ty = types if len(types) == len(fields) else ["string"] * len(fields)
            n += 1
            yield {f: _tsv_value(p, t, unset, empty, set_sep) for f, p, t in zip(fields, parts, ty)}


# --------------------------------------------------------------------------- mapping
def _nz(v: Any) -> Any:
    return None if v in ("-", "") else v


class ZeekAdapter(BaseParser):
    name = "zeek"
    version = VERSION
    source_short = "NET"
    source_long = "Zeek"

    def __init__(self, config: ZeekConfig | None = None) -> None:
        super().__init__()
        self.config = config or ZeekConfig()

    def matches(self, path: str, head_bytes: bytes) -> bool:
        return PcapParser().matches(path, head_bytes)

    # ------------------------------------------------------------------ public API
    def analyze(self, path: str, provenance: Provenance | None = None) -> ZeekReport:
        self.warnings, self.warning_count = [], 0
        prov = provenance or Provenance(evidence_path=os.path.basename(path))
        self._prov = prov
        if not os.path.isfile(path):
            raise ParserError(f"capture not found: {path}")
        binary = find_zeek(self.config)
        if binary:
            try:
                with tempfile.TemporaryDirectory(prefix="veritas-zeek-") as logdir:
                    self.run_zeek(binary, path, logdir)
                    report = self.parse_log_dir(logdir, path, prov)
                    report.warnings, report.warning_count = list(self.warnings), self.warning_count
                    return report
            except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
                self.warn(f"zeek failed: {type(exc).__name__}: {str(exc)[:300]}")
                if not self.config.fallback:
                    raise ParserError(f"zeek failed: {exc}") from exc
        else:
            if not self.config.fallback:
                raise ParserError("zeek binary not found")
            self.warn("zeek binary not found; using native PCAP parser")
        native = PcapParser()
        rep = native.analyze(path, prov)
        for w in rep.warnings:
            self.warn(w)
        self.warning_count += max(rep.warning_count - len(rep.warnings), 0)
        return ZeekReport(path, "native", rep.events, {}, list(self.warnings), self.warning_count)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        yield from self.analyze(path, prov).events

    def run_zeek(self, binary: str, pcap: str, logdir: str) -> None:
        cmd = [binary, "-C", "-r", os.path.abspath(pcap), *self.config.scripts, "LogAscii::use_json=T"]
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            cmd, cwd=logdir, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=self.config.timeout_s, env=scrubbed_env(), check=False,
        )
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
            raise RuntimeError(f"zeek exited {proc.returncode}: {' | '.join(tail)}")
        for line in proc.stderr.decode("utf-8", "replace").splitlines()[:50]:
            if line.strip():
                self.warn(f"zeek: {line.strip()[:300]}")

    def parse_log_dir(self, logdir: str, pcap: str, prov: Provenance | None = None) -> ZeekReport:
        if prov is not None:
            self._prov = prov
        report = ZeekReport(pcap, "zeek")
        events: list[Event] = []
        for log in LOGS:
            path = os.path.join(logdir, f"{log}.log")
            if not os.path.isfile(path):
                continue
            count = 0
            for row in read_log(path, self.warn, self.config.max_rows_per_log):
                count += 1
                try:
                    ev = getattr(self, f"_map_{log}")(row, count)
                except Exception as exc:  # noqa: BLE001 - record-level
                    self.warn(f"{log}.log row {count}: {type(exc).__name__}: {exc}")
                    continue
                if ev is not None:
                    events.append(ev)
            report.logs[log] = count
        report.events = sorted_events(events)
        return report

    # ------------------------------------------------------------------ per-log mapping
    def _ev(self, data_type: str, desc: str, msg: str, row: dict[str, Any], log: str, rowno: int,
            attrs: dict[str, Any]) -> Event:
        ts = zeek_time_ns(row.get("ts"))
        attrs = {k: _plain(v) for k, v in attrs.items()}
        attrs["zeek_log"] = log
        return self.event(data_type, desc, msg, ts, offset=rowno, attrs=attrs)

    @staticmethod
    def _endpoints(row: dict[str, Any]) -> dict[str, Any]:
        return {"uid": row.get("uid"), "orig_h": row.get("id.orig_h"), "orig_p": row.get("id.orig_p"),
                "resp_h": row.get("id.resp_h"), "resp_p": row.get("id.resp_p")}

    def _map_conn(self, row, rowno):
        dur = zeek_time_ns(row.get("duration"))
        a = dict(self._endpoints(row), proto=row.get("proto"), service=_nz(row.get("service")),
                 duration_ns=dur, orig_bytes=row.get("orig_bytes"), resp_bytes=row.get("resp_bytes"),
                 orig_pkts=row.get("orig_pkts"), resp_pkts=row.get("resp_pkts"), conn_state=row.get("conn_state"),
                 history=row.get("history"))
        svc = f" [{a['service']}]" if a["service"] else ""
        msg = (f"{str(a['proto'] or '').upper()} {a['orig_h']}:{a['orig_p']} -> {a['resp_h']}:{a['resp_p']}{svc} "
               f"{(a['orig_pkts'] or 0) + (a['resp_pkts'] or 0)} packets {(a['orig_bytes'] or 0) + (a['resp_bytes'] or 0)} bytes")
        return self._ev("network:conn", Desc.START, msg, row, "conn", rowno, a)

    def _map_dns(self, row, rowno):
        answers = row.get("answers") or []
        a = dict(self._endpoints(row), query=row.get("query"), qtype=row.get("qtype_name"),
                 rcode=row.get("rcode_name"), answers=answers, trans_id=row.get("trans_id"),
                 proto=row.get("proto"), client=row.get("id.orig_h"), server=row.get("id.resp_h"))
        msg = f"DNS {a['query']} {a['qtype']} {a['rcode'] or ''}".rstrip()
        if answers:
            msg += ": " + ", ".join(str(x) for x in answers[:10])
        return self._ev("network:dns", Desc.SENT, msg, row, "dns", rowno, a)

    def _map_http(self, row, rowno):
        host, uri = row.get("host") or row.get("id.resp_h"), row.get("uri") or ""
        url = uri if str(uri).lower().startswith(("http://", "https://")) else f"http://{host}{uri}"
        a = dict(self._endpoints(row), method=row.get("method"), host=host, uri=uri, url=url,
                 user_agent=row.get("user_agent"), referrer=row.get("referrer"), status_code=row.get("status_code"),
                 status_msg=row.get("status_msg"), request_body_len=row.get("request_body_len"),
                 response_body_len=row.get("response_body_len"), resp_mime_types=row.get("resp_mime_types"),
                 resp_fuids=row.get("resp_fuids"))
        msg = f"HTTP {a['method']} {url}" + (f" -> {a['status_code']}" if a["status_code"] is not None else "")
        return self._ev("network:http:request", Desc.SENT, msg, row, "http", rowno, a)

    def _map_ssl(self, row, rowno):
        a = dict(self._endpoints(row), sni=row.get("server_name"), version=row.get("version"),
                 cipher=row.get("cipher"), established=row.get("established"), ja3=row.get("ja3"),
                 ja3s=row.get("ja3s"), subject=row.get("subject"), issuer=row.get("issuer"),
                 cert_chain_fps=row.get("cert_chain_fps") or row.get("cert_chain_fuids"))
        msg = f"TLS {a['version'] or '?'} SNI={a['sni'] or '-'} cipher={a['cipher'] or '-'}"
        return self._ev("network:tls:client_hello", Desc.SENT, msg, row, "ssl", rowno, a)

    def _map_files(self, row, rowno):
        a = {"fuid": row.get("fuid"), "uid": (row.get("conn_uids") or [None])[0] if isinstance(row.get("conn_uids"), list) else row.get("uid"),
             "source": row.get("source"), "mime": row.get("mime_type"), "filename": row.get("filename"),
             "size": row.get("seen_bytes"), "total_bytes": row.get("total_bytes"), "md5": row.get("md5"),
             "sha1": row.get("sha1"), "sha256": row.get("sha256"), "tx_h": row.get("tx_hosts"),
             "rx_h": row.get("rx_hosts"), "complete": not row.get("missing_bytes")}
        msg = (f"File {a['filename'] or '-'} {a['size']} bytes {a['mime'] or '-'} "
               f"sha256={a['sha256'] or '-'} via {a['source'] or '-'}")
        return self._ev("network:file", Desc.RECEIVED, msg, row, "files", rowno, a)

    def _map_x509(self, row, rowno):
        a = {"fingerprint": row.get("fingerprint") or row.get("id"), "subject": row.get("certificate.subject"),
             "issuer": row.get("certificate.issuer"), "serial": row.get("certificate.serial"),
             "not_before_ns": zeek_time_ns(row.get("certificate.not_valid_before")),
             "not_after_ns": zeek_time_ns(row.get("certificate.not_valid_after")),
             "san": row.get("san.dns")}
        msg = f"TLS certificate subject={a['subject']} issuer={a['issuer']}"
        return self._ev("network:tls:certificate", Desc.RECEIVED, msg, row, "x509", rowno, a)


def parse(path: str, provenance: Any = None) -> Iterator[Event]:
    """Pipeline contract: Zeek when available, otherwise the native parser."""
    yield from ZeekAdapter().parse(path, _as_provenance(provenance))


def _as_provenance(p: Any) -> Provenance | None:
    if p is None or isinstance(p, Provenance):
        return p
    return Provenance(evidence_sha256=getattr(p, "evidence_sha256", ""), evidence_path=getattr(p, "evidence_path", ""))
