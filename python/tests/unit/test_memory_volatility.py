"""Volatility 3 driver: row flattening, event mapping, subprocess backend against a fake ``vol``
CLI, in-process backend failure handling, determinism and no-crash properties."""
from __future__ import annotations

import json
import sys
import textwrap

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from veritas.memory import analyze_image
from veritas.memory.volatility import (
    PluginSpec,
    VolatilityConfig,
    VolatilityDriver,
    available_plugins,
    build_vol_args,
    flatten_tree,
    parse_vol_json,
    resolve_plugin,
    rows_to_events,
    short_name,
)
from veritas.parsers.base import ParserError, Provenance
from veritas.timeline.schema import Desc

PSLIST = [
    {"PID": 4, "PPID": 0, "ImageFileName": "System", "Offset(V)": 0x1000, "CreateTime": "2024-05-01T08:00:00+00:00",
     "ExitTime": None, "Threads": 100, "__children": []},
    {"PID": 500, "PPID": 4, "ImageFileName": "smss.exe", "Offset(V)": 0x2000, "CreateTime": "2024-05-01T08:00:01+00:00",
     "ExitTime": None, "__children": []},
    {"PID": 600, "PPID": 4, "ImageFileName": "wininit.exe", "Offset(V)": 0x3000,
     "CreateTime": "2024-05-01T08:00:02+00:00", "ExitTime": None, "__children": []},
    {"PID": 700, "PPID": 600, "ImageFileName": "lsass.exe", "Offset(V)": 0x4000,
     "CreateTime": "2024-05-01T08:00:03+00:00", "ExitTime": None, "__children": []},
    {"PID": 800, "PPID": 600, "ImageFileName": "services.exe", "Offset(V)": 0x5000,
     "CreateTime": "2024-05-01T08:00:03+00:00", "ExitTime": None, "__children": []},
    {"PID": 900, "PPID": 4242, "ImageFileName": "evil.exe", "Offset(V)": 0x6000,
     "CreateTime": "2024-05-01T09:00:00.500000+00:00", "ExitTime": "2024-05-01T09:05:00+00:00", "__children": []},
    {"PID": 1000, "PPID": 900, "ImageFileName": "svchost.exe", "Offset(V)": 0x7000,
     "CreateTime": "2024-05-01T09:00:01+00:00", "ExitTime": None, "__children": []},
]

FAKE_OUTPUT = {
    "windows.info": [{"Variable": "Kernel Base", "Value": "0xf80000000000", "__children": []},
                     {"Variable": "SystemTime", "Value": "2024-05-01 10:00:00+00:00", "__children": []}],
    "windows.pslist": PSLIST,
    "windows.psscan": PSLIST + [{"PID": 1337, "PPID": 4, "ImageFileName": "rootkit.exe", "Offset(V)": 0x9000,
                                 "CreateTime": "2024-05-01T09:30:00+00:00", "ExitTime": None, "__children": []}],
    "windows.pstree": [dict(PSLIST[0], __children=[dict(PSLIST[1], __children=[])])],
    "windows.netstat": [{"Offset": 0x100, "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 49700,
                         "ForeignAddr": "203.0.113.9", "ForeignPort": 443, "State": "ESTABLISHED", "PID": 1000,
                         "Owner": "svchost.exe", "Created": "2024-05-01T09:01:00+00:00", "__children": []}],
    "windows.malware.malfind": [{"PID": 1000, "Process": "svchost.exe", "Start VPN": 0x10000, "End VPN": 0x10fff,
                                 "Tag": "VadS", "Protection": "PAGE_EXECUTE_READWRITE", "CommitCharge": 1,
                                 "PrivateMemory": 1, "Hexdump": "4d 5a 90 00 03 00", "Disasm": "dec ebp",
                                 "__children": []}],
    "windows.handles": [{"PID": 1000, "Process": "svchost.exe", "Offset": 0x55, "HandleValue": 0x44, "Type": "Process",
                         "GrantedAccess": 0x1010, "Name": "lsass.exe Pid 700", "__children": []},
                        {"PID": 900, "Process": "evil.exe", "Offset": 0x56, "HandleValue": 0x48, "Type": "Process",
                         "GrantedAccess": 0x1fffff, "Name": "lsass.exe Pid 700", "__children": []}],
}

FAKE_VOL = textwrap.dedent('''
    import json, sys, time, os
    argv = sys.argv[1:]
    with open(os.environ["FAKE_VOL_LOG"], "a", encoding="utf-8") as fh:
        fh.write(json.dumps(argv) + "\\n")
    data = json.load(open(os.environ["FAKE_VOL_DATA"], encoding="utf-8"))
    plugin = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-r", "-o", "-f", "-s", "--cache-path", "-u"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        plugin = a
        break
    if plugin == "windows.netscan":
        sys.stderr.write("Unsatisfied requirement plugins.NetScan.kernel.symbol_table_name\\n")
        sys.exit(1)
    if plugin == "windows.sleepy":
        time.sleep(30)
    if plugin not in data:
        sys.stderr.write("vol: error: invalid choice %r\\n" % plugin)
        sys.exit(2)
    sys.stdout.write("\\n" + json.dumps(data[plugin], indent=2, sort_keys=True) + "\\n")
''')


@pytest.fixture
def fake_vol(tmp_path, monkeypatch):
    script = tmp_path / "fake_vol.py"
    script.write_text(FAKE_VOL, encoding="utf-8")
    data = tmp_path / "data.json"
    data.write_text(json.dumps(FAKE_OUTPUT), encoding="utf-8")
    log = tmp_path / "argv.log"
    monkeypatch.setenv("FAKE_VOL_DATA", str(data))
    monkeypatch.setenv("FAKE_VOL_LOG", str(log))
    image = tmp_path / "mem image.raw"
    image.write_bytes(b"\0" * 4096)
    return {"cmd": [sys.executable, str(script)], "log": log, "image": image}


def _cfg(fake_vol, **kw) -> VolatilityConfig:
    return VolatilityConfig(backend="subprocess", vol_command=fake_vol["cmd"], timeout_s=60, **kw)


# --------------------------------------------------------------------------- pure helpers
def test_short_name():
    assert short_name("windows.malware.malfind") == "malfind"
    assert short_name("windows.pslist.PsList") == "pslist"
    assert short_name("linux.bash") == "bash"


def test_flatten_tree_depth_and_parent():
    rows, trunc = flatten_tree(FAKE_OUTPUT["windows.pstree"])
    assert not trunc
    assert [(r["PID"], r["_depth"], r["_parent"]) for r in rows] == [(4, 0, -1), (500, 1, 0)]
    assert all("__children" not in r for r in rows)


def test_flatten_tree_handles_hostile_nesting_and_cap():
    node: dict = {"PID": 0, "__children": []}
    root = node
    for i in range(20000):  # deeper than the recursion limit
        child = {"PID": i + 1, "__children": []}
        node["__children"].append(child)
        node = child
    rows, trunc = flatten_tree([root, "junk", 5, None])
    assert len(rows) == 20001 and not trunc
    rows, trunc = flatten_tree([root], max_rows=10)
    assert len(rows) == 10 and trunc


def test_parse_vol_json_keeps_floats_as_text():
    rows, _ = parse_vol_json('\n[{"A": 1.25, "B": 2, "__children": []}]\n')
    assert rows[0]["A"] == "1.25" and rows[0]["B"] == 2


def test_rows_to_events_time_columns_and_types():
    d = VolatilityDriver()
    d._prov = Provenance(evidence_sha256="ab" * 32, evidence_path="mem.raw")
    rows, _ = flatten_tree(PSLIST)
    events = list(rows_to_events(d, "windows.pslist", rows))
    evil = [e for e in events if e.attrs.get("PID") == 900]
    assert {e.timestamp_desc for e in evil} == {Desc.CREATION, Desc.END}
    created = next(e for e in evil if e.timestamp_desc == Desc.CREATION)
    assert created.timestamp == 1714554000_500000000
    assert created.data_type == "memory:process"
    assert created.offset == 0x6000
    assert created.evidence_sha256 == "ab" * 32
    assert "ImageFileName=evil.exe" in created.message
    info = list(rows_to_events(d, "windows.info", flatten_tree(FAKE_OUTPUT["windows.info"])[0]))
    st_ev = next(e for e in info if e.attrs["Variable"] == "SystemTime")
    assert st_ev.timestamp == 1714557600 * 10**9 and st_ev.data_type == "memory:system_info"
    mal = list(rows_to_events(d, "windows.malware.malfind", flatten_tree(FAKE_OUTPUT["windows.malware.malfind"])[0]))
    assert mal[0].data_type == "memory:injection" and mal[0].timestamp is None
    assert mal[0].timestamp_desc == Desc.NOT_A_TIME


def test_rows_to_events_bad_time_is_warning():
    d = VolatilityDriver()
    events = list(rows_to_events(d, "windows.pslist", [{"PID": 1, "CreateTime": "not a date", "_depth": 0}]))
    assert len(events) == 1 and events[0].timestamp is None
    assert d.warning_count == 1


def test_build_vol_args(tmp_path):
    cfg = VolatilityConfig(vol_command=["vol"], offline=True, symbol_dirs=[str(tmp_path)], cache_dir=str(tmp_path))
    args = build_vol_args("img.raw", "windows.vadyarascan", {"yara_file": "r.yar", "pid": [4, 8]}, cfg, "out")
    assert args[:5] == ["vol", "-q", "-r", "json", "-o"]
    assert "--offline" in args and "-s" in args and "--cache-path" in args
    i = args.index("windows.vadyarascan")
    assert args[i + 1:] == ["--pid", "4", "8", "--yara-file", "r.yar"]


# --------------------------------------------------------------------------- subprocess backend
def test_subprocess_backend_full_run(fake_vol):
    cfg = _cfg(fake_vol, offline=True, plugins=[
        PluginSpec.of("windows.info"), PluginSpec.of("windows.pslist"), PluginSpec.of("windows.psscan"),
        PluginSpec.of("windows.netscan", "windows.netstat"),
        PluginSpec.of("windows.malware.malfind", "windows.malfind"),
        PluginSpec.of("windows.malware.hollowprocesses", optional=True),
        PluginSpec.of("windows.handles"),
    ])
    prov = Provenance(evidence_sha256="cd" * 32, evidence_path="cases/1/mem.raw")
    report = VolatilityDriver(cfg).run(str(fake_vol["image"]), prov)
    assert report.backend == "subprocess"
    assert report.results["windows.netscan"].plugin == "windows.netstat"
    assert report.results["windows.netscan"].errors and "exited 1" in report.results["windows.netscan"].errors[0]
    assert not report.results["windows.malware.hollowprocesses"].ok
    types = {e.data_type for e in report.events}
    assert {"memory:process", "memory:network:connection", "memory:injection", "memory:handle",
            "memory:system_info"} <= types
    assert all(e.evidence_path == "cases/1/mem.raw" and e.parser == "volatility3" for e in report.events)
    # fallback errors from a step that eventually succeeded are not warnings; the absent optional is
    # reported (subprocess cannot know the plugin is absent, so it is a real failure)
    assert any("hollowprocesses" in w for w in report.warnings)
    argv = [json.loads(l) for l in fake_vol["log"].read_text(encoding="utf-8").splitlines()]
    assert all("--offline" in a and "-q" in a and a[a.index("-r") + 1] == "json" for a in argv)
    assert all(a[a.index("-f") + 1] == str(fake_vol["image"].resolve()) for a in argv)


def test_subprocess_backend_is_deterministic(fake_vol):
    cfg = _cfg(fake_vol)
    a = VolatilityDriver(cfg).run(str(fake_vol["image"]))
    b = VolatilityDriver(cfg).run(str(fake_vol["image"]))
    assert [e.to_json() for e in a.events] == [e.to_json() for e in b.events]
    assert [e.sort_key() for e in a.events] == sorted(e.sort_key() for e in a.events)


def test_subprocess_timeout_is_warning(fake_vol):
    cfg = _cfg(fake_vol, plugins=[PluginSpec.of("windows.sleepy"), PluginSpec.of("windows.pslist")])
    cfg.timeout_s = 8  # sleepy sleeps 30 s; generous margin for a loaded CI runner
    report = VolatilityDriver(cfg).run(str(fake_vol["image"]))
    assert any("timeout" in w for w in report.warnings)
    assert report.results["windows.pslist"].ok


def test_parse_contract_and_missing_image(fake_vol, tmp_path):
    from veritas.memory import volatility

    class P:  # any object with the two provenance attributes
        evidence_sha256 = "ef" * 32
        evidence_path = "x/mem.raw"

    events = list(volatility.parse(str(fake_vol["image"]), P(), config=_cfg(fake_vol)))
    assert events and all(e.evidence_sha256 == "ef" * 32 for e in events)
    with pytest.raises(ParserError):
        list(VolatilityDriver(_cfg(fake_vol)).parse(str(tmp_path / "nope.raw")))


def test_analyze_image_end_to_end_with_fake_vol(fake_vol):
    res = analyze_image(str(fake_vol["image"]), _cfg(fake_vol), yara_physical=True)
    rules = {f.rule for f in res.findings}
    assert {"unexpected_parent", "hidden_process", "rwx_private_memory", "lsass_handle"} <= rules
    assert any(e.data_type == "memory:finding" for e in res.events)


def test_config_from_env(monkeypatch, tmp_path):
    env = {"VERITAS_VOL_OS": "linux", "VERITAS_VOL_OFFLINE": "1", "VERITAS_VOL_BACKEND": "subprocess",
           "VERITAS_VOL_SYMBOL_DIRS": str(tmp_path), "VERITAS_VOL_COMMAND": json.dumps(["vol"])}
    cfg = VolatilityConfig.from_env(env)
    assert cfg.os == "linux" and cfg.offline and cfg.backend == "subprocess" and tuple(cfg.vol_command) == ("vol",)
    assert cfg.plugin_specs()[0].label == "linux.pslist"
    with pytest.raises(ParserError):
        VolatilityConfig(os="plan9").plugin_specs()


# --------------------------------------------------------------------------- in-process backend
def test_inprocess_plugin_listing():
    plugins = available_plugins()
    assert resolve_plugin("windows.pslist", plugins) == "windows.pslist.PsList"
    assert resolve_plugin("windows.doesnotexist", plugins) is None


def test_inprocess_junk_image_fails_cleanly(tmp_path):
    img = tmp_path / "junk.raw"
    img.write_bytes(bytes(range(256)) * 1024)
    cfg = VolatilityConfig(backend="inprocess", offline=True, plugins=[
        PluginSpec.of("windows.pslist"), PluginSpec.of("windows.not_a_plugin", optional=True)])
    report = VolatilityDriver(cfg).run(str(img))
    assert report.events == []
    assert report.results["windows.not_a_plugin"].skipped
    assert report.warning_count == 1 and "windows.pslist" in report.warnings[0]


# --------------------------------------------------------------------------- properties
json_scalars = st.one_of(st.none(), st.booleans(), st.integers(-(2**70), 2**70), st.text(max_size=40))
json_values = st.recursive(json_scalars, lambda c: st.one_of(st.lists(c, max_size=4),
                                                             st.dictionaries(st.text(max_size=12), c, max_size=4)),
                           max_leaves=20)
row_strategy = st.dictionaries(
    st.sampled_from(["PID", "PPID", "CreateTime", "ExitTime", "Created", "LoadTime", "Offset(V)", "Base",
                     "ImageFileName", "Variable", "Value", "Hexdump", "x"]),
    json_values, max_size=8)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(row_strategy, max_size=6), st.sampled_from(["windows.pslist", "windows.info", "windows.malfind", "x.y"]))
def test_rows_to_events_never_raises(rows, plugin):
    d = VolatilityDriver()
    for r in rows:
        r["_depth"] = 0
    for e in rows_to_events(d, plugin, rows):
        e.to_json()


@settings(max_examples=200, deadline=None)
@given(json_values)
def test_flatten_tree_never_raises(tree):
    rows, _ = flatten_tree(tree)
    assert all(isinstance(r, dict) for r in rows)


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=200))
def test_parse_vol_json_only_valueerror(text):
    try:
        parse_vol_json(text)
    except ValueError:
        pass


def test_to_jsonable_normalises_str_subclasses():
    import copy

    from veritas.memory.volatility import _to_jsonable

    class Wrapped(str):
        def __reduce_ex__(self, protocol):  # mimics volatility3 objects.String
            raise AttributeError("not copyable")

    out = _to_jsonable(Wrapped("ntdll.dll"))
    assert type(out) is str and out == "ntdll.dll"
    assert copy.deepcopy(out) == "ntdll.dll"
