"""YARA over memory: chunked layer scanning (boundary hits, dedupe) and the Volatility
process-memory plugin path through a fake ``vol`` CLI."""
from __future__ import annotations

import sys
import textwrap

from veritas.malware.yara_scan import compile_rules
from veritas.memory.volatility import VolatilityConfig
from veritas.memory.yarascan import FileLayer, LayerYara, ProcessMemoryYara

RULE = 'rule Marker { meta: severity = "high" strings: $a = "VERITAS-MEMORY-MARKER-0123456789" condition: $a }'
MARKER = b"VERITAS-MEMORY-MARKER-0123456789"


def test_layer_scan_finds_marker_across_chunk_boundary(tmp_path):
    img = tmp_path / "phys.raw"
    data = bytearray(64 * 1024)
    pos = 4096 - 10  # straddles the first chunk boundary
    data[pos:pos + len(MARKER)] = MARKER
    data[40000:40000 + len(MARKER)] = MARKER
    img.write_bytes(bytes(data))
    ly = LayerYara(compile_rules(source=RULE), chunk=4096, overlap=256)
    matches = ly.scan_layer(FileLayer(str(img)), "phys.raw")
    offs = sorted(s["offset"] for m in matches for s in m.strings)
    assert offs == [pos, 40000]
    events = ly.to_events(matches)
    assert [e.offset for e in events] == [pos, 40000]
    assert all(e.data_type == "memory:yara_match" and e.attrs["address_space"] == "physical" for e in events)


def test_layer_scan_handles_unreadable_regions():
    class Flaky:
        maximum_address = 3 * 4096 - 1

        def read(self, offset, length, pad=False):
            if offset == 4096:
                raise OSError("paged out")
            buf = bytearray(length)
            if offset == 8192:
                buf[100:100 + len(MARKER)] = MARKER
            return bytes(buf)

    ly = LayerYara(compile_rules(source=RULE), chunk=4096, overlap=128)
    matches = ly.scan_layer(Flaky())
    assert [m.first_offset for m in matches] == [8192 + 100]
    assert ly.warning_count == 1


FAKE_VOL = textwrap.dedent('''
    import json, sys
    args = sys.argv[1:]
    assert "--yara-file" in args, args
    rules = open(args[args.index("--yara-file") + 1], encoding="utf-8").read()
    assert "rule Mimikatz_Command_Strings" in rules
    rows = [{"Offset": 0x7ff000, "PID": 612, "Rule": "Mimikatz_Command_Strings", "Component": "$c1",
             "Value": "73 65 6b 75", "__children": []}]
    print(json.dumps(rows))
''')


def test_process_memory_yara_via_vadyarascan(tmp_path):
    script = tmp_path / "vol.py"
    script.write_text(FAKE_VOL, encoding="utf-8")
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\0" * 16)
    pm = ProcessMemoryYara(VolatilityConfig(backend="subprocess", vol_command=[sys.executable, str(script)]))
    rule_file = pm.build_combined_rules(str(tmp_path / "combined.yar"))
    assert compile_rules([rule_file]).rule_count == compile_rules().rule_count
    events, warnings = pm.scan(str(img), rule_file)
    assert warnings == []
    assert len(events) == 1
    e = events[0]
    assert e.data_type == "memory:yara_match" and e.attrs["PID"] == 612 and e.attrs["Rule"] == "Mimikatz_Command_Strings"
    assert e.offset == 0x7ff000


def test_process_memory_yara_failure_is_reported(tmp_path):
    img = tmp_path / "mem.raw"
    img.write_bytes(b"\0")
    pm = ProcessMemoryYara(VolatilityConfig(backend="subprocess", vol_command=[sys.executable, "-c", "import sys; sys.exit(3)"]))
    events, warnings = pm.scan(str(img), "rules.yar")
    assert events == [] and warnings and "exited 3" in warnings[0]
    assert ProcessMemoryYara(VolatilityConfig(os="mac")).scan(str(img), "r.yar")[0] == []
