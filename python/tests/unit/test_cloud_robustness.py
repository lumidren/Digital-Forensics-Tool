"""Helpers, robustness (hypothesis) and determinism for veritas.cloud."""
from __future__ import annotations

import json
import plistlib
from datetime import date, datetime, time, timezone
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from veritas.cloud import aws_cloudtrail, aws_elb, aws_s3, azure, base, gws, m365, registry
from veritas.cloud.base import ParserError, ParseResult

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "cloud"
PARSE_FUNCS = [
    aws_cloudtrail.parse, aws_s3.parse, aws_elb.parse, azure.parse, azure.parse_activity_log,
    azure.parse_entra_audit, azure.parse_entra_signin, azure.parse_appgw, gws.parse, m365.parse, registry.parse_auto,
]
SAMPLES = sorted(p.read_bytes() for p in FIX.iterdir())
HYP = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def _no_floats(value):
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(isinstance(k, str) and _no_floats(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_no_floats(v) for v in value)
    return value is None or isinstance(value, (str, int, bool))


def _run_all(data: bytes) -> None:
    for fn in PARSE_FUNCS:
        try:
            result = fn(data)
        except ParserError:
            continue
        for e in result:
            json.dumps(e.to_dict())
            assert _no_floats(e.attrs)
    registry.select("x", data)


@HYP
@given(st.binary(max_size=2048))
def test_random_bytes_only_raise_parsererror(data):
    _run_all(data)


@HYP
@given(st.sampled_from(SAMPLES), st.integers(min_value=0, max_value=6000), st.binary(max_size=8))
def test_truncated_and_mutated_samples(sample, cut, junk):
    _run_all(sample[:cut])
    _run_all(sample[:cut] + junk + sample[cut + len(junk):])


@HYP
@given(st.recursive(st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=20),
                    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4), max_leaves=20))
def test_random_json_structures(value):
    blob = json.dumps({"Records": [value], "value": [value], "items": [value]}).encode()
    _run_all(blob)
    _run_all(json.dumps(value).encode())


def test_determinism_two_runs(corpus):
    sources = [*sorted(FIX.iterdir()), corpus / "plaso" / "aws_elb_access.log",
               corpus / "plaso" / "azure_application_gateway_access.json"]
    for src in sources:
        a = registry.parse_auto(src).to_jsonl()
        b = registry.parse_auto(src).to_jsonl()
        assert a == b and a.endswith("\n")
        for line in a.splitlines():
            d = json.loads(line)
            assert list(d["attrs"]) == sorted(d["attrs"])
            assert _no_floats(d["attrs"])


# --------------------------------------------------------------------------- helper coverage


def test_parse_result_helpers():
    r = ParseResult()
    for i in range(base.MAX_WARNINGS + 5):
        r.warn(f"w{i}")
    assert len(r.warnings) == base.MAX_WARNINGS and r.warning_count == base.MAX_WARNINGS + 5
    other = ParseResult()
    other.extend(r)
    assert other.warning_count == base.MAX_WARNINGS + 5
    assert len(other) == 0 and list(other) == [] and other.to_jsonl() == ""


def test_time_helpers():
    assert base.normalize_iso("2023-01-01 10:00:00.123456789+0000") == "2023-01-01T10:00:00.123456+00:00"
    assert base.parse_time("2023-01-01T00:00:00.1234567Z") == 1672531200123456000
    assert base.parse_time("2023-01-01T00:00:00+0100") == 1672527600000000000
    assert base.parse_time("") is None and base.parse_time(5) is None and base.parse_time("garbage") is None
    assert base.clf_to_iso("06/Feb/2019:00:00:38 +0530") == "2019-02-06T00:00:38+05:30"
    assert base.clf_to_iso("06/Feb/2019:00:00:38.5") == "2019-02-06T00:00:38.5+00:00"
    assert base.clf_to_iso("06/Foo/2019:00:00:38 +0000") is None
    assert base.clf_to_iso("x") is None
    assert base.tz_of("2023-01-01T00:00:00Z") == "UTC"
    assert base.tz_of("2023-01-01T00:00:00+00:00") == "UTC"
    assert base.tz_of("2023-01-01T00:00:00-05:00") == "-05:00"
    assert base.tz_of("2023-01-01") is None and base.tz_of(None) is None


def test_jsonable_and_attr_helpers():
    assert base.jsonable(1.0) == 1 and base.jsonable(1.5) == "1.5" and base.jsonable(float("nan")) == "nan"
    assert base.jsonable(b"\x01\x02") == "0102"
    assert base.jsonable(datetime(2023, 1, 1)) == "2023-01-01T00:00:00.000000Z"
    assert base.jsonable(datetime(2023, 1, 1, tzinfo=timezone.utc)) == "2023-01-01T00:00:00+00:00"
    assert base.jsonable(date(2023, 1, 2)) == "2023-01-02" and base.jsonable(time(1, 2)) == "01:02:00"
    assert base.jsonable({"b": 1, 2: {3}}) == {"2": [3], "b": 1}
    assert base.jsonable(plistlib.UID(7)) == 7
    assert base.jsonable(object.__new__(type("Odd", (), {"__str__": lambda s: "odd"}))) == "odd"
    assert base.jsonable("x" * (base.MAX_STRING_ATTR_CHARS + 5)).endswith("...")
    deep = cur = {}
    for _ in range(12):
        cur["k"] = {}
        cur = cur["k"]
    assert "..." in json.dumps(base.jsonable(deep))
    long_list = base.jsonable(list(range(base.MAX_LIST_ITEMS + 3)))
    assert long_list[-1] == "... 3 more"
    assert base.bounded_json(None) == (None, False)
    assert base.as_int("12") == 12 and base.as_int("1.9") == 1 and base.as_int("-") is None
    assert base.as_int("x") is None and base.as_int(True) is None and base.as_int(2.5) == 2
    assert base.as_int(float("nan")) is None and base.as_int([1]) is None and base.as_int(None) is None
    assert base.redact_last4("356789012345678") == "***********5678" and base.redact_last4("12") == "**"
    assert base.redact_last4(None) is None
    assert base.first({"a": "", "b": 2}, "a", "b") == 2 and base.first(None, "a", default=3) == 3
    assert base.decode_text(b"\xef\xbb\xbfhi") == "hi" and base.decode_text("hé".encode("utf-16")) == "hé"
    assert base.decode_text(b"\xff\xfe\x00") != ""
    assert base.split_log_fields('a "b c" [d e] "unterminated') == ["a", "b c", "d e", "unterminated"]
    assert base.split_log_fields("a [unterminated") == ["a", "unterminated"]
    assert list(base.iter_json_values("{} [] ,  {}")) == [{}, [], {}]


def test_guard_wraps_unexpected():
    with pytest.raises(ParserError, match="ctx: ValueError"):
        with base.guard("ctx"):
            raise ValueError("boom")
    with pytest.raises(KeyboardInterrupt):
        with base.guard("ctx"):
            raise KeyboardInterrupt
    provenance = type("P", (), {"evidence_path": "p", "evidence_sha256": "s", "host": "h", "user": "u"})()
    assert base.provenance_fields(provenance) == ("p", "s")
    assert base.provenance_fields(None, "a", "b") == ("a", "b")
    assert base.apply_provenance(ParseResult(), None).events == []
