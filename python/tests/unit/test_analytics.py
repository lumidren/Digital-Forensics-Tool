import pytest

from veritas.analytics import attack
from veritas.analytics.execution import correlate
from veritas.analytics.findings import FindingsEngine, Finding, PROPOSED, iter_stored
from veritas.analytics.ioc import Indicator, Matcher, infer_type, load_indicators
from veritas.analytics.lateral import build_graph
from veritas.analytics.provenance import build as build_prov
from veritas.analytics.timestomp import indicators
from veritas.analytics.user_activity import reconstruct
from veritas.timeline.schema import Desc, Event

T0 = 1_700_000_000_000_000_000
NS = 1_000_000_000


def ev(data_type, msg="", ts=T0, host="WS01", user="alice", **attrs):
    return Event(data_type=data_type, timestamp_desc=Desc.EVENT, message=msg, timestamp=ts, evidence_sha256="e" * 64, evidence_path="p", host=host, user=user, attrs=attrs)


def evtx(eid, ts=T0, host="WS01", user=None, **ed):
    return ev("windows:evtx:record", f"[{eid}]", ts, host, user, event_identifier=eid, channel="Security", source_name="Microsoft-Windows-Security-Auditing", record_number=ed.pop("rn", 1), event_data=ed, **{k.lower(): v for k, v in ed.items()})


def test_finding_normalization_and_state():
    f = Finding("r", "t", "d", "high", 1.7, "c", ["T1", "T1"], [3, 1, 1], ["b", "a"], ["h", ""], ["u"])
    assert f.confidence == 1.0 and f.attack_techniques == ["T1"] and f.event_ids == [1, 3] and f.hosts == ["h"]
    assert f.state == PROPOSED and len(f.finding_id) == 24
    with pytest.raises(ValueError):
        Finding("r", "t", "d", "urgent", 0.5, "c")


def test_timestomp_indicators():
    assert indicators({"si_crtime_ns": T0, "fn_crtime_ns": T0 + 10 * NS}) == ["si_before_fn"]
    assert indicators({"si_crtime_ns": T0, "si_mtime_ns": T0, "fn_crtime_ns": T0 - NS, "fn_mtime_ns": T0 + 123}) == ["zero_subsecond"]
    assert indicators({"timestomp_indicators": ["x"]}) == ["x"]
    assert indicators({}) == []


def test_engine_runs_all_rules_and_only_proposes():
    events = [
        ev("fs:stat:ntfs", "f", file_reference="70-1", path="/Users/bob/Desktop/payload.exe", si_crtime_ns=T0, fn_crtime_ns=T0 + 10 * NS + 1234),
        evtx(1102, rn=5),
        evtx(4688, rn=6, NewProcessName="C:\\Tools\\mimikatz.exe", process_name="C:\\Tools\\mimikatz.exe", command_line="mimikatz.exe"),
        evtx(4624, rn=7, LogonType="10", IpAddress="10.0.0.5", TargetUserName="admin", logon_type="10", ip_address="10.0.0.5", target_user_name="admin"),
        ev("windows:registry:run", "run key", value="C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"),
        ev("chrome:history:file_downloaded", "dl", full_path="C:\\Users\\alice\\Downloads\\inv.exe", url="http://evil.example/inv.exe"),
        ev("windows:prefetch:execution", "pf", executable="INV.EXE", mapped_files=["\\VOLUME{1}\\USERS\\ALICE\\DOWNLOADS\\INV.EXE"]),
        ev("windows:shellbags", "bag"),
    ]
    findings = FindingsEngine().run(iter_stored(events))
    rules = {f.rule for f in findings}
    assert {"timestomp", "antiforensics", "execution", "lateral_movement", "persistence", "file_provenance", "user_activity"} <= rules
    assert all(f.state == PROPOSED for f in findings)
    assert findings[0].severity in ("critical", "high")
    exe = next(f for f in findings if f.rule == "execution" and "mimikatz" in f.title)
    assert exe.details["rows"][0]["proves_execution"] is True and "T1003.001" in exe.attack_techniques
    assert attack.describe("T1003.001").startswith("OS Credential Dumping")


def test_execution_correlation_sources():
    rows = correlate(iter_stored([
        ev("windows:prefetch:execution", executable="EVIL.EXE"),
        ev("windows:registry:appcompatcache", path="C:\\x\\evil.exe"),
        ev("windows:registry:amcache", full_path="c:\\x\\evil.exe", sha1="A" * 40),
        ev("windows:registry:amcache", full_path="c:\\y\\good.exe", sha1="A" * 40),
        ev("windows:registry:appcompatcache", path="C:\\only\\present.exe"),
    ]))
    assert set(rows["evil.exe"].sources) == {"prefetch", "shimcache", "amcache"}
    assert rows["evil.exe"].proves_execution() and not rows["present.exe"].proves_execution()
    findings = list(__import__("veritas.analytics.execution", fromlist=["x"]).ExecutionCorrelationRule().run(iter_stored([
        ev("windows:registry:amcache", full_path="c:\\x\\evil.exe", sha1="A" * 40),
        ev("windows:registry:amcache", full_path="c:\\y\\good.exe", sha1="A" * 40),
    ])))
    assert any("several names" in f.title for f in findings)


def test_lateral_graph():
    edges = build_graph(iter_stored([
        evtx(4624, LogonType="3", IpAddress="10.1.1.2", TargetUserName="svc", logon_type="3", ip_address="10.1.1.2", target_user_name="svc", LogonProcessName="NtLmSsp", AuthenticationPackageName="NTLM"),
        evtx(4624, LogonType="2", IpAddress="-", TargetUserName="local", logon_type="2"),
        evtx(7045, ServiceName="PSEXESVC", ImagePath="%SystemRoot%\\PSEXESVC.exe", service_name="PSEXESVC", image_path="%SystemRoot%\\PSEXESVC.exe"),
        evtx(4625, IpAddress="10.9.9.9", TargetUserName="root", ip_address="10.9.9.9"),
        evtx(5145, ShareName="\\\\*\\ADMIN$", IpAddress="10.1.1.2", share_name="\\\\*\\ADMIN$", ip_address="10.1.1.2"),
    ]))
    kinds = {(e.src, e.kind) for e in edges}
    assert ("10.1.1.2", "logon_type_3") in kinds and ("10.1.1.2", "ntlm_network_logon") in kinds
    assert ("remote", "remote_service_install") in kinds and ("10.9.9.9", "failed_logon") in kinds and ("10.1.1.2", "admin_share_admin$") in kinds
    assert not any(e.kind == "logon_type_2" for e in edges)


def test_user_activity_and_provenance():
    summary = reconstruct(iter_stored([
        evtx(4624, TargetUserName="bob", target_user_name="bob"),
        ev("windows:shellbags", user="bob"),
        evtx(4624, TargetUserName="WS01$", target_user_name="WS01$"),
    ]))
    assert set(summary) == {"bob"} and set(summary["bob"]["categories"]) == {"logons", "folders_browsed"}
    nodes = build_prov(iter_stored([
        ev("chrome:history:file_downloaded", full_path="C:\\Users\\a\\Downloads\\x.exe", url="http://h/x.exe"),
        ev("fs:ntfs:usn_change", path="C:\\Users\\a\\Downloads\\x.exe", update_reason_flags="FILE_DELETE|CLOSE"),
    ]))
    n = nodes["\\users\\a\\downloads\\x.exe"]
    assert n.origin_kind == "browser_download" and set(n.events) == {"downloaded", "deleted"}


def test_ioc_matcher_and_loader():
    inds = load_indicators("sha256:" + "a" * 64 + "\n10.0.0.1\nevil.example\n# c\nregex:mimi\\w+\n")
    assert [i.ioc_type for i in inds] == ["sha256", "ipv4", "domain", "regex"]
    m = Matcher(inds)
    hits = list(m.sweep(iter_stored([
        ev("x", "hash " + "A" * 64 + " from 10.0.0.1"),
        ev("x", "visited http://sub.evil.example/path", url="http://sub.evil.example/"),
        ev("x", "ran MIMIKATZ now"),
        ev("x", "nothing"),
    ])))
    assert {(h.event_id, h.ioc_id.split(":")[0]) for h in hits} == {(0, "sha256"), (0, "ipv4"), (1, "domain"), (2, "regex")}
    assert sum(1 for h in hits if h.event_id == 1) == 2  # message and attrs.url
    assert infer_type("bad.exe") == "filename" and infer_type("C:\\x") == "path" and infer_type("a@b.c") == "email"
    with pytest.raises(ValueError):
        Indicator("regex", "(a+)+b")
    with pytest.raises(ValueError):
        Indicator("md5", "zz")
    assert load_indicators('[{"ioc_type":"domain","value":"X.Y."}]')[0].value == "x.y"


def test_timestomp_grading():
    from veritas.analytics.timestomp import TimestompRule

    def ntfs(ref, path, si_cr, fn_cr, si_m=None):
        return ev("fs:stat:ntfs", path, file_reference=ref, path=path, si_crtime_ns=si_cr, fn_crtime_ns=fn_cr, si_mtime_ns=si_m or si_cr)

    base = T0 + 5 * NS
    events = [
        ntfs("10-1", "/Users/bob/Desktop/payload.exe", T0, base + 77),           # isolated anomaly
        ntfs("11-1", "/Users/bob/Desktop/notes.txt", base, base + 1),            # normal sibling
        ntfs("12-1", "/Users/bob/Desktop/report.docx", base, base + 2),          # normal sibling
        ntfs("20-1", "/Program Files/App/a.dll", T0, base + 5),                  # installer tree
        ntfs("21-1", "/ntldr", T0, base + 9),                                   # setup root file
        ntfs("30-1", "/Users/bob/doc.pdf", base + 3, base + 3, si_m=T0),        # USN contradiction below
        ev("fs:ntfs:usn_change", "usn", ts=T0 + 100 * NS, file_reference="30-1", update_reason="DATA_OVERWRITE|CLOSE"),
    ]
    fs = list(TimestompRule().run(iter_stored(events)))
    titles = {f.title: f for f in fs}
    assert titles["Timestamps contradicted by USN journal: /Users/bob/doc.pdf"].severity == "high"
    assert titles["Possible timestomping: /Users/bob/Desktop/payload.exe"].severity == "medium"
    agg = next(f for f in fs if "installation or bulk-copied" in f.title)
    assert agg.severity == "low" and agg.details["total"] == 2
    assert not any("a.dll" in f.title or "ntldr" in f.title for f in fs if f.severity != "low")


def test_offensive_tool_prefix_matching():
    from veritas.analytics.execution import suspicious

    assert suspicious("cain25b45.exe") == ("T1040", "high")
    assert suspicious("ethereal-setup-0.10.6.exe")[0] == "T1040"
    assert suspicious("netstumblerinstaller_0_4_0.exe")[0] == "T1040"
    assert suspicious("lookatlan.exe")[0] == "T1046"
    assert suspicious("tor.exe")[0] == "T1090.003"
    for benign in ("torrent.exe", "johnny.exe", "explorer.exe", "wcescomm.exe", "abelssoft.exe"):
        assert suspicious(benign) is None, benign


def test_tool_family_groups_spellings():
    from veritas.analytics.execution import ExecutionCorrelationRule

    events = [
        ev("windows:prefetch:execution", executable="CAIN.EXE"),
        ev("windows:prefetch:execution", executable="CAIN25B45.EXE"),
        ev("windows:registry:userassist", value_name="UEME_RUNPATH:C:\\Documents and Settings\\x\\Start Menu\\Cain v2.5.lnk"),
        ev("windows:prefetch:execution", executable="NETSTUMBLERINSTALLER_0_4_0.EX"),
        ev("windows:registry:appcompatcache", path="C:\\Program Files\\Network Stumbler\\NetStumbler.exe"),
    ]
    fs = {f.title: f for f in ExecutionCorrelationRule().run(iter_stored(events))}
    assert set(fs) == {"Dual-use tool observed: cain", "Dual-use tool observed: netstumbler"}
    cain = fs["Dual-use tool observed: cain"]
    assert sorted(cain.details["names"]) == ["cain v2.5.lnk", "cain.exe", "cain25b45.exe"] and cain.severity == "high"
    assert "proven" in cain.description and len(cain.event_ids) == 3
