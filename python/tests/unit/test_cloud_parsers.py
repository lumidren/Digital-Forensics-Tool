"""Concrete-value tests for the cloud audit-log normalizers."""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from veritas.cloud import aws_cloudtrail, aws_elb, aws_s3, azure, gws, m365, registry
from veritas.cloud.base import ParserError
from veritas.timeline.schema import Desc

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "cloud"


class Prov:
    def __init__(self, sha="f" * 64, path="case/evidence.log", host=None, user=None):
        self.evidence_sha256, self.evidence_path, self.host, self.user = sha, path, host, user


# --------------------------------------------------------------------------- AWS ELB (corpus)


def test_elb_corpus_counts_and_values(corpus):
    r = aws_elb.parse(corpus / "plaso" / "aws_elb_access.log")
    assert r.warnings == []
    assert len(r) == 26
    by_kind = {}
    for e in r.events:
        by_kind.setdefault((e.attrs["log_format"], e.timestamp_desc), 0)
        by_kind[(e.attrs["log_format"], e.timestamp_desc)] += 1
    assert by_kind == {("alb", Desc.END): 10, ("alb", Desc.START): 10, ("classic", Desc.END): 4, ("nlb", Desc.END): 2}
    ev = r.sorted()
    assert ev[0].timestamp == 1578761719624000000 and ev[0].timestamp_desc == Desc.START
    assert ev[-1].timestamp == 1671505180000000000
    assert ev[-1].attrs["tls_cipher"] == "ECDHE-RSA-AES128-SHA"
    first = r.events[0]
    assert first.data_type == "aws:elb:access"
    assert first.attrs["raw_time"] == "2020-01-11T16:55:20.356586Z"
    assert first.timestamp == 1578761720356586000
    assert first.attrs["client_ip"] == "192.168.1.10" and first.attrs["client_port"] == 44325
    assert first.attrs["elb_status_code"] == 200 and first.attrs["sent_bytes"] == 107999
    assert first.attrs["request_url"] == "https://www.domain.name:443/"
    assert first.host == "app/production-web/jf29fj2198ejf922"
    classic = [e for e in r.events if e.attrs["log_format"] == "classic"]
    assert [e.attrs.get("received_bytes") for e in classic] == [0, 0, 82, -1]
    assert "http_method" not in classic[2].attrs and "elb_status_code" not in classic[2].attrs


def test_elb_bad_lines_and_empty():
    good = b'2021-05-13T23:39:43.945958Z my-lb 1.2.3.4:1 10.0.0.1:80 0.1 0.1 0.1 200 200 0 29 "GET http://x/ HTTP/1.1" "curl" - -\n'
    r = aws_elb.parse(good + b"garbage line here\n" + b"http 2020-13-45T99:99:99Z app/x 1.1.1.1:1 2.2.2.2:2\n")
    assert len(r) == 1 and r.warning_count == 2
    with pytest.raises(ParserError):
        aws_elb.parse(b"\n\n")
    with pytest.raises(ParserError):
        aws_elb.parse(b"nothing that matches\n")
    bad_time = b'http 2020-01-11T16:55:20.356586Zx app/x 1.1.1.1:1 2.2.2.2:2 0 0 0 200 200 1 1 "GET / HTTP/1.1" "ua" - - arn "t" "d" "c" 1 notatime "f"\n'
    r = aws_elb.parse(bad_time)
    assert r.events[0].timestamp is None and r.events[0].timestamp_desc == Desc.NOT_A_TIME
    assert any("request creation" in w for w in r.warnings)


# --------------------------------------------------------------------------- CloudTrail


def test_cloudtrail_records():
    r = aws_cloudtrail.parse(FIX / "cloudtrail.json")
    assert len(r) == 3 and r.warnings == []
    login, denied, s3 = r.events
    assert login.data_type == "aws:cloudtrail:entry"
    assert login.timestamp == 1677664800000000000 and login.attrs["raw_time"] == "2023-03-01T10:00:00Z"
    assert login.user == "arn:aws:iam::123456789012:user/alice"
    assert login.host is None and login.attrs["source_ip_address"] == "203.0.113.10"
    assert login.attrs["response_elements"] == {"ConsoleLogin": "Success"}
    assert login.attrs["event_name"] == "ConsoleLogin" and login.attrs["read_only"] is False
    assert denied.attrs["error_code"] == "AccessDenied"
    assert denied.attrs["identity_type"] == "AssumedRole"
    assert denied.attrs["identity_access_key_id"] == "ASIAEXAMPLEKEY"
    assert denied.attrs["session_issuer_user_name"] == "Admin"
    assert denied.attrs["session_mfa_authenticated"] is False
    assert "error=AccessDenied" in denied.message
    assert s3.timestamp == 1677666030500000000
    assert s3.attrs["request_parameters_truncated"] is True
    assert isinstance(s3.attrs["request_parameters"], str) and len(s3.attrs["request_parameters"]) == 4099
    assert [x["ARN"] for x in s3.attrs["resources"]] == [
        "arn:aws:s3:::finance-reports/q1/report.pdf", "arn:aws:s3:::finance-reports"]
    assert s3.attrs["read_only"] is True


def test_cloudtrail_jsonl_gzip_matches_json():
    a = aws_cloudtrail.parse(FIX / "cloudtrail.json", evidence_path="x")
    b = aws_cloudtrail.parse(FIX / "cloudtrail.jsonl.gz", evidence_path="x")
    assert a.to_jsonl() == b.to_jsonl()


def test_cloudtrail_partial_and_errors():
    data = json.dumps({"Records": [{"eventName": "X", "eventSource": "s", "eventTime": "bad"}, {"foo": 1}]})
    r = aws_cloudtrail.parse(data.encode())
    assert len(r) == 1 and r.warning_count == 2 and r.events[0].timestamp is None
    with pytest.raises(ParserError):
        aws_cloudtrail.parse(b'{"Records": [{"foo": 1}]}')
    with pytest.raises(ParserError):
        aws_cloudtrail.parse(b"")
    with pytest.raises(ParserError):
        aws_cloudtrail.parse(b"[1,2]")
    with pytest.raises(ParserError):
        aws_cloudtrail.parse(b"42")
    with pytest.raises(ParserError):
        aws_cloudtrail.parse(b"\x1f\x8bnotgzip")
    with pytest.raises(ParserError):
        aws_cloudtrail.parse(Path("does/not/exist.json"))
    with pytest.raises(ParserError):
        aws_cloudtrail.parse(12345)


# --------------------------------------------------------------------------- S3


def test_s3_access_log():
    r = aws_s3.parse(FIX / "s3_access.log")
    assert len(r) == 2 and r.warnings == ["line 3: not an S3 access log record"]
    a, b = r.events
    assert a.data_type == "aws:s3:access_log"
    assert a.timestamp == 1549411238000000000 and a.attrs["raw_time"] == "06/Feb/2019:00:00:38 +0000"
    assert a.attrs["operation"] == "REST.GET.VERSIONING" and a.attrs["http_status"] == 200
    assert a.attrs["bytes_sent"] == 113 and a.attrs["remote_ip"] == "192.0.2.3"
    assert a.attrs["request_id"] == "3E57427F3EXAMPLE" and a.attrs["signature_version"] == "SigV4"
    assert "key" not in a.attrs and a.attrs["user_agent"] == "S3Console/0.4"
    assert b.user == "arn:aws:iam::123456789012:user/alice"
    assert b.attrs["key"] == "photos/cat.jpg" and b.attrs["object_size"] == 2048
    assert b.attrs["http_method"] == "PUT" and b.attrs["request_path"] == "/awsexamplebucket1/photos/cat.jpg"
    assert b.attrs["referrer"] == "https://console.example/"
    assert b.timezone == "UTC"


def test_s3_errors():
    with pytest.raises(ParserError):
        aws_s3.parse(b"")
    with pytest.raises(ParserError):
        aws_s3.parse(b"only junk\n")
    short = b"owner bucket [06/Feb/2019:00:00:38 +0000] 1.2.3.4 req id op\n"
    with pytest.raises(ParserError):
        aws_s3.parse(short)
    extra = (b'o b [31/Xyz/2019:00:00:38 +0000] 1.2.3.4 r i OP k "GET / HTTP/1.1" 200 - 1 2 3 4 "-" "ua" - h s c a h t ap acl x1 x2\n')
    r = aws_s3.parse(extra)
    assert r.events[0].timestamp is None and r.events[0].attrs["extra_fields"] == ["x1", "x2"]


# --------------------------------------------------------------------------- Azure


def test_azure_activity_log():
    r = azure.parse_activity_log(FIX / "azure_activity.json")
    assert len(r) == 2 and r.warnings == []
    a, b = r.events
    assert a.data_type == "azure:activity_log:entry"
    assert a.timestamp == 1677661200123456000 and a.attrs["raw_time"] == "2023-03-01T09:00:00.1234567Z"
    assert a.user == "ops@contoso.com" and a.attrs["caller_ip_address"] == "203.0.113.50"
    assert a.attrs["duration_ms"] == 1532 and a.attrs["result_type"] == "Success"
    assert a.attrs["identity_claims"]["upn"] == "ops@contoso.com"
    assert a.attrs["identity_claims"]["objectidentifier"] == "aaaa-bbbb"
    assert a.attrs["authorization_action"] == "Microsoft.Compute/virtualMachines/write"
    assert a.attrs["properties"] == {"serviceRequestId": "abc-123", "statusCode": "Created"}
    assert b.timestamp == 1677663000000000000
    assert b.attrs["operation_name"] == "Microsoft.Authorization/roleAssignments/write"
    assert b.attrs["result_type"] == "Failed" and b.attrs["result_signature"] == "Forbidden"
    assert b.user == "intruder@contoso.com"


def test_entra_audit():
    r = azure.parse_entra_audit(FIX / "entra_audit.json")
    assert len(r) == 2
    a, b = r.events
    assert a.data_type == "azure:entra:audit" and a.timestamp == 1677668400123456000
    assert a.user == "admin@contoso.com" and a.attrs["initiated_by_ip_address"] == "198.51.100.7"
    assert a.attrs["activity_display_name"] == "Add user" and a.attrs["result"] == "success"
    t = a.attrs["target_resources"][0]
    assert t["user_principal_name"] == "bob@contoso.com"
    assert t["modified_properties"] == [{"name": "AccountEnabled", "new": "[true]", "old": "[]"}]
    assert a.attrs["additional_details"] == {"UserType": "Member"}
    assert "on bob@contoso.com" in a.message
    assert b.user == "Microsoft Graph" and b.attrs["result"] == "failure"
    assert b.attrs["initiated_by_app_id"] == "00000003-0000-0000-c000-000000000000"


def test_entra_signin():
    r = azure.parse_entra_signin(FIX / "entra_signin.json")
    assert len(r) == 2
    ok, bad = r.events
    assert ok.data_type == "azure:entra:signin" and ok.timestamp_desc == Desc.LAST_LOGIN
    assert ok.timestamp == 1677657600000000000 and ok.user == "alice@contoso.com"
    assert ok.attrs["success"] is True and ok.attrs["status_error_code"] == 0
    assert ok.attrs["location_latitude"] == "47.606209" and ok.attrs["location_longitude"] == "-122.332071"
    assert ok.attrs["device_display_name"] == "ALICE-PC" and ok.attrs["conditional_access_status"] == "success"
    assert ok.attrs["applied_conditional_access_policies"] == [{"display_name": "Require MFA", "result": "success"}]
    assert bad.attrs["status_error_code"] == 50126 and bad.attrs["success"] is False
    assert bad.message.startswith("Sign-in failure 50126 for alice@contoso.com to Azure Portal")


def test_azure_appgw_corpus(corpus):
    r = azure.parse_appgw(corpus / "plaso" / "azure_application_gateway_access.json")
    assert len(r) == 2
    a, b = r.events
    assert a.data_type == "azure:appgw:access" and a.timestamp == 1634249831000000000
    assert a.attrs["client_ip"] == "185.42.129.24" and a.attrs["http_status"] == 200
    assert a.attrs["time_taken"] == "0.034" and a.attrs["sent_bytes"] == 466
    assert a.attrs["raw_time"] == "2021-10-14T22:17:11+00:00" and a.host == "20.110.30.194"
    assert b.attrs["http_status"] == 400 and b.timestamp == 1634249832000000000


def test_azure_mixed_and_errors():
    mixed = (FIX / "entra_signin.json").read_bytes() + (FIX / "entra_audit.json").read_bytes()
    r = azure.parse(mixed)
    assert sorted({e.data_type for e in r.events}) == ["azure:entra:audit", "azure:entra:signin"]
    r = azure.parse_entra_audit(mixed)
    assert len(r) == 2 and r.warning_count == 2
    with pytest.raises(ParserError):
        azure.parse(b'[{"x": 1}]')
    bad_time = b'{"activityDateTime": "nope", "activityDisplayName": "x", "initiatedBy": 5, "targetResources": [1]}'
    r = azure.parse_entra_audit(bad_time)
    assert r.events[0].timestamp is None and r.warning_count == 1
    r = azure.parse_entra_signin(b'{"createdDateTime": "bad", "userPrincipalName": "u"}')
    assert r.events[0].attrs.get("success") is None and "unknown" in r.events[0].message
    r = azure.parse_activity_log(b'{"time": "bad", "operationName": "op", "category": "c"}')
    assert r.events[0].timestamp is None
    r = azure.parse_appgw(b'{"operationName": "ApplicationGatewayAccess", "timeStamp": "x"}')
    assert r.events[0].timestamp is None


# --------------------------------------------------------------------------- Google Workspace


def test_gws_activities():
    r = gws.parse(FIX / "gws_activities.json")
    assert len(r) == 3 and r.warnings == []
    login, download, acl = r.events
    assert login.data_type == "gws:audit:entry"
    assert login.timestamp == 1677672000000000000 and login.user == "alice@example.com"
    assert login.attrs["application_name"] == "login" and login.attrs["event_name"] == "login_success"
    assert login.attrs["param_login_type"] == "google_password" and login.attrs["param_is_suspicious"] is False
    assert login.attrs["ip_address"] == "203.0.113.20"
    assert download.attrs["param_doc_title"] == "Q1 plan" and download.attrs["param_billable"] is True
    assert acl.offset == 2 and acl.attrs["event_index"] == 1
    assert acl.attrs["param_count"] == 3 and acl.attrs["param_ids"] == [1, 2]
    assert acl.attrs["param_new_value"] == ["can_view"]
    assert acl.attrs["param_nested"] == {"k": "v"} and acl.attrs["param_nested_list"] == [{"a": 7}]


def test_gws_edge_cases():
    rec = {"id": {"time": "bad", "applicationName": "admin"}, "events": []}
    r = gws.parse(json.dumps([rec, {"other": 1}]).encode())
    assert len(r) == 1 and r.events[0].timestamp is None and r.warning_count == 2
    rec2 = {"id": {"time": "2023-01-01T00:00:00Z", "applicationName": "a"}, "events": [{"name": "n", "parameters": [{"name": "p"}]}]}
    r = gws.parse(json.dumps(rec2).encode())
    assert "param_p" not in r.events[0].attrs
    with pytest.raises(ParserError):
        gws.parse(b'{"items": []}')


# --------------------------------------------------------------------------- Microsoft 365


def test_m365_csv():
    r = m365.parse(FIX / "m365_ual.csv")
    assert len(r) == 4 and r.warnings == ["row 4: AuditData is not a JSON object"]
    login, mail, sp, aad = r.events
    assert login.data_type == "m365:ual:entry" and login.timestamp_desc == Desc.LAST_LOGIN
    assert login.timestamp == 1677657598000000000 and login.timezone == "UTC"
    assert login.attrs["raw_time"] == "2023-03-01T07:59:58"
    assert login.attrs["record_type"] == 15 and login.attrs["record_type_name"] == "AzureActiveDirectoryStsLogon"
    assert login.attrs["login_success"] is True and login.attrs["csv_record_id"] == "M-1"
    assert login.attrs["extended_properties"] == {"RequestType": "Login:login", "UserAgent": "Mozilla/5.0"}
    assert login.attrs["actor"] == ["u-alice", "alice@contoso.com"]
    assert mail.attrs["record_type_name"] == "ExchangeItemAggregated"
    assert mail.attrs["mailbox_owner_upn"] == "alice@contoso.com" and mail.attrs["folders"] == ["\\Inbox"]
    assert mail.attrs["item_subjects"] == ["Wire transfer", "Invoice"]
    assert mail.attrs["client_ip"] == "203.0.113.10"
    assert sp.attrs["source_file_name"] == "budget.xlsx" and sp.attrs["site_url"] == "https://contoso.sharepoint.com/sites/fin/"
    assert sp.attrs["record_type_name"] == "SharePointFileOperation"
    assert aad.attrs["modified_properties"] == [{"name": "AccountEnabled", "new": "[false]", "old": "[true]"}]
    assert aad.attrs["target"] == ["User_u-bob"] and aad.user == "admin@contoso.com"


def test_m365_json():
    r = m365.parse(FIX / "m365_ual.json")
    assert len(r) == 3
    failed, rule, other = r.events
    assert failed.attrs["login_success"] is False and failed.attrs["logon_error"] == "InvalidUserNameOrPassword"
    assert rule.attrs["parameters"] == {"ForwardTo": "eve@evil.example", "Name": "fwd"}
    assert rule.attrs["item_subject"] == "rule" and rule.attrs["item_parent_folder"] == "\\Inbox"
    assert rule.attrs["record_type_name"] == "ExchangeAdmin"
    assert other.attrs["record_type_name"] == "Unknown(999)"


def test_m365_wrapped_and_dates():
    wrapped = [
        {"CreationDate": "3/1/2023 9:05:07 PM", "Operations": "X", "UserIds": "u@x", "AuditData": json.dumps({"Operation": "X"})},
        {"CreationDate": "2023-03-01", "AuditData": {"CreationTime": "2023-03-01T00:00:00Z", "Operation": "Y", "RecordType": "Custom"}},
        {"AuditData": "{bad"},
    ]
    r = m365.parse(json.dumps(wrapped).encode())
    assert len(r) == 2 and r.warning_count == 1
    assert r.events[0].timestamp == 1677704707000000000 and r.events[0].user == "u@x"
    assert r.events[1].attrs["record_type_name"] == "Custom"
    assert m365.record_type_name(None) is None
    r = azure.parse_entra_signin(b'{"createdDateTime": "2023-01-01T00:00:00Z", "userPrincipalName": "u", '
                                 b'"location": {"geoCoordinates": {"latitude": "x", "longitude": true}}}')
    assert "location_latitude" not in r.events[0].attrs
    assert m365._us_date("12/31/2023 12:00 AM") == "2023-12-31T00:00:00+00:00"
    assert m365._us_date("nope") is None
    with pytest.raises(ParserError):
        m365.parse(b"RecordId,AuditData\r\n1,nope\r\n")


# --------------------------------------------------------------------------- registry


@pytest.mark.parametrize("name,expected", [
    ("cloudtrail.json", "aws_cloudtrail"), ("cloudtrail.jsonl.gz", "aws_cloudtrail"),
    ("s3_access.log", "aws_s3_access"), ("azure_activity.json", "azure_activity"),
    ("entra_audit.json", "azure_entra_audit"), ("entra_signin.json", "azure_entra_signin"),
    ("gws_activities.json", "gws_reports"), ("m365_ual.csv", "m365_ual"), ("m365_ual.json", "m365_ual"),
])
def test_registry_select_fixtures(name, expected):
    path = FIX / name
    parser = registry.select(path, path.read_bytes()[:4096])
    assert parser is not None and parser.name == expected
    events = list(registry.parse_auto(path, Prov()))
    assert events and all(e.data_type in parser.data_types for e in events)
    assert all(e.evidence_sha256 == "f" * 64 and e.evidence_path == "case/evidence.log" for e in events)


def test_registry_corpus(corpus):
    assert registry.select("x", (corpus / "plaso" / "aws_elb_access.log").read_bytes()).name == "aws_elb_access"
    assert registry.select(None, (corpus / "plaso" / "azure_application_gateway_access.json").read_bytes()).name == "azure_appgw"
    events = list(registry.parse_auto(corpus / "plaso" / "aws_elb_access.log", Prov(user="examiner")))
    assert len(events) == 26 and events == sorted(events, key=lambda e: e.sort_key())
    assert all(e.user == "examiner" for e in events)


def test_registry_negative():
    assert registry.select("x", b"") is None
    assert registry.select("x", "text") is None
    assert registry.select("x", b"   \n") is None
    assert registry.select("x", b"\x1f\x8b\x00garbage") is None
    assert registry.select("x", b'{"unrelated": 1}') is None
    assert registry.select("x", b"hello world\n") is None
    assert registry.select("x", b'CreationDate,UserIds,Operations,AuditData\r\n').name == "m365_ual"
    assert registry.select("x", gzip.compress(b'{"Records":[{"eventName":"a","eventSource":"b"}]}', mtime=0)).name == "aws_cloudtrail"
    assert registry.select("x", b'{"time":"t","operationName":"o"}').name == "azure_activity"
    assert registry.select("x", b'[{"a\\"b": 1, "CreationTime": "t", "Operation": "o"}]').name == "m365_ual"
    assert registry.select("x", b'{"AuditData": "x", "CreationDate": "y"}').name == "m365_ual"
    with pytest.raises(ParserError):
        registry.parse_auto(b"plain text that matches nothing")
    assert set(registry.PARSERS) == {
        "aws_cloudtrail", "aws_s3_access", "aws_elb_access", "azure_activity", "azure_entra_audit",
        "azure_entra_signin", "azure_appgw", "gws_reports", "m365_ual"}
