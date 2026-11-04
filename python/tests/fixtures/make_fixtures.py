"""Deterministically (re)generate the synthetic cloud and mobile fixtures.

Run from the repository root::

    .venv/Scripts/python python/tests/fixtures/make_fixtures.py

The generated files are committed so the tests never need to regenerate them. Every value is
fixed (no wall clock, no randomness): rerunning produces identical bytes for the text, JSON,
plist, gzip and tar outputs. SQLite files are logically identical (page layout may vary between
SQLite versions, which does not affect parsing).

Corpus files reused: testdata/corpus/plaso/android/{mmssms.db,contacts2.db,downloads.db}.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import plistlib
import re
import shutil
import sqlite3
import sys
import tarfile
import zlib
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CORPUS = REPO / "testdata" / "corpus" / "plaso"
CLOUD = HERE / "cloud"
MOBILE = HERE / "mobile"
COCOA = 978_307_200



_TOKEN = re.compile(rb"xox[abposr]-[A-Za-z0-9-]{10,}")


def _scrub_tokens(path: Path) -> None:
    """The public corpus downloads.db embeds a Slack-token-shaped string; replace it with a
    same-length placeholder (SQLite stays valid) so committed fixtures never carry secrets."""
    data = path.read_bytes()
    new = _TOKEN.sub(lambda m: (b"REDACTED-TOKEN-" + b"0" * len(m.group(0)))[: len(m.group(0))], data)
    if new != data:
        path.write_bytes(new)

def _reset(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def _sqlite(path: Path, script: str, rows: dict[str, list[tuple]]) -> None:
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(script)
    for table, values in rows.items():
        if values:
            marks = ",".join("?" * len(values[0]))
            conn.executemany(f"INSERT INTO {table} VALUES ({marks})", values)
    conn.commit()
    conn.execute("VACUUM")
    conn.close()


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)


def _json(obj) -> str:
    return json.dumps(obj, indent=1, sort_keys=False, ensure_ascii=False) + "\n"


def _gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, filename="") as gz:
        gz.write(data)
    return buf.getvalue()


# =========================================================================== cloud

CLOUDTRAIL_RECORDS = [
    {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE1", "arn": "arn:aws:iam::123456789012:user/alice",
                         "accountId": "123456789012", "userName": "alice"},
        "eventTime": "2023-03-01T10:00:00Z", "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.10",
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "Yes"}, "eventID": "11111111-1111-1111-1111-111111111111",
        "readOnly": False, "eventType": "AwsConsoleSignIn", "managementEvent": True,
        "recipientAccountId": "123456789012", "eventCategory": "Management",
    },
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "AssumedRole", "principalId": "AROAEXAMPLE2:bob", "arn": "arn:aws:sts::123456789012:assumed-role/Admin/bob",
            "accountId": "123456789012", "accessKeyId": "ASIAEXAMPLEKEY",
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "principalId": "AROAEXAMPLE2", "arn": "arn:aws:iam::123456789012:role/Admin",
                                  "accountId": "123456789012", "userName": "Admin"},
                "attributes": {"creationDate": "2023-03-01T10:05:00Z", "mfaAuthenticated": "false"},
            },
        },
        "eventTime": "2023-03-01T10:10:00Z", "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1", "sourceIPAddress": "198.51.100.23", "userAgent": "aws-cli/2.9.0",
        "errorCode": "AccessDenied", "errorMessage": "User is not authorized to perform iam:CreateAccessKey",
        "requestParameters": {"userName": "carol"}, "responseElements": None,
        "eventID": "22222222-2222-2222-2222-222222222222", "readOnly": False, "eventType": "AwsApiCall",
        "managementEvent": True, "recipientAccountId": "123456789012",
    },
    {
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "principalId": "AIDAEXAMPLE1", "arn": "arn:aws:iam::123456789012:user/alice",
                         "accountId": "123456789012", "accessKeyId": "AKIAEXAMPLEKEY", "userName": "alice"},
        "eventTime": "2023-03-01T10:20:30.500Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "awsRegion": "us-west-2", "sourceIPAddress": "203.0.113.10", "userAgent": "[aws-sdk-go/1.44]",
        "requestParameters": {"bucketName": "finance-reports", "key": "q1/" + "x" * 5000 + ".pdf"},
        "responseElements": None, "eventID": "33333333-3333-3333-3333-333333333333", "readOnly": True,
        "resources": [{"type": "AWS::S3::Object", "ARN": "arn:aws:s3:::finance-reports/q1/report.pdf"},
                      {"accountId": "123456789012", "type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::finance-reports"}],
        "eventType": "AwsApiCall", "managementEvent": False, "recipientAccountId": "123456789012", "eventCategory": "Data",
    },
]

S3_LINES = [
    '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket1 [06/Feb/2019:00:00:38 +0000] '
    '192.0.2.3 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be 3E57427F3EXAMPLE REST.GET.VERSIONING - '
    '"GET /awsexamplebucket1?versioning HTTP/1.1" 200 - 113 - 7 - "-" "S3Console/0.4" - '
    's9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 '
    'AuthHeader awsexamplebucket1.s3.us-west-1.amazonaws.com TLSV1.2 - -',
    '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be awsexamplebucket1 [06/Feb/2019:00:01:57 +0000] '
    '198.51.100.9 arn:aws:iam::123456789012:user/alice A1206F460EXAMPLE REST.PUT.OBJECT photos/cat.jpg '
    '"PUT /awsexamplebucket1/photos/cat.jpg HTTP/1.1" 200 - - 2048 51 20 "https://console.example/" "aws-cli/2.9.0" - '
    'BNaBsXZQQDbssi6xMBdBU2sLt+Yf5kZDmeBUP35sFoKa3sLLeMC78iwEIWxs99CRUrbS4n11234= SigV4 ECDHE-RSA-AES128-SHA '
    'AuthHeader awsexamplebucket1.s3.us-west-1.amazonaws.com TLSV1.2',
    "this line is not an access log record",
]

AZURE_ACTIVITY = {"value": [
    {
        "time": "2023-03-01T09:00:00.1234567Z",
        "resourceId": "/SUBSCRIPTIONS/0000/RESOURCEGROUPS/RG1/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM1",
        "operationName": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "category": "Administrative",
        "resultType": "Success", "resultSignature": "Succeeded.Created", "durationMs": "1532",
        "callerIpAddress": "203.0.113.50", "correlationId": "c0ffee00-0000-0000-0000-000000000001",
        "level": "Information", "location": "global",
        "identity": {
            "authorization": {"scope": "/subscriptions/0000/resourceGroups/RG1", "action": "Microsoft.Compute/virtualMachines/write"},
            "claims": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "ops@contoso.com",
                       "ipaddr": "203.0.113.50", "appid": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
                       "http://schemas.microsoft.com/identity/claims/objectidentifier": "aaaa-bbbb"},
        },
        "properties": {"statusCode": "Created", "serviceRequestId": "abc-123"},
    },
    {
        "eventTimestamp": "2023-03-01T09:30:00Z",
        "operationName": {"value": "Microsoft.Authorization/roleAssignments/write", "localizedValue": "Create role assignment"},
        "category": {"value": "Administrative", "localizedValue": "Administrative"},
        "status": {"value": "Failed", "localizedValue": "Failed"}, "subStatus": {"value": "Forbidden"},
        "caller": "intruder@contoso.com", "resourceId": "/subscriptions/0000",
        "properties": {"requestbody": "{\"properties\":{\"roleDefinitionId\":\"Owner\"}}"},
    },
]}

ENTRA_AUDIT = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/directoryAudits", "value": [
    {
        "id": "Directory_AAAA", "category": "UserManagement", "correlationId": "corr-1", "result": "success",
        "resultReason": "", "activityDisplayName": "Add user", "activityDateTime": "2023-03-01T11:00:00.1234567Z",
        "loggedByService": "Core Directory", "operationType": "Add",
        "initiatedBy": {"app": None, "user": {"id": "u-admin", "displayName": "Admin", "userPrincipalName": "admin@contoso.com",
                                               "ipAddress": "198.51.100.7"}},
        "targetResources": [{"id": "u-bob", "displayName": "Bob", "type": "User", "userPrincipalName": "bob@contoso.com",
                             "modifiedProperties": [{"displayName": "AccountEnabled", "oldValue": "[]", "newValue": "[true]"}]}],
        "additionalDetails": [{"key": "UserType", "value": "Member"}],
    },
    {
        "id": "Directory_BBBB", "category": "ApplicationManagement", "correlationId": "corr-2", "result": "failure",
        "resultReason": "Insufficient privileges", "activityDisplayName": "Update application",
        "activityDateTime": "2023-03-01T11:05:00Z", "loggedByService": "Core Directory", "operationType": "Update",
        "initiatedBy": {"user": None, "app": {"appId": "00000003-0000-0000-c000-000000000000", "displayName": "Microsoft Graph",
                                              "servicePrincipalId": "sp-1", "servicePrincipalName": None}},
        "targetResources": [{"id": "app-1", "displayName": "Payroll", "type": "Application", "modifiedProperties": []}],
        "additionalDetails": [],
    },
]}

ENTRA_SIGNIN = [
    {
        "id": "signin-1", "createdDateTime": "2023-03-01T08:00:00Z", "userDisplayName": "Alice",
        "userPrincipalName": "alice@contoso.com", "userId": "u-alice", "appId": "app-o365",
        "appDisplayName": "Office 365 Exchange Online", "ipAddress": "203.0.113.10", "clientAppUsed": "Browser",
        "correlationId": "c-1", "conditionalAccessStatus": "success", "isInteractive": True,
        "riskLevelDuringSignIn": "none", "riskState": "none", "resourceDisplayName": "Office 365 Exchange Online",
        "status": {"errorCode": 0, "failureReason": None, "additionalDetails": None},
        "deviceDetail": {"deviceId": "dev-1", "displayName": "ALICE-PC", "operatingSystem": "Windows 10",
                         "browser": "Edge 110.0", "isCompliant": True, "isManaged": True, "trustType": "Azure AD joined"},
        "location": {"city": "Seattle", "state": "Washington", "countryOrRegion": "US",
                     "geoCoordinates": {"altitude": None, "latitude": 47.6062095, "longitude": -122.3320708}},
        "appliedConditionalAccessPolicies": [{"id": "p1", "displayName": "Require MFA", "result": "success"}],
    },
    {
        "id": "signin-2", "createdDateTime": "2023-03-01T08:05:10Z", "userDisplayName": "Alice",
        "userPrincipalName": "alice@contoso.com", "userId": "u-alice", "appDisplayName": "Azure Portal",
        "ipAddress": "192.0.2.66", "clientAppUsed": "Browser", "conditionalAccessStatus": "notApplied",
        "isInteractive": True, "status": {"errorCode": 50126, "failureReason": "Invalid username or password."},
        "deviceDetail": {"deviceId": "", "operatingSystem": "Linux", "browser": "Firefox 109.0"},
        "location": {"city": "Unknown", "countryOrRegion": "RU", "geoCoordinates": {}},
    },
]

GWS = {"kind": "admin#reports#activities", "items": [
    {
        "kind": "admin#reports#activity",
        "id": {"time": "2023-03-01T12:00:00.000Z", "uniqueQualifier": "-1234567890", "applicationName": "login", "customerId": "C01"},
        "etag": "\"e1\"", "actor": {"callerType": "USER", "email": "alice@example.com", "profileId": "1001"},
        "ipAddress": "203.0.113.20",
        "events": [{"type": "login", "name": "login_success",
                    "parameters": [{"name": "login_type", "value": "google_password"},
                                   {"name": "is_suspicious", "boolValue": False}]}],
    },
    {
        "kind": "admin#reports#activity",
        "id": {"time": "2023-03-01T12:30:00.000Z", "uniqueQualifier": "42", "applicationName": "drive", "customerId": "C01"},
        "actor": {"email": "alice@example.com", "profileId": "1001"}, "ipAddress": "203.0.113.20",
        "events": [
            {"type": "access", "name": "download",
             "parameters": [{"name": "doc_title", "value": "Q1 plan"}, {"name": "doc_id", "value": "abc"},
                            {"name": "visibility", "value": "private"}, {"name": "billable", "boolValue": True}]},
            {"type": "acl_change", "name": "change_user_access",
             "parameters": [{"name": "target_user", "value": "eve@evil.example"},
                            {"name": "old_value", "multiValue": ["none"]}, {"name": "new_value", "multiValue": ["can_view"]},
                            {"name": "count", "intValue": "3"}, {"name": "ids", "multiIntValue": ["1", "2"]},
                            {"name": "nested", "messageValue": {"parameter": [{"name": "k", "value": "v"}]}},
                            {"name": "nested_list", "multiMessageValue": [{"parameter": [{"name": "a", "intValue": "7"}]}]}]},
        ],
    },
]}

M365_RECORDS = [
    {"CreationTime": "2023-03-01T07:59:58", "Id": "m-1", "Operation": "UserLoggedIn", "OrganizationId": "org",
     "RecordType": 15, "ResultStatus": "Success", "UserKey": "u-alice", "UserType": 0, "Version": 1,
     "Workload": "AzureActiveDirectory", "ClientIP": "203.0.113.10", "ObjectId": "00000002-0000-0ff1-ce00-000000000000",
     "UserId": "alice@contoso.com", "AzureActiveDirectoryEventType": 1,
     "ExtendedProperties": [{"Name": "UserAgent", "Value": "Mozilla/5.0"}, {"Name": "RequestType", "Value": "Login:login"}],
     "ApplicationId": "app-o365", "ErrorNumber": "0",
     "Actor": [{"ID": "u-alice", "Type": 0}, {"ID": "alice@contoso.com", "Type": 5}]},
    {"CreationTime": "2023-03-01T08:10:00", "Id": "m-2", "Operation": "MailItemsAccessed", "OrganizationId": "org",
     "RecordType": 50, "ResultStatus": "Succeeded", "UserId": "alice@contoso.com", "Workload": "Exchange",
     "ClientIPAddress": "203.0.113.10", "MailboxOwnerUPN": "alice@contoso.com", "LogonType": 0,
     "ClientInfoString": "Client=OWA", "Folders": [{"Path": "\\Inbox", "FolderItems": [{"Subject": "Wire transfer"}, {"Subject": "Invoice"}]}]},
    {"CreationTime": "2023-03-01T08:20:00", "Id": "m-3", "Operation": "FileDownloaded", "OrganizationId": "org",
     "RecordType": 6, "UserId": "alice@contoso.com", "Workload": "SharePoint", "ClientIP": "203.0.113.10",
     "ObjectId": "https://contoso.sharepoint.com/sites/fin/Shared Documents/budget.xlsx",
     "SiteUrl": "https://contoso.sharepoint.com/sites/fin/", "SourceFileName": "budget.xlsx", "SourceFileExtension": "xlsx",
     "SourceRelativeUrl": "Shared Documents", "ItemType": "File", "UserAgent": "Mozilla/5.0", "EventSource": "SharePoint"},
    {"CreationTime": "2023-03-01T08:30:00", "Id": "m-4", "Operation": "Update user.", "OrganizationId": "org",
     "RecordType": 8, "ResultStatus": "Success", "UserId": "admin@contoso.com", "Workload": "AzureActiveDirectory",
     "ObjectId": "bob@contoso.com", "ModifiedProperties": [{"Name": "AccountEnabled", "OldValue": "[true]", "NewValue": "[false]"}],
     "Target": [{"ID": "User_u-bob", "Type": 2}]},
]
M365_JSON = [
    {"CreationTime": "2023-03-02T01:00:00", "Id": "m-5", "Operation": "UserLoginFailed", "RecordType": 15,
     "ResultStatus": "Failed", "UserId": "alice@contoso.com", "Workload": "AzureActiveDirectory",
     "ClientIP": "192.0.2.66", "LogonError": "InvalidUserNameOrPassword"},
    {"CreationTime": "2023-03-02T01:05:00", "Id": "m-6", "Operation": "New-InboxRule", "RecordType": 1,
     "ResultStatus": "True", "UserId": "alice@contoso.com", "Workload": "Exchange", "ClientIP": "192.0.2.66:51234",
     "ObjectId": "alice\\fwd", "Parameters": [{"Name": "ForwardTo", "Value": "eve@evil.example"}, {"Name": "Name", "Value": "fwd"}],
     "Item": {"Id": "item-1", "Subject": "rule", "ParentFolder": {"Path": "\\Inbox"}}},
    {"CreationTime": "2023-03-02T01:06:00", "Id": "m-7", "Operation": "Custom", "RecordType": 999, "Workload": "Other"},
]


def make_cloud() -> None:
    _reset(CLOUD)
    _write(CLOUD / "cloudtrail.json", _json({"Records": CLOUDTRAIL_RECORDS}))
    jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in CLOUDTRAIL_RECORDS)
    _write(CLOUD / "cloudtrail.jsonl.gz", _gzip(jsonl.encode("utf-8")))
    _write(CLOUD / "s3_access.log", "\n".join(S3_LINES) + "\n")
    _write(CLOUD / "azure_activity.json", _json(AZURE_ACTIVITY))
    _write(CLOUD / "entra_audit.json", _json(ENTRA_AUDIT))
    _write(CLOUD / "entra_signin.json", _json(ENTRA_SIGNIN))
    _write(CLOUD / "gws_activities.json", _json(GWS))
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["RecordId", "CreationDate", "RecordType", "Operation", "UserId", "AuditData", "AssociatedAdminUnits"])
    for r in M365_RECORDS:
        w.writerow([r["Id"].upper(), r["CreationTime"] + ".0000000Z", r["RecordType"], r["Operation"], r["UserId"],
                    json.dumps(r, sort_keys=True), ""])
    w.writerow(["BAD", "3/1/2023 9:00:00 AM", "1", "Broken", "x@contoso.com", "not json", ""])
    _write(CLOUD / "m365_ual.csv", "﻿" + buf.getvalue())
    _write(CLOUD / "m365_ual.json", _json(M365_JSON))


# =========================================================================== iOS backup


def _cocoa(y, mo, d, h=0, mi=0, s=0.0) -> float:
    from calendar import timegm
    return timegm((y, mo, d, h, mi, 0, 0, 0, 0)) + s - COCOA


def make_sms_db(path: Path) -> None:
    base = int(_cocoa(2023, 3, 1, 10))  # 2023-03-01T10:00:00Z
    _sqlite(path, """
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, country TEXT, service TEXT);
        CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT, chat_identifier TEXT, service_name TEXT, display_name TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, handle_id INTEGER, service TEXT,
            date INTEGER, date_read INTEGER, date_delivered INTEGER, is_from_me INTEGER, is_read INTEGER,
            is_delivered INTEGER, cache_has_attachments INTEGER);
        CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER, message_date INTEGER);
    """, {
        "handle": [(1, "+15551230001", "us", "iMessage"), (2, "+15551230002", "us", "SMS")],
        "chat": [(1, "iMessage;-;+15551230001", "+15551230001", "iMessage", ""),
                 (2, "SMS;-;+15551230002", "+15551230002", "SMS", "Courier")],
        "message": [
            (1, "G-1", "Meet at the dock at 9", 1, "iMessage", base * 10**9, (base + 60) * 10**9, 0, 0, 1, 1, 0),
            (2, "G-2", "On my way", 1, "iMessage", (base + 120) * 10**9, 0, (base + 125) * 10**9, 1, 1, 1, 0),
            (3, "G-3", "Package delivered", 2, "SMS", base + 3600, 0, 0, 0, 0, 1, 1),
        ],
        "chat_message_join": [(1, 1, 0), (1, 2, 0), (2, 3, 0)],
    })


def make_call_history(path: Path) -> None:
    _sqlite(path, """
        CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER, ZANSWERED INTEGER,
            ZCALLTYPE INTEGER, ZORIGINATED INTEGER, ZDATE TIMESTAMP, ZDURATION FLOAT, ZADDRESS VARCHAR,
            ZSERVICE_PROVIDER VARCHAR, ZISO_COUNTRY_CODE VARCHAR, ZLOCATION VARCHAR, ZNAME VARCHAR, ZUNIQUE_ID VARCHAR);
    """, {"ZCALLRECORD": [
        (1, 2, 1, 1, 1, 1, _cocoa(2023, 3, 1, 12, 0, 0.5), 125.0, "+15551230001", "com.apple.Telephony", "us",
         "California", None, "CALL-1"),
        (2, 2, 1, 0, 8, 0, _cocoa(2023, 3, 1, 13), 0.0, "+15551230003", "com.apple.FaceTime", "us", None, None, "CALL-2"),
    ]})


def make_address_book(path: Path) -> None:
    _sqlite(path, """
        CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, Last TEXT, Middle TEXT, Organization TEXT,
            Note TEXT, CreationDate INTEGER, ModificationDate INTEGER);
        CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY, record_id INTEGER, property INTEGER, identifier INTEGER,
            label INTEGER, value TEXT);
    """, {
        "ABPerson": [(1, "Alice", "Archer", None, None, "met at conference", 600000000, 699300000),
                     (2, None, None, None, "Harbor Freight Co", None, None, None)],
        "ABMultiValue": [(1, 1, 3, 0, 1, "+15551230001"), (2, 1, 4, 1, 2, "alice@example.com"),
                         (3, 2, 3, 0, 1, "+15559998888"), (4, 1, 99, 0, 1, "ignored")],
    })


def make_photos(path: Path) -> None:
    _sqlite(path, """
        CREATE TABLE ZASSET (Z_PK INTEGER PRIMARY KEY, ZFILENAME VARCHAR, ZDIRECTORY VARCHAR, ZUUID VARCHAR,
            ZKIND INTEGER, ZWIDTH INTEGER, ZHEIGHT INTEGER, ZLATITUDE FLOAT, ZLONGITUDE FLOAT, ZDATECREATED TIMESTAMP,
            ZADDEDDATE TIMESTAMP, ZMODIFICATIONDATE TIMESTAMP, ZTRASHEDSTATE INTEGER, ZHIDDEN INTEGER, ZFAVORITE INTEGER);
    """, {"ZASSET": [
        (1, "IMG_0001.HEIC", "DCIM/100APPLE", "UUID-1", 0, 4032, 3024, 37.774929123, -122.419415789,
         _cocoa(2023, 3, 1, 9, 0, 0.25), _cocoa(2023, 3, 1, 9, 0, 5), _cocoa(2023, 3, 1, 9, 0, 10), 0, 0, 1),
        (2, "IMG_0002.MOV", "DCIM/100APPLE", "UUID-2", 1, 1920, 1080, -180.0, -180.0,
         _cocoa(2023, 3, 1, 11), _cocoa(2023, 3, 1, 11, 0, 1), None, 0, 0, 0),
    ]})


def _mbfile(relpath: str, size: int, mtime: int, mode: int) -> bytes:
    archive = {
        "$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": plistlib.UID(1)},
        "$objects": [
            "$null",
            {"$class": plistlib.UID(3), "LastModified": mtime, "Birth": mtime - 3600, "LastStatusChange": mtime,
             "Size": size, "Mode": mode, "InodeNumber": 1000 + size % 997, "UserID": 501, "GroupID": 501,
             "ProtectionClass": 3, "Flags": 0, "RelativePath": plistlib.UID(2)},
            relpath,
            {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]},
        ],
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY, sort_keys=True)


def make_ios_backup() -> None:
    root = MOBILE / "ios_backup"
    _reset(root)
    staging = MOBILE / "_staging"
    _reset(staging)
    make_sms_db(staging / "sms.db")
    make_call_history(staging / "CallHistory.storedata")
    make_address_book(staging / "AddressBook.sqlitedb")
    make_photos(staging / "Photos.sqlite")
    wifi = {"List of known networks": [
        {"SSID_STR": "CoffeeShop", "BSSID": "aa:bb:cc:dd:ee:ff", "SecurityMode": "WPA2 Personal",
         "lastJoined": datetime(2023, 2, 28, 8, 30), "lastAutoJoined": datetime(2023, 3, 1, 8, 0)},
        {"SSID_STR": "Airport_Free", "SecurityMode": "Open"},
    ]}
    (staging / "com.apple.wifi.plist").write_bytes(plistlib.dumps(wifi, fmt=plistlib.FMT_XML, sort_keys=True))
    (staging / "garbage.db").write_bytes(b"this is not sqlite" * 40)

    files = [
        ("HomeDomain", "Library/SMS/sms.db", staging / "sms.db"),
        ("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata", staging / "CallHistory.storedata"),
        ("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", staging / "AddressBook.sqlitedb"),
        ("CameraRollDomain", "Media/PhotoData/Photos.sqlite", staging / "Photos.sqlite"),
        ("WirelessDomain", "Library/Preferences/com.apple.wifi.plist", staging / "com.apple.wifi.plist"),
        # Present in the manifest but its content is corrupt: must become a warning.
        ("HomeDomain", "Library/Accounts/Accounts3.sqlite", staging / "garbage.db"),
        # Present in the manifest but missing on disk: must become a warning.
        ("HomeDomain", "Library/Notes/NoteStore.sqlite", None),
    ]
    rows = []
    mtime0 = 1677700000
    rows.append((hashlib.sha1(b"HomeDomain-Library/SMS").hexdigest(), "HomeDomain", "Library/SMS", 2,
                 _mbfile("Library/SMS", 0, mtime0 - 60, 0o40755)))
    for i, (domain, rel, src) in enumerate(files):
        fid = hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()
        data = src.read_bytes() if src is not None else b""
        if src is not None:
            _write(root / fid[:2] / fid, data)
        rows.append((fid, domain, rel, 1, _mbfile(rel, len(data), mtime0 + i * 60, 0o100644)))
    rows.append((hashlib.sha1(b"MediaDomain-Library/no-metadata").hexdigest(), "MediaDomain", "Library/no-metadata", 1, None))
    _sqlite(root / "Manifest.db", """
        CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);
        CREATE INDEX FilesDomainIdx ON Files(domain);
        CREATE TABLE Properties (key TEXT PRIMARY KEY, value BLOB);
    """, {"Files": rows})
    shutil.rmtree(staging)

    info = {
        "Device Name": "Examiner iPhone", "Display Name": "Examiner iPhone", "Product Type": "iPhone14,2",
        "Product Name": "iPhone 13 Pro", "Product Version": "16.3.1", "Build Version": "20D67",
        "Serial Number": "F2LXK0ABCDEF", "IMEI": "356789012345678", "Phone Number": "+1 (555) 123-9876",
        "Unique Identifier": "00008110001A2B3C4D5E6F70", "GUID": "0123456789ABCDEF0123456789ABCDEF",
        "Last Backup Date": datetime(2023, 3, 2, 9, 15, 0), "iTunes Version": "12.12.7", "Target Type": "Device",
    }
    status = {"Date": datetime(2023, 3, 2, 9, 15, 30), "IsFullBackup": False, "Version": "3.3",
              "SnapshotState": "finished", "BackupState": "new", "UUID": "STATUS-UUID-1"}
    manifest = {
        "IsEncrypted": False, "Version": "10.0", "Date": datetime(2023, 3, 2, 9, 0, 0), "WasPasscodeSet": True,
        "Lockdown": {"DeviceName": "Examiner iPhone", "ProductVersion": "16.3.1", "SerialNumber": "F2LXK0ABCDEF"},
        "Applications": {
            "net.whatsapp.WhatsApp": {"CFBundleIdentifier": "net.whatsapp.WhatsApp", "CFBundleVersion": "23.4.79",
                                      "ContainerContentClass": "Data/Application",
                                      "Path": "/var/containers/Bundle/Application/AAA/WhatsApp.app"},
            "com.example.chat": {"CFBundleVersion": "412", "ContainerContentClass": "Data/Application",
                                 "Path": "/var/containers/Bundle/Application/BBB/Chat.app"},
        },
    }
    for name, obj, fmt in (("Info.plist", info, plistlib.FMT_XML), ("Status.plist", status, plistlib.FMT_BINARY),
                           ("Manifest.plist", manifest, plistlib.FMT_BINARY)):
        (root / name).write_bytes(plistlib.dumps(obj, fmt=fmt, sort_keys=True))

    enc = MOBILE / "ios_backup_encrypted"
    _reset(enc)
    (enc / "Manifest.plist").write_bytes(plistlib.dumps(
        {"IsEncrypted": True, "Version": "10.0", "BackupKeyBag": b"\x00" * 32}, fmt=plistlib.FMT_BINARY, sort_keys=True))
    (enc / "Info.plist").write_bytes(plistlib.dumps({"Device Name": "Locked iPhone"}, fmt=plistlib.FMT_XML))


# =========================================================================== Android


def _tar_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1700000000
            ti.mode = 0o600
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _manifest(pkg: str) -> bytes:
    return f"1\n{pkg}\n29\n29\n\n0\n".encode()


def make_android_backup() -> None:
    out = MOBILE / "android"
    _reset(out)
    members = [
        ("apps/com.android.providers.telephony/_manifest", _manifest("com.android.providers.telephony")),
        ("apps/com.android.providers.telephony/db/mmssms.db", (CORPUS / "android" / "mmssms.db").read_bytes()),
        ("apps/com.android.providers.telephony/sp/prefs.xml", b"<?xml version='1.0'?><map/>\n"),
        ("apps/com.android.providers.contacts/_manifest", _manifest("com.android.providers.contacts")),
        ("apps/com.android.providers.contacts/db/contacts2.db", (CORPUS / "android" / "contacts2.db").read_bytes()),
    ]
    payload = _tar_bytes(members)
    _write(out / "backup.ab", b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(payload, 9))
    _write(out / "backup_uncompressed.ab", b"ANDROID BACKUP\n1\n0\nnone\n" + _tar_bytes(members[:2]))
    _write(out / "backup_encrypted.ab",
           b"ANDROID BACKUP\n5\n1\nAES-256\n" + b"0" * 64 + b"\n" + b"0" * 64 + b"\n10000\n" + b"\x00" * 64)


def make_android_pull() -> None:
    root = MOBILE / "android_pull"
    _reset(root)
    prov = root / "data" / "data"
    dl = _mk(prov / "com.android.providers.downloads" / "databases" / "downloads.db")
    shutil.copyfile(CORPUS / "android" / "downloads.db", dl)
    _scrub_tokens(dl)
    _sqlite(prov / "com.android.providers.contacts" / "databases" / "calllog.db", """
        CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER,
            new INTEGER, name TEXT, countryiso TEXT, geocoded_location TEXT, normalized_number TEXT, is_read INTEGER,
            subscription_component_name TEXT);
    """, {"calls": [
        (1, "+15551230001", 1677664800000, 60, 2, 0, "Alice", "US", "California", "+15551230001", 1,
         "com.android.phone/com.android.services.telephony.TelephonyConnectionService"),
        (2, "+15551230009", 1677668400000, 0, 3, 1, None, "US", None, None, 0, None),
    ]})
    _sqlite(prov / "com.android.providers.contacts" / "databases" / "contacts2.db", """
        CREATE TABLE mimetypes (_id INTEGER PRIMARY KEY, mimetype TEXT);
        CREATE TABLE raw_contacts (_id INTEGER PRIMARY KEY, account_name TEXT, account_type TEXT, display_name TEXT,
            deleted INTEGER, times_contacted INTEGER, last_time_contacted INTEGER, starred INTEGER);
        CREATE TABLE data (_id INTEGER PRIMARY KEY, raw_contact_id INTEGER, mimetype_id INTEGER, data1 TEXT,
            data2 TEXT, data3 TEXT);
    """, {
        "mimetypes": [(1, "vnd.android.cursor.item/name"), (5, "vnd.android.cursor.item/phone_v2"),
                      (6, "vnd.android.cursor.item/email_v2"), (7, "vnd.android.cursor.item/photo")],
        "raw_contacts": [(1, "user@gmail.com", "com.google", "Alice Archer", 0, 4, 1677664800000, 1),
                         (2, None, None, None, 0, 0, 0, 0)],
        "data": [(1, 1, 1, "Alice Archer", "Alice", "Archer"), (2, 1, 5, "+15551230001", "2", None),
                 (3, 1, 6, "alice@example.com", "1", None), (4, 2, 5, "+15551230002", "2", None),
                 (5, 2, 1, "Bob Builder", "Bob", "Builder"), (6, 2, 7, None, None, None),
                 (7, 99, 5, "+19999999999", "2", None)],
    })
    _sqlite(prov / "com.android.providers.telephony" / "databases" / "mmssms.db", """
        CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER, date_sent INTEGER,
            read INTEGER, status INTEGER, type INTEGER, subject TEXT, body TEXT, seen INTEGER);
        CREATE TABLE pdu (_id INTEGER PRIMARY KEY, thread_id INTEGER, date INTEGER, date_sent INTEGER, msg_box INTEGER,
            read INTEGER, m_id TEXT, sub TEXT, m_size INTEGER);
        CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, seq INTEGER, ct TEXT, name TEXT, cl TEXT, text TEXT,
            _data TEXT);
        CREATE TABLE addr (_id INTEGER PRIMARY KEY, msg_id INTEGER, address TEXT, type INTEGER);
    """, {
        "sms": [(1, 1, "+15551230001", 1677664900000, 1677664899000, 1, -1, 1, None, "See you at 9", 1),
                (2, 1, "+15551230001", 1677664950000, 0, 1, -1, 3, None, "draft text", 1)],
        "pdu": [(1, 1, 1677665000, 0, 1, 1, "MID-1", "Pic", 20480), (2, 1, 1677665100, 0, 2, 1, "MID-2", None, 100)],
        "part": [(1, 1, -1, "application/smil", None, "smil.xml", "<smil/>", None),
                 (2, 1, 0, "text/plain", None, "text_0.txt", "Look at this", None),
                 (3, 1, 1, "image/jpeg", "IMG.jpg", "IMG.jpg", None, "/data/user_de/0/com.android.providers.telephony/app_parts/PART_1")],
        "addr": [(1, 1, "+15551230001", 137), (2, 1, "insert-address-token", 151), (3, 2, "+15551230002", 151)],
    })
    _sqlite(prov / "com.android.browser" / "databases" / "browser2.db", """
        CREATE TABLE history (_id INTEGER PRIMARY KEY, title TEXT, url TEXT, created INTEGER, date INTEGER,
            visits INTEGER, user_entered INTEGER);
        CREATE TABLE bookmarks (_id INTEGER PRIMARY KEY, title TEXT, url TEXT, folder INTEGER, created INTEGER,
            deleted INTEGER);
    """, {
        "history": [(1, "Example", "https://example.com/", 1677600000000, 1677664800000, 3, 1),
                    (2, "Search", "https://search.example/?q=boat", 0, 1677665400000, 1, 0)],
        "bookmarks": [(1, "Bookmarks", None, 1, 0, 0), (2, "Docs", "https://docs.example/", 0, 1677500000000, 0)],
    })
    packages = (
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<packages>\n"
        f'  <package name="com.example.chat" codePath="/data/app/com.example.chat-1" flags="572996" '
        f'ft="{1677000000000:x}" it="{1677000000000:x}" ut="{1677600000000:x}" version="412" userId="10123" '
        'installer="com.android.vending">\n'
        '    <perms>\n      <item name="android.permission.READ_SMS" granted="true" />\n'
        '      <item name="android.permission.CAMERA" granted="true" />\n    </perms>\n  </package>\n'
        '  <package name="com.android.settings" codePath="/system/priv-app/Settings" version="29" sharedUserId="1000" />\n'
        '  <package codePath="/nowhere" />\n'
        "</packages>\n"
    )
    _write(root / "data" / "system" / "packages.xml", packages)
    _write(root / "data" / "data" / "com.broken" / "databases" / "webview.db", b"corrupt" * 100)


def _mk(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def main() -> int:
    if not CORPUS.is_dir():
        print(f"corpus missing: {CORPUS}", file=sys.stderr)
        return 1
    make_cloud()
    make_ios_backup()
    make_android_backup()
    make_android_pull()
    print(f"fixtures written under {HERE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
