"""Basic Security Module / OpenBSM audit trails (macOS ``/var/audit``, FreeBSD).

Big-endian token stream. Each record starts with a header token whose ``record_byte_count``
bounds the record; tokens inside it are decoded until the trailer (0x13) or the bound. An
unknown token type stops decoding of *that* record (a warning is counted) and parsing resumes at
the next record using the header byte count, so one odd token never derails the file.

Supported tokens: header32 (0x14), header32_ex (0x15), header64 (0x74), header64_ex (0x79),
trailer (0x13), subject32/process32 (0x24/0x26), subject64/process64 (0x75/0x77),
subject32_ex/process32_ex (0x7a/0x7b), subject64_ex/process64_ex (0x7c/0x7d), return32 (0x27),
return64 (0x72), text (0x28), path (0x23), exec_args (0x3c), exec_env (0x3d), arg32 (0x2d),
arg64 (0x71), attr32 (0x3e), attr64 (0x73), in_addr (0x2a), in_addr_ex (0x7e), ip (0x2b),
iport (0x2c), socket (0x2e), socket_ex (0x7f), sockinet32 (0x80), sockinet128 (0x81),
sockunix (0x82), seq (0x2f), ipc (0x22), ipc_perm (0x32), opaque (0x29), data (0x21), zonename (0x60), file (0x11),
newgroups (0x3b), exit (0x52), identity (0xed), upriv (0x39).

One ``bsm:entry`` per record (Content Modification Time = header time) with the decoded tokens
in ``attrs.tokens`` and convenience fields (subject uids, return status/value, text, paths, argv).
"""
from __future__ import annotations

import ipaddress
import os
import struct
from typing import Any, Iterator

from veritas.parsers.base import BaseParser, ParserError, Provenance, clip
from veritas.timeline.schema import NS, Desc, Event

HEADERS = {0x14, 0x15, 0x74, 0x79}
MAX_FILE = 1024 * 1024 * 1024
MAX_RECORD = 16 * 1024 * 1024
EVENT_NAMES = {
    0: "indir system call", 1: "exit(2)", 2: "fork(2)", 3: "open(2) - attr only", 5: "creat(2)", 6: "link(2)",
    7: "unlink(2)", 9: "exec(2)", 10: "chdir(2)", 23: "execve(2)", 32: "login - local", 43: "su(1)",
    45001: "AUE_audit_startup", 45002: "AUE_audit_shutdown", 45014: "AUE_modify_password",
    45023: "AUE_login", 45024: "AUE_logout", 45025: "AUE_ssh", 45029: "AUE_audit_recovery",
    6152: "login - local", 6153: "logout - local", 6158: "sudo(8)", 6159: "su(1)",
}
RETURN_STATUS = {0: "Success", 1: "Operation not permitted", 2: "No such file or directory", 13: "Permission denied",
                 255: "Failure"}


class _Reader:
    def __init__(self, data: bytes, pos: int, end: int):
        self.d, self.p, self.end = data, pos, end

    def take(self, n: int) -> bytes:
        if n < 0 or self.p + n > self.end:
            raise ValueError("token overruns record")
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def cstr16(self) -> str:
        n = self.u16()
        return clip(self.take(n).split(b"\x00", 1)[0].decode("utf-8", "replace"))

    def addr(self, typ: int) -> str:
        if typ == 16:
            return str(ipaddress.IPv6Address(self.take(16)))
        return str(ipaddress.IPv4Address(self.take(4)))


def _subject(r: _Reader, port64: bool, ex: bool) -> dict[str, Any]:
    auid, euid, egid, ruid, rgid, pid, sid = (r.u32() for _ in range(7))
    port = r.u64() if port64 else r.u32()
    if ex:
        atype = r.u32()
        addr = r.addr(atype)
    else:
        addr = r.addr(4)
    return {"audit_uid": auid, "effective_uid": euid, "effective_gid": egid, "real_uid": ruid, "real_gid": rgid,
            "pid": pid, "session_id": sid, "terminal_port": port, "terminal_ip": addr}


def _strings(r: _Reader, count: int) -> list[str]:
    out = []
    for _ in range(min(count, 4096)):
        nul = r.d.find(b"\x00", r.p, r.end)
        if nul < 0:
            raise ValueError("unterminated exec string")
        out.append(clip(r.d[r.p:nul].decode("utf-8", "replace")))
        r.p = nul + 1
    return out


def decode_token(tid: int, r: _Reader) -> dict[str, Any]:
    if tid in (0x24, 0x26):
        return {"type": "subject32" if tid == 0x24 else "process32", **_subject(r, False, False)}
    if tid in (0x75, 0x77):
        return {"type": "subject64" if tid == 0x75 else "process64", **_subject(r, True, False)}
    if tid in (0x7a, 0x7b):
        return {"type": "subject32_ex" if tid == 0x7a else "process32_ex", **_subject(r, False, True)}
    if tid in (0x7c, 0x7d):
        return {"type": "subject64_ex" if tid == 0x7c else "process64_ex", **_subject(r, True, True)}
    if tid == 0x27:
        st = r.u8()
        return {"type": "return32", "status": st, "status_name": RETURN_STATUS.get(st), "value": r.u32()}
    if tid == 0x72:
        st = r.u8()
        return {"type": "return64", "status": st, "status_name": RETURN_STATUS.get(st), "value": r.u64()}
    if tid == 0x28:
        return {"type": "text", "text": r.cstr16()}
    if tid == 0x23:
        return {"type": "path", "path": r.cstr16()}
    if tid == 0x60:
        return {"type": "zonename", "zonename": r.cstr16()}
    if tid in (0x3c, 0x3d):
        n = r.u32()
        return {"type": "exec_args" if tid == 0x3c else "exec_env", "strings": _strings(r, n)}
    if tid == 0x2d:
        num, val = r.u8(), r.u32()
        return {"type": "arg32", "number": num, "value": val, "text": r.cstr16()}
    if tid == 0x71:
        num, val = r.u8(), r.u64()
        return {"type": "arg64", "number": num, "value": val, "text": r.cstr16()}
    if tid == 0x3e:
        mode, uid, gid, fsid = (r.u32() for _ in range(4))
        return {"type": "attr32", "mode": mode, "uid": uid, "gid": gid, "fsid": fsid, "node_id": r.u64(), "device": r.u32()}
    if tid == 0x73:
        mode, uid, gid, fsid = (r.u32() for _ in range(4))
        return {"type": "attr64", "mode": mode, "uid": uid, "gid": gid, "fsid": fsid, "node_id": r.u64(), "device": r.u64()}
    if tid == 0x2a:
        return {"type": "in_addr", "address": r.addr(4)}
    if tid == 0x7e:
        return {"type": "in_addr_ex", "address": r.addr(r.u32())}
    if tid == 0x2b:
        return {"type": "ip", "header": r.take(20).hex()}
    if tid == 0x2c:
        return {"type": "iport", "port": r.u16()}
    if tid == 0x2e:
        return {"type": "socket", "socket_type": r.u16(), "port": r.u16(), "address": r.addr(4)}
    if tid == 0x7f:
        dom, styp, atype = r.u16(), r.u16(), r.u32()
        lport, laddr = r.u16(), r.addr(atype)
        rport, raddr = r.u16(), r.addr(atype)
        return {"type": "socket_ex", "domain": dom, "socket_type": styp, "local_port": lport, "local_address": laddr,
                "remote_port": rport, "remote_address": raddr}
    if tid == 0x80:
        return {"type": "sockinet32", "family": r.u16(), "port": r.u16(), "address": r.addr(4)}
    if tid == 0x81:
        return {"type": "sockinet128", "family": r.u16(), "port": r.u16(), "address": r.addr(16)}
    if tid == 0x82:
        fam = r.u16()
        return {"type": "sockunix", "family": fam, "path": clip(r.take(104).split(b"\x00", 1)[0].decode("utf-8", "replace"))}
    if tid == 0x2f:
        return {"type": "seq", "sequence": r.u32()}
    if tid == 0x22:
        return {"type": "ipc", "object_type": r.u8(), "object_id": r.u32()}
    if tid == 0x32:
        uid, gid, puid, pgid, mode, seq, key = (r.u32() for _ in range(7))
        return {"type": "ipc_perm", "uid": uid, "gid": gid, "creator_uid": puid, "creator_gid": pgid, "mode": mode,
                "sequence": seq, "key": key}
    if tid == 0x29:
        return {"type": "opaque", "data": r.take(r.u16())[:256].hex()}
    if tid == 0x21:
        how, unit, count = r.u8(), r.u8(), r.u8()
        size = {0: 1, 1: 2, 2: 4, 3: 8}.get(unit, 1)
        return {"type": "data", "how": how, "unit": unit, "data": r.take(size * count)[:256].hex()}
    if tid == 0x11:
        sec, msec = r.u32(), r.u32()
        return {"type": "file", "seconds": sec, "milliseconds": msec, "name": r.cstr16()}
    if tid == 0x3b:
        n = r.u16()
        return {"type": "newgroups", "groups": [r.u32() for _ in range(min(n, 4096))]}
    if tid == 0x52:
        return {"type": "exit", "status": r.u32(), "return": r.u32()}
    if tid == 0x39:
        return {"type": "upriv", "success": r.u8(), "privilege": r.cstr16()}
    if tid == 0xED:
        st = r.u32()
        signing_id = r.cstr16()
        cdhash = r.take(r.u16()).hex()
        return {"type": "identity", "signer_type": st, "signing_id": signing_id, "cdhash": cdhash}
    raise KeyError(tid)


class BsmParser(BaseParser):
    name = "bsm_log"
    version = "1.0"
    source_short = "LOG"
    source_long = "BSM audit trail"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        if len(head_bytes) < 18 or head_bytes[0] not in HEADERS:
            return False
        size = struct.unpack(">I", head_bytes[1:5])[0]
        return 18 <= size <= MAX_RECORD and head_bytes[5] in (1, 2, 10, 11)

    def _parse(self, path: str, prov: Provenance) -> Iterator[Event]:
        size = os.path.getsize(path)
        if size > MAX_FILE:
            raise ParserError("bsm: file too large")
        with open(path, "rb") as fh:
            data = fh.read()
        if not data or data[0] not in HEADERS:
            raise ParserError("bsm: does not start with a header token")
        pos = 0
        while pos < len(data):
            tid = data[pos]
            if tid not in HEADERS:
                self.warn(f"offset {pos}: expected header token, got {tid:#x}; stopping")
                break
            if pos + 5 > len(data):
                self.warn(f"offset {pos}: truncated header")
                break
            rec_size = struct.unpack_from(">I", data, pos + 1)[0]
            if rec_size < 18 or rec_size > MAX_RECORD:
                self.warn(f"offset {pos}: implausible record size {rec_size}; stopping")
                break
            end = min(len(data), pos + rec_size)
            try:
                ev = self._record(data, pos, end, tid)
                if ev is not None:
                    yield ev
            except Exception as exc:  # noqa: BLE001
                self.warn(f"record at {pos}: {exc}")
            if end <= pos:
                break
            pos = end

    def _record(self, data: bytes, pos: int, end: int, tid: int) -> Event | None:
        r = _Reader(data, pos + 1, end)
        r.u32()
        version = r.u8()
        event_type, modifier = r.u16(), r.u16()
        addr = None
        if tid in (0x15, 0x79):
            addr = r.addr(r.u32())
        if tid in (0x14, 0x15):
            sec, frac = r.u32(), r.u32()
            ts = sec * NS + min(frac, 999) * 1_000_000
        else:
            sec, frac = r.u64(), r.u64()
            ts = sec * NS + (frac if frac < NS else 0)
        tokens: list[dict[str, Any]] = []
        complete = False
        while r.p < end:
            t = r.u8()
            if t == 0x13:
                magic, count = r.u16(), r.u32()
                complete = magic == 0xB105
                break
            try:
                tokens.append(decode_token(t, r))
            except KeyError:
                self.warn(f"record at {pos}: unsupported token {t:#x}; rest of record skipped")
                break
            if len(tokens) >= 1024:
                break
        attrs: dict[str, Any] = {"event_type": event_type, "event_type_name": EVENT_NAMES.get(event_type),
                                 "event_modifier": modifier, "record_version": version, "host_address": addr,
                                 "record_length": end - pos, "complete": complete, "tokens": tokens}
        for t in tokens:
            ttype = t["type"]
            if ttype.startswith("subject"):
                attrs.setdefault("subject", {k: v for k, v in t.items() if k != "type"})
            elif ttype.startswith("return"):
                attrs.setdefault("return_status", t["status"])
                attrs.setdefault("return_value", t["value"])
            elif ttype == "text":
                attrs.setdefault("text", [])
                attrs["text"].append(t["text"])
            elif ttype == "path":
                attrs.setdefault("paths", [])
                attrs["paths"].append(t["path"])
            elif ttype == "exec_args":
                attrs["argv"] = t["strings"]
        subj = attrs.get("subject") or {}
        msg = f"Type: {attrs['event_type_name'] or event_type} Return: {attrs.get('return_status')} " \
              f"auid={subj.get('audit_uid')} " + " ".join(attrs.get("text", []) + attrs.get("paths", []))
        return self.event("bsm:entry", Desc.MODIFICATION, msg.strip(), ts, offset=pos, attrs=attrs)


PARSERS = [BsmParser]
