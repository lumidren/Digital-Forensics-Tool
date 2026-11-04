"""OpenSSH configuration and key inventory (``Not a time`` events unless ``mtime_ns`` given).

* ``authorized_keys``: options, key type, base64 key (SHA-256 fingerprint computed), comment.
  Options such as ``command=``, ``from=``, ``environment=`` are surfaced; forced commands are
  flagged. -> ``linux:ssh:authorized_key``
* ``known_hosts``: hosts (or ``|1|`` hashed host marker), key type, fingerprint, ``@revoked``/
  ``@cert-authority`` markers. -> ``linux:ssh:known_host``
* ``sshd_config``: every directive; dangerous settings flagged in ``attrs.risky`` (PermitRootLogin
  yes, PasswordAuthentication yes, PermitEmptyPasswords yes, AuthorizedKeysFile outside home,
  AuthorizedKeysCommand, GatewayPorts yes, PermitTunnel yes, AllowTcpForwarding yes,
  PermitUserEnvironment yes, X11Forwarding yes, UsePAM no). -> ``linux:ssh:sshd_config``
* ``~/.ssh/config``: Host blocks with HostName/User/Port/IdentityFile/ProxyCommand/LocalForward/
  RemoteForward/DynamicForward. -> ``linux:ssh:client_config``
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Iterator

from veritas.parsers.base import Provenance
from veritas.parsers.text_log import TextLogParser, is_text
from veritas.timeline.schema import Desc, Event

KEY_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa-cert-v01@openssh.com",
             "ssh-ed25519-cert-v01@openssh.com")
RISKY = {
    "permitrootlogin": lambda v: v.lower() == "yes", "passwordauthentication": lambda v: v.lower() == "yes",
    "permitemptypasswords": lambda v: v.lower() == "yes", "gatewayports": lambda v: v.lower() in ("yes", "clientspecified"),
    "permittunnel": lambda v: v.lower() in ("yes", "point-to-point", "ethernet"),
    "allowtcpforwarding": lambda v: v.lower() in ("yes", "all"), "permituserenvironment": lambda v: v.lower() != "no",
    "x11forwarding": lambda v: v.lower() == "yes", "usepam": lambda v: v.lower() == "no",
    "authorizedkeyscommand": lambda v: v.lower() != "none",
    "authorizedkeysfile": lambda v: any(not p.startswith((".ssh/", "%h/.ssh/")) for p in v.split()),
    "strictmodes": lambda v: v.lower() == "no", "challengeresponseauthentication": lambda v: v.lower() == "yes",
}
CLIENT_KEYS = {"hostname", "user", "port", "identityfile", "proxycommand", "proxyjump", "localforward",
               "remoteforward", "dynamicforward", "forwardagent", "stricthostkeychecking", "userknownhostsfile"}


def _split_options(text: str) -> tuple[str, str]:
    """Split a leading options field honouring double quotes."""
    in_q = False
    for i, ch in enumerate(text):
        if ch == '"':
            in_q = not in_q
        elif ch in " \t" and not in_q:
            return text[:i], text[i:].strip()
    return text, ""


def _fingerprint(b64: str) -> str | None:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _parse_key(text: str) -> dict | None:
    parts = text.split(None, 2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        return None
    return {"key_type": parts[0], "fingerprint": _fingerprint(parts[1]), "comment": parts[2] if len(parts) > 2 else None}


def _name(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


class _SshBase(TextLogParser):
    source_short = "LOG"
    files: tuple[str, ...] = ()

    def matches(self, path: str, head_bytes: bytes) -> bool:
        n = _name(path)
        return is_text(head_bytes) and any(n == f or n.startswith(f + ".") for f in self.files)

    def begin(self, prov: Provenance) -> None:
        self.mtime = prov.mtime_ns

    def _desc(self) -> str:
        return Desc.MODIFICATION if self.mtime else Desc.NOT_A_TIME


class AuthorizedKeysParser(_SshBase):
    name = "ssh_authorized_keys"
    version = "1.0"
    source_long = "SSH authorized_keys"
    files = ("authorized_keys", "authorized_keys2")

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        s = line.strip()
        if not s or s.startswith("#"):
            return
        key = _parse_key(s)
        options = None
        if key is None:
            options, rest = _split_options(s)
            key = _parse_key(rest)
        if key is None:
            self.warn(f"line {lineno}: unrecognised key line")
            return
        opts = {}
        for o in re.findall(r'([A-Za-z-]+)(?:="((?:[^"\\]|\\.)*)")?', options or ""):
            if o[0]:
                opts[o[0].lower()] = o[1] if o[1] else True
        key.update({"options": opts, "forced_command": opts.get("command"), "from_restriction": opts.get("from")})
        yield self.event("linux:ssh:authorized_key", self._desc(),
                         f"authorized key {key['key_type']} {key['fingerprint']} {key['comment'] or ''}".strip(),
                         self.mtime, offset=lineno, attrs=key)


class KnownHostsParser(_SshBase):
    name = "ssh_known_hosts"
    version = "1.0"
    source_long = "SSH known_hosts"
    files = ("known_hosts", "known_hosts2", "ssh_known_hosts")

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        s = line.strip()
        if not s or s.startswith("#"):
            return
        marker = None
        if s.startswith("@"):
            marker, s = s.split(None, 1) if " " in s else (s, "")
        parts = s.split(None, 1)
        if len(parts) < 2:
            self.warn(f"line {lineno}: unrecognised known_hosts line")
            return
        key = _parse_key(parts[1])
        if key is None:
            self.warn(f"line {lineno}: unrecognised key")
            return
        hosts = parts[0]
        key.update({"hosts": [] if hosts.startswith("|1|") else hosts.split(","), "hashed": hosts.startswith("|1|"),
                    "marker": marker})
        yield self.event("linux:ssh:known_host", self._desc(), f"known host {hosts} {key['key_type']} {key['fingerprint']}",
                         self.mtime, offset=lineno, attrs=key)


class SshdConfigParser(_SshBase):
    name = "sshd_config"
    version = "1.0"
    source_long = "sshd_config"
    files = ("sshd_config",)

    def begin(self, prov: Provenance) -> None:
        super().begin(prov)
        self.match_block: str | None = None

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        s = line.strip()
        if not s or s.startswith("#"):
            return
        parts = re.split(r"\s+|\s*=\s*", s, maxsplit=1)
        key, value = parts[0], parts[1] if len(parts) > 1 else ""
        if key.lower() == "match":
            self.match_block = value
        check = RISKY.get(key.lower())
        risky = bool(check and check(value))
        attrs = {"directive": key, "value": value, "risky": risky, "match_block": self.match_block}
        yield self.event("linux:ssh:sshd_config", self._desc(), f"sshd_config {key} {value}" + (" [RISKY]" if risky else ""),
                         self.mtime, offset=lineno, attrs=attrs)


class SshClientConfigParser(_SshBase):
    name = "ssh_client_config"
    version = "1.0"
    source_long = "SSH client config"

    def matches(self, path: str, head_bytes: bytes) -> bool:
        p = path.replace("\\", "/").lower()
        return is_text(head_bytes) and (p.endswith("/.ssh/config") or p.endswith("/ssh_config"))

    def begin(self, prov: Provenance) -> None:
        super().begin(prov)
        self.block: dict | None = None

    def _flush(self) -> Iterator[Event]:
        if self.block is None:
            return
        b, self.block = self.block, None
        yield self.event("linux:ssh:client_config", self._desc(),
                         f"ssh Host {b['host']} -> {b.get('hostname') or ''} {b.get('proxycommand') or ''}".strip(),
                         self.mtime, offset=b["lineno"], attrs={k: v for k, v in b.items() if k != "lineno"})

    def parse_line(self, lineno: int, line: str) -> Iterator[Event]:
        s = line.strip()
        if not s or s.startswith("#"):
            return
        parts = re.split(r"\s+|\s*=\s*", s, maxsplit=1)
        key, value = parts[0].lower(), parts[1] if len(parts) > 1 else ""
        if key in ("host", "match"):
            yield from self._flush()
            self.block = {"host": value, "lineno": lineno, "block_type": key}
            return
        if self.block is None:
            self.block = {"host": "*", "lineno": lineno, "block_type": "global"}
        if key in CLIENT_KEYS:
            self.block[key] = value

    def finish(self) -> Iterator[Event]:
        yield from self._flush()


PARSERS = [AuthorizedKeysParser, KnownHostsParser, SshdConfigParser, SshClientConfigParser]
