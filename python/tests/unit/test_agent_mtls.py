"""Real mutual-TLS upload: the Rust agent against a TLS server that demands a client certificate.

Certificates are generated per test run: an engagement CA, a server leaf for 127.0.0.1, a client
leaf signed by the CA, and a rogue client signed by an unrelated CA. The server speaks the agent's
resumable intake protocol (see crates/veritas-agent/src/transfer.rs), records the verified peer
certificate, and reassembles the segments so the bytes can be checked end to end.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402


def _agent_bin() -> Path:
    exe = "veritas-agent.exe" if os.name == "nt" else "veritas-agent"
    d = os.environ.get("VERITAS_BIN_DIR")
    cand = Path(d) / exe if d else Path(__file__).resolve().parents[3] / "target" / "release" / exe
    if not cand.exists():
        found = shutil.which("veritas-agent")
        if not found:
            pytest.skip("veritas-agent binary not built (set VERITAS_BIN_DIR)")
        return Path(found)
    return cand


# --------------------------------------------------------------------------------------- PKI
def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Veritas test engagement"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn: str):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(ca_key, ca_cert, cn: str, server: bool, key_type: str = "rsa"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if key_type == "rsa" else ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    b = (
        x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    if server:
        b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), critical=False)
    return key, b.sign(ca_key, hashes.SHA256())


def _pem_cert(c) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def _pem_key(k) -> bytes:  # PKCS#8, which is what the agent's native-tls identity loader takes
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca_key, ca = _ca("Veritas Engagement CA")
    srv_key, srv = _leaf(ca_key, ca, "intake.test", server=True)
    cli_key, cli = _leaf(ca_key, ca, "agent-WS01", server=False)
    rogue_ca_key, rogue_ca = _ca("Rogue CA")
    rog_key, rog = _leaf(rogue_ca_key, rogue_ca, "agent-rogue", server=False)
    files = {
        "ca.pem": _pem_cert(ca), "ca.key": _pem_key(ca_key), "server.pem": _pem_cert(srv) + _pem_cert(ca), "server.key": _pem_key(srv_key),
        "client.pem": _pem_cert(cli), "client.key": _pem_key(cli_key),
        "rogue.pem": _pem_cert(rog), "rogue.key": _pem_key(rog_key), "rogue-ca.pem": _pem_cert(rogue_ca),
    }
    for n, b in files.items():
        (d / n).write_bytes(b)
    return d


# ------------------------------------------------------------------------------- intake server
class _State:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions: dict[str, dict] = {}
        self.peers: list[str] = []


def _handler(state: _State):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # keep pytest output quiet
            pass

        def _peer(self):
            cert = self.connection.getpeercert()
            cn = dict(x[0] for x in cert["subject"])["commonName"]
            with state.lock:
                state.peers.append(cn)

        def _send(self, code: int, obj) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length", "0")))

        def do_POST(self):
            self._peer()
            parts = self.path.strip("/").split("/")
            if self.path == "/api/v1/intake/sessions":
                m = json.loads(self._body())
                sid = f"S{len(state.sessions) + 1}"
                with state.lock:
                    state.sessions[sid] = {"manifest": m, "segments": {}}
                return self._send(201, {"session_id": sid})
            if len(parts) == 6 and parts[5] == "complete":
                self._body()
                s = state.sessions.get(parts[4])
                if s is None:
                    return self._send(404, {"detail": "unknown session"})
                if sorted(s["segments"]) != [x["index"] for x in s["manifest"]["segments"]]:
                    return self._send(409, {"detail": "missing segments"})
                s["complete"] = True
                return self._send(201, {"ok": True})
            self._send(404, {"detail": "no route"})

        def do_GET(self):
            self._peer()
            parts = self.path.strip("/").split("/")
            s = state.sessions.get(parts[4]) if len(parts) == 5 else None
            if s is None:
                return self._send(404, {"detail": "unknown session"})
            segs = [{"index": i, "size": len(b), "sha256": hashlib.sha256(b).hexdigest()} for i, b in sorted(s["segments"].items())]
            self._send(200, {"segments": segs})

        def do_PUT(self):
            self._peer()
            parts = self.path.strip("/").split("/")
            s = state.sessions.get(parts[4]) if len(parts) == 7 else None
            if s is None:
                return self._send(404, {"detail": "unknown session"})
            body = self._body()
            if hashlib.sha256(body).hexdigest() != self.headers.get("X-Segment-SHA256", "").lower():
                return self._send(422, {"detail": "segment hash mismatch"})
            s["segments"][int(parts[6])] = body
            self._send(200, {"ok": True})

    return H


@pytest.fixture()
def server(pki):
    state = _State()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pki / "server.pem", pki / "server.key")
    ctx.load_verify_locations(pki / "ca.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED  # THREAT:T8.1 the server refuses any connection without a CA-issued client cert
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"https://127.0.0.1:{httpd.server_address[1]}", state
    httpd.shutdown()
    httpd.server_close()


def _manifest(d: Path, n: int = 3, size: int = 200_000) -> tuple[Path, bytes]:
    whole = b""
    segs = []
    for i in range(n):
        data = bytes((j * 31 + i * 7) % 251 for j in range(size))
        whole += data
        p = d / f"img.{i:03}"
        p.write_bytes(data)
        segs.append({"index": i, "path": str(p), "name": p.name, "size": size, "sha256": hashlib.sha256(data).hexdigest()})
    mp = d / "img.manifest.json"
    mp.write_text(json.dumps({"evidence_id": "EV-1", "case_id": "CASE-1", "segments": segs}), encoding="utf-8")
    return mp, whole


def _upload(url: str, pki: Path, manifest: Path, cert: str = "client", ca: str = "ca.pem") -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(_agent_bin()), "upload", "--server", url, "--client-cert", str(pki / f"{cert}.pem"), "--client-key", str(pki / f"{cert}.key"), "--ca", str(pki / ca), str(manifest)],
        capture_output=True, text=True, timeout=120,
    )


# ------------------------------------------------------------------------------------- tests
def test_mtls_upload_delivers_every_byte(server, pki, tmp_path):
    url, state = server
    mp, whole = _manifest(tmp_path)
    r = _upload(url, pki, mp)
    assert r.returncode == 0, r.stderr
    (s,) = state.sessions.values()
    assert s.get("complete") is True
    got = b"".join(s["segments"][i] for i in sorted(s["segments"]))
    assert hashlib.sha256(got).digest() == hashlib.sha256(whole).digest()
    # Every request arrived on a connection that presented the engagement client certificate.
    assert state.peers and set(state.peers) == {"agent-WS01"}


def test_server_rejects_a_client_cert_from_another_ca(server, pki, tmp_path):
    url, state = server
    mp, _ = _manifest(tmp_path, n=1, size=1000)
    r = _upload(url, pki, mp, cert="rogue")
    assert r.returncode != 0
    assert not state.sessions and not state.peers


def test_agent_rejects_a_server_not_signed_by_the_pinned_ca(server, pki, tmp_path):
    url, state = server
    mp, _ = _manifest(tmp_path, n=1, size=1000)
    r = _upload(url, pki, mp, ca="rogue-ca.pem")
    assert r.returncode != 0
    assert not state.sessions


def test_https_without_a_client_identity_is_refused_by_the_agent(server, pki, tmp_path):
    url, state = server
    mp, _ = _manifest(tmp_path, n=1, size=1000)
    r = subprocess.run([str(_agent_bin()), "upload", "--server", url, str(mp)], capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "client-cert" in (r.stderr + r.stdout)
    assert not state.sessions


def test_ec_client_keys_work_except_on_windows_schannel(server, pki, tmp_path):
    """native-tls on Windows (SChannel) only imports RSA PKCS#8 identities; OpenSSL and Secure
    Transport take EC keys too. Issue RSA client certificates for Windows agents (docs/RUNBOOK.md)."""
    url, state = server
    ca_key = serialization.load_pem_private_key((pki / "ca.key").read_bytes(), None)
    ca = x509.load_pem_x509_certificate((pki / "ca.pem").read_bytes())
    key, cert = _leaf(ca_key, ca, "agent-ec", server=False, key_type="ec")
    (tmp_path / "ec.pem").write_bytes(_pem_cert(cert))
    (tmp_path / "ec.key").write_bytes(_pem_key(key))
    mp, _ = _manifest(tmp_path, n=1, size=1000)
    r = subprocess.run([str(_agent_bin()), "upload", "--server", url, "--client-cert", str(tmp_path / "ec.pem"), "--client-key", str(tmp_path / "ec.key"),
                        "--ca", str(pki / "ca.pem"), str(mp)], capture_output=True, text=True, timeout=120)
    if os.name == "nt":
        assert r.returncode != 0 and "client identity" in r.stderr
    else:
        assert r.returncode == 0, r.stderr
        assert "agent-ec" in state.peers
