"""Application context: one object owning every long-lived resource of an API process."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

from .. import __version__
from ..audit.log import AuditLog
from ..custody.ledger import ExaminerKey, Ledger, build_export, key_record, rfc3339_autosi, tool_info, verify_entries
from ..store.content import CaseKeyring, LocalStore, S3Store
from ..timeline.store import open_store
from .auth import TokenService
from .config import Settings
from .db import make_engine, make_sessionmaker

log = logging.getLogger("veritas.api")

SERVICE_ACTOR = "veritas-pipeline"


class KeyVault:
    """Examiner signing keys held server-side, sealed at rest with a key derived from the master key.

    Seeds are never logged or returned by any route. THREAT:T6.1
    """

    def __init__(self, directory: Path, master: bytes):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self._box = SecretBox(hashlib.sha256(master + b"veritas-user-signing-keys").digest())
        self._lock = threading.Lock()
        self.registry_path = self.dir / "registry.json"

    def _path(self, holder: str) -> Path:
        return self.dir / (hashlib.sha256(holder.encode()).hexdigest()[:32] + ".key")

    def get_or_create(self, holder: str, role: str = "examiner") -> ExaminerKey:
        with self._lock:
            p = self._path(holder)
            if p.exists():
                seed = self._box.decrypt(p.read_bytes())
                return ExaminerKey.from_seed_hex(seed.hex())
            key = ExaminerKey.generate()
            p.write_bytes(self._box.encrypt(bytes(key.signing), nacl_random(SecretBox.NONCE_SIZE)))
            reg = self.registry()
            reg["keys"].append(key_record(key, holder, role, datetime.now(timezone.utc) - timedelta(minutes=1)))
            self.registry_path.write_text(json.dumps(reg, indent=2, sort_keys=True), encoding="utf-8")
            return key

    def registry(self) -> dict[str, Any]:
        if self.registry_path.exists():
            return json.loads(self.registry_path.read_text(encoding="utf-8"))
        return {"keys": []}

    def revoke(self, holder: str) -> str | None:
        reg = self.registry()
        key_id = None
        for k in reg["keys"]:
            if k["holder"] == holder and k.get("valid_to") is None:
                k["valid_to"] = rfc3339_autosi(datetime.now(timezone.utc))
                key_id = k["key_id"]
        self.registry_path.write_text(json.dumps(reg, indent=2, sort_keys=True), encoding="utf-8")
        p = self._path(holder)
        if p.exists():
            p.unlink()
        return key_id


class AppContext:
    def __init__(self, settings: Settings):
        self.settings = settings
        for d in (settings.ledger_dir, settings.store_dir, settings.reports_dir, settings.keys_dir):
            d.mkdir(parents=True, exist_ok=True)
        master = self._master_key()
        self.keyring = CaseKeyring(master)
        self.engine = make_engine(settings.database_url)
        self.Session = make_sessionmaker(self.engine)
        if settings.store_backend == "s3":
            self.store = S3Store(settings.s3_bucket or "veritas-evidence", self.keyring, settings.retention_days, kms_key_id=os.environ.get("VERITAS_S3_KMS_KEY_ID"))
        else:
            self.store = LocalStore(settings.store_dir, self.keyring)
        self.timeline = open_store(settings.timeline_url)
        self.audit = AuditLog(settings.data_dir / "audit.db")
        self.vault = KeyVault(settings.keys_dir, master)
        self.service_key = self.vault.get_or_create(SERVICE_ACTOR, role="admin")
        tok_path = settings.keys_dir / "token-signing.pem"
        if not tok_path.exists():
            tok_path.write_bytes(TokenService(settings.token_ttl_s).private_pem())
            os.chmod(tok_path, 0o600)
        self.tokens = TokenService(settings.token_ttl_s, tok_path.read_bytes(), settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url)
        self.tool = tool_info("veritas-api", __version__, "veritas-api")
        self._ledgers: dict[str, Ledger] = {}
        self._ledger_lock = threading.Lock()

    def _master_key(self) -> bytes:
        if self.settings.master_key_hex:
            return bytes.fromhex(self.settings.master_key_hex)
        p = self.settings.keys_dir / "master.key"
        if not p.exists():
            log.warning("VERITAS_MASTER_KEY not set; generated a local master key (native profile only)")
            p.write_bytes(os.urandom(32))
            os.chmod(p, 0o600)
        return p.read_bytes()

    # --- custody ------------------------------------------------------------------------------
    def ledger(self, case_id: str) -> Ledger:
        with self._ledger_lock:
            led = self._ledgers.get(case_id)
            if led is None:
                led = self._ledgers[case_id] = Ledger(self.settings.ledger_dir / f"{case_id}.jsonl")
            return led

    def create_ledger(self, case_id: str, actor: str) -> str:
        ledger_id = f"L-{case_id}"
        key = self.vault.get_or_create(actor)
        self.ledger(case_id).create(ledger_id, case_id, key, actor, self.tool)
        return ledger_id

    def custody(self, case_id: str, actor: str, kind: str, purpose: str, **kw) -> dict[str, Any]:
        key = self.service_key if actor == SERVICE_ACTOR else self.vault.get_or_create(actor)
        return self.ledger(case_id).append(key, actor, kind, purpose, kw.pop("tool", self.tool), **kw)

    def custody_export(self, case_id: str, actor: str) -> dict[str, Any]:
        key = self.vault.get_or_create(actor)
        entries = self.ledger(case_id).entries()
        return build_export(entries, self.vault.registry(), self.anchors(case_id), key, actor)

    def anchors(self, case_id: str) -> list[dict[str, Any]]:
        p = self.settings.ledger_dir / f"{case_id}.anchors.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def anchor(self, case_id: str, sink: str = "file") -> dict[str, Any]:
        head = self.ledger(case_id).head()
        if head is None:
            raise ValueError("empty ledger")
        rec = {"ledger_id": head["ledger_id"], "seq": head["seq"], "head_hash": head["entry_hash"], "anchored_at": rfc3339_autosi(datetime.now(timezone.utc)), "sink": sink, "receipt": None}
        with open(self.settings.ledger_dir / f"{case_id}.anchors.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return rec

    def verify_custody(self, case_id: str) -> tuple[bool, list[str]]:
        return verify_entries(self.ledger(case_id).entries(), self.vault.registry())
