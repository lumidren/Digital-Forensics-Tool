"""Runtime configuration from environment variables (12-factor). Secrets are never logged."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


@dataclass(slots=True)
class Settings:
    data_dir: Path
    database_url: str
    timeline_url: str
    store_backend: str  # "local" | "s3"
    s3_bucket: str | None
    master_key_hex: str | None
    oidc_issuer: str | None
    oidc_audience: str | None
    oidc_jwks_url: str | None
    local_auth: bool
    token_ttl_s: int
    cors_origins: list[str]
    ledger_actor_key_seed: str | None
    retention_days: int
    max_upload_bytes: int
    report_template_dir: Path
    bin_dir: str | None
    otel_endpoint: str | None
    redact_by_default: bool = True
    instance_name: str = "veritas"
    extra: dict = field(default_factory=dict)

    @property
    def ledger_dir(self) -> Path:
        return self.data_dir / "ledgers"

    @property
    def store_dir(self) -> Path:
        return self.data_dir / "store"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    def __repr__(self) -> str:
        return f"Settings(data_dir={self.data_dir!s}, database_url={_mask(self.database_url)}, store={self.store_backend}, oidc={self.oidc_issuer})"


def _mask(url: str) -> str:
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        return f"{scheme}://***@{rest.split('@', 1)[1]}"
    return url


def load() -> Settings:
    data = Path(_env("VERITAS_DATA_DIR", str(Path.cwd() / "var")) or "var").resolve()
    data.mkdir(parents=True, exist_ok=True)
    return Settings(
        data_dir=data,
        database_url=_env("VERITAS_DATABASE_URL", f"sqlite:///{(data / 'veritas.db').as_posix()}") or "",
        timeline_url=_env("VERITAS_TIMELINE_URL", f"sqlite:///{(data / 'timeline.db').as_posix()}") or "",
        store_backend=_env("VERITAS_STORE", "local") or "local",
        s3_bucket=_env("VERITAS_S3_BUCKET"),
        master_key_hex=_env("VERITAS_MASTER_KEY"),
        oidc_issuer=_env("VERITAS_OIDC_ISSUER"),
        oidc_audience=_env("VERITAS_OIDC_AUDIENCE", "veritas"),
        oidc_jwks_url=_env("VERITAS_OIDC_JWKS_URL"),
        local_auth=(_env("VERITAS_LOCAL_AUTH", "1") == "1"),
        token_ttl_s=int(_env("VERITAS_TOKEN_TTL_S", "28800") or 28800),
        cors_origins=[o for o in (_env("VERITAS_CORS_ORIGINS", "http://localhost:3000") or "").split(",") if o],
        ledger_actor_key_seed=_env("VERITAS_SERVICE_KEY_SEED"),
        retention_days=int(_env("VERITAS_RETENTION_DAYS", "3650") or 3650),
        max_upload_bytes=int(_env("VERITAS_MAX_UPLOAD_BYTES", str(2 * 1024**4)) or 0),
        report_template_dir=Path(_env("VERITAS_REPORT_TEMPLATES", str(Path(__file__).resolve().parents[1] / "reporting" / "templates")) or ""),
        bin_dir=_env("VERITAS_BIN_DIR"),
        otel_endpoint=_env("OTEL_EXPORTER_OTLP_ENDPOINT"),
    )


def new_secret() -> str:
    return secrets.token_hex(32)
