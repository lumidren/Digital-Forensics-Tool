"""Case database: users, cases, membership, evidence, collaboration objects, findings, IOCs, reports."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # subject (OIDC sub or local username)
    display_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)  # local auth only, argon2id
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    can_unmask_pii: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    signing_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | review | closed | disposed
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    legal_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ledger_id: Mapped[str] = mapped_column(String(64))
    # Retention disposal (set once, by POST /api/v1/admin/retention/dispose). The case row, its custody
    # ledger, anchors and the audit log are kept forever as proof of what existed and that it was destroyed.
    disposed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disposed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    disposal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    members: Mapped[list["Membership"]] = relationship(back_populates="case", cascade="all, delete-orphan")


ROLES = ("viewer", "examiner", "reviewer", "lead")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("case_id", "user_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(String(16))
    case: Mapped[Case] = relationship(back_populates="members")


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # EV-...
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    md5: Mapped[str] = mapped_column(String(32))
    sha3_256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    name: Mapped[str] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(String(32))  # disk | memory | triage | logs | pcap | cloud | mobile | file
    description: Mapped[str] = mapped_column(Text, default="")
    host: Mapped[str | None] = mapped_column(String(200), nullable=True)
    acquired_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tz_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    clock_skew_ms: Mapped[int] = mapped_column(Integer, default=0)
    ingest_entry_hash: Mapped[str] = mapped_column(String(64))
    ingested: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    # Additional segment objects of a multi-file image (E02, E03, ...), each stored under its own
    # SHA-256: [{"name": ..., "sha256": ..., "size": ...}]. The primary object is `sha256`.
    segments: Mapped[list] = mapped_column(JSON, default=list)


class Bookmark(Base):
    __tablename__ = "bookmarks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    event_id: Mapped[int] = mapped_column(BigInteger)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    label: Mapped[str] = mapped_column(String(300), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    target_type: Mapped[str] = mapped_column(String(32))  # case | event | evidence | finding | hypothesis
    target_id: Mapped[str] = mapped_column(String(64))
    body: Mapped[str] = mapped_column(Text)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Hypothesis(Base):
    __tablename__ = "hypotheses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(300))
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | supported | refuted
    supporting_event_ids: Mapped[list] = mapped_column(JSON, default=list)
    refuting_event_ids: Mapped[list] = mapped_column(JSON, default=list)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    detail: Mapped[str] = mapped_column(Text, default="")
    assignee: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16), default="todo")  # todo | doing | done
    due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    rule: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    category: Mapped[str] = mapped_column(String(64))
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    evidence_sha256: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    first_ns: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_ns: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="proposed")  # proposed | confirmed | rejected | approved
    origin: Mapped[str] = mapped_column(String(16), default="rule")  # rule | manual
    confirmed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    examiner_rationale: Mapped[str] = mapped_column(Text, default="")
    reviewer_comment: Mapped[str] = mapped_column(Text, default="")


class IocRow(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("case_id", "ioc_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    ioc_id: Mapped[str] = mapped_column(String(600))
    ioc_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(600))
    source: Mapped[str] = mapped_column(String(100))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SavedView(Base):
    __tablename__ = "saved_views"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(200))
    query: Mapped[dict] = mapped_column(JSON)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    format: Mapped[str] = mapped_column(String(8))
    sha256: Mapped[str] = mapped_column(String(64))
    state_hash: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(128))
    signer_key_id: Mapped[str] = mapped_column(String(64))
    ledger_entry_hash: Mapped[str] = mapped_column(String(64))
    path: Mapped[str] = mapped_column(String(1000))
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


def make_engine(url: str):
    engine = create_engine(url, future=True, pool_pre_ping=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _fk(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()
    Base.metadata.create_all(engine)
    _add_missing_columns(engine)
    return engine


def _add_missing_columns(engine) -> None:
    """Additive schema migration: add nullable columns introduced after a database was created."""
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in have:
                ddl = col.type.compile(dialect=engine.dialect)
                with engine.begin() as c:
                    c.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl}'))  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text - additive DDL built from the ORM model metadata, no user input


def make_sessionmaker(engine):
    return sessionmaker(engine, expire_on_commit=False, future=True)
