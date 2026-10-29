"""SQLite persistence with explicit, versioned migrations.

Each migration is applied once, in order, inside a transaction, and recorded
in ``schema_migrations``. Never edit an applied migration; append a new one.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "initial schema", """
CREATE TABLE samples (
    id            INTEGER PRIMARY KEY,
    sha256        TEXT NOT NULL UNIQUE CHECK (length(sha256) = 64),
    label         TEXT NOT NULL DEFAULT '',
    mode          TEXT NOT NULL CHECK (mode IN ('synthetic', 'empirical')),
    approval_id   TEXT,
    source        TEXT NOT NULL,
    retrieved     TEXT NOT NULL,
    packer_label  TEXT NOT NULL DEFAULT '',
    note          TEXT NOT NULL DEFAULT '',
    file_stored   INTEGER NOT NULL DEFAULT 0,
    file_size     INTEGER,
    pe_meta       TEXT,
    created_utc   TEXT NOT NULL,
    CHECK (mode = 'synthetic' OR (approval_id IS NOT NULL AND length(trim(approval_id)) > 0))
);
CREATE TABLE artifacts (
    id                 INTEGER PRIMARY KEY,
    sample_id          INTEGER NOT NULL REFERENCES samples(id),
    kind               TEXT NOT NULL CHECK (kind IN
                         ('A','B_recovery','B','C','S','evidence','cape_report','payload_pe','sample_pe')),
    origin             TEXT NOT NULL CHECK (origin IN ('upload','bundle','tool','derived','fixture')),
    storage_name       TEXT NOT NULL,
    sha256             TEXT NOT NULL CHECK (length(sha256) = 64),
    size               INTEGER NOT NULL,
    original_name      TEXT NOT NULL DEFAULT '',
    tool_name          TEXT,
    tool_version       TEXT,
    derived_from       INTEGER REFERENCES artifacts(id),
    superseded         INTEGER NOT NULL DEFAULT 0,
    created_utc        TEXT NOT NULL,
    UNIQUE (sample_id, kind, sha256)
);
CREATE TABLE jobs (
    id                INTEGER PRIMARY KEY,
    sample_id         INTEGER NOT NULL REFERENCES samples(id),
    status            TEXT NOT NULL CHECK (status IN ('queued','running','complete','failed','interrupted')),
    progress          INTEGER NOT NULL DEFAULT 0,
    message           TEXT NOT NULL DEFAULT '',
    error             TEXT,
    worker_id         TEXT,
    heartbeat_utc     TEXT,
    created_utc       TEXT NOT NULL,
    started_utc       TEXT,
    finished_utc      TEXT,
    result_dir        TEXT,
    manifest_sha256   TEXT,
    mapping_name      TEXT,
    mapping_version   TEXT,
    mapping_sha256    TEXT,
    pipeline_version  TEXT,
    python_version    TEXT,
    results_json      TEXT
);
CREATE TABLE job_stages (
    job_id   INTEGER NOT NULL REFERENCES jobs(id),
    stage    TEXT NOT NULL CHECK (stage IN ('A','B','C','S')),
    status   TEXT NOT NULL CHECK (status IN
               ('queued','running','complete','failed','not_recovered','awaiting_input')),
    notes    TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (job_id, stage)
);
CREATE TABLE job_inputs (
    job_id       INTEGER NOT NULL REFERENCES jobs(id),
    key          TEXT NOT NULL,
    artifact_id  INTEGER NOT NULL REFERENCES artifacts(id),
    sha256       TEXT NOT NULL,
    PRIMARY KEY (job_id, key)
);
CREATE TABLE job_outputs (
    job_id  INTEGER NOT NULL REFERENCES jobs(id),
    name    TEXT NOT NULL,
    sha256  TEXT NOT NULL,
    PRIMARY KEY (job_id, name)
);
CREATE TABLE job_tools (
    job_id   INTEGER NOT NULL REFERENCES jobs(id),
    tool     TEXT NOT NULL,
    version  TEXT NOT NULL,
    PRIMARY KEY (job_id, tool)
);
CREATE TABLE evidence_refs (
    id            INTEGER PRIMARY KEY,
    job_id        INTEGER NOT NULL REFERENCES jobs(id),
    kind          TEXT NOT NULL CHECK (kind IN ('residual','gain')),
    technique     TEXT NOT NULL,
    label         TEXT NOT NULL,
    evidence_ref  TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE job_events (
    id       INTEGER PRIMARY KEY,
    job_id   INTEGER NOT NULL REFERENCES jobs(id),
    ts_utc   TEXT NOT NULL,
    level    TEXT NOT NULL CHECK (level IN ('info','warning','error')),
    message  TEXT NOT NULL
);
CREATE INDEX idx_artifacts_sample ON artifacts(sample_id, kind);
CREATE INDEX idx_jobs_sample ON jobs(sample_id, status);
"""),
    (2, "demo mode: synthetic scenario per demo sample", """
ALTER TABLE samples ADD COLUMN demo_scenario TEXT
    CHECK (demo_scenario IS NULL OR demo_scenario IN ('accepted', 'rejected'))
"""),
]

SCHEMA_VERSION = MIGRATIONS[-1][0]


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations; return the resulting schema version."""
    conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_utc TEXT NOT NULL)""")
    applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    for version, description, sql in MIGRATIONS:
        if version in applied:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in (s.strip() for s in sql.split(";")):
                if statement:
                    conn.execute(statement)
            conn.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)", (version, description, utcnow()))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return schema_version(conn)


def schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return int(row[0] or 0)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def add_event(conn: sqlite3.Connection, job_id: int, level: str, message: str) -> None:
    conn.execute("INSERT INTO job_events (job_id, ts_utc, level, message) VALUES (?, ?, ?, ?)",
                 (job_id, utcnow(), level, message[:2000]))


def loads(value: str | None, default: Any = None) -> Any:
    return json.loads(value) if value else default
