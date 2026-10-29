"""Database: versioned migrations and integrity constraints."""

import sqlite3

import pytest

from webapp.backend.db import MIGRATIONS, SCHEMA_VERSION, connect, migrate, schema_version


def test_migrations_apply_once_and_are_idempotent(tmp_path):
    conn = connect(tmp_path / "x.sqlite3")
    assert migrate(conn) == SCHEMA_VERSION == MIGRATIONS[-1][0]
    assert migrate(conn) == SCHEMA_VERSION
    assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == len(MIGRATIONS)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"samples", "artifacts", "jobs", "job_stages", "job_inputs", "job_outputs",
            "job_tools", "evidence_refs", "job_events"} <= tables
    assert schema_version(conn) == SCHEMA_VERSION


def test_constraints_enforce_gate3_uniqueness_and_status_vocabulary(tmp_path):
    conn = connect(tmp_path / "x.sqlite3")
    migrate(conn)
    ins = ("INSERT INTO samples (sha256, mode, approval_id, source, retrieved, created_utc)"
           " VALUES (?, ?, ?, 's', '2026-10-27', 'now')")
    with pytest.raises(sqlite3.IntegrityError):  # empirical without approval
        conn.execute(ins, ("a" * 64, "empirical", None))
    conn.execute(ins, ("a" * 64, "synthetic", None))
    with pytest.raises(sqlite3.IntegrityError):  # duplicate SHA-256
        conn.execute(ins, ("a" * 64, "synthetic", None))
    with pytest.raises(sqlite3.IntegrityError):  # unknown job status
        conn.execute("INSERT INTO jobs (sample_id, status, created_utc) VALUES (1, 'done', 'now')")
    conn.execute("INSERT INTO jobs (sample_id, status, created_utc) VALUES (1, 'queued', 'now')")
    with pytest.raises(sqlite3.IntegrityError):  # stage statuses are a fixed vocabulary
        conn.execute("INSERT INTO job_stages (job_id, stage, status) VALUES (1, 'A', 'zero')")
