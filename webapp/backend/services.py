"""Business rules shared by the API, the worker and the demo importer.

Every rule that already exists in ``pipeline/`` is reused from there
(SHA-256 and date validation, register rules, report readers, the recovery gate).
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from pipeline.hashing import normalize_sha256, sha256_bytes
from pipeline.registry import RegistryError, add_candidate, validate_date
from pipeline.synthetic import KIT_ORDER, SCENARIO_DESCRIPTIONS, SCENARIOS, demo_payload_sha, dumps, fake_sha, scenario_files

from . import storage
from .config import PROJECT_ROOT, Settings
from .db import loads, row_dict, transaction, utcnow
from .validation import (
    BINARY_KINDS,
    JSON_KINDS,
    ValidationError,
    parse_pe_header,
    read_bundle,
    validate_json_artifact,
)

ACTIVE_JOB_STATES = ("queued", "running")
# Values that are clearly not a real approval reference. The app cannot verify a
# genuine reference; it only refuses the obvious stand-ins.
PLACEHOLDER_APPROVALS = {"", "n/a", "na", "none", "null", "tbd", "todo", "pending", "demo", "test", "x", "xxx",
                         "unknown", "approved", "yes", "placeholder", "dummy", "fake", "0", "000"}


class ServiceError(Exception):
    status_code = 400

    def __init__(self, message: str, **extra: Any):
        super().__init__(message)
        self.message = message
        self.extra = extra


class NotFound(ServiceError):
    status_code = 404


class Conflict(ServiceError):
    status_code = 409


class Forbidden(ServiceError):
    status_code = 403


class TooLarge(ServiceError):
    status_code = 413


# ----------------------------------------------------------------------------- samples


def get_sample(conn: sqlite3.Connection, sample_id: int) -> dict[str, Any]:
    row = row_dict(conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone())
    if row is None:
        raise NotFound("sample not found")
    row["pe_meta"] = loads(row["pe_meta"])
    return row


def create_sample(conn: sqlite3.Connection, settings: Settings, *, sha256: str, label: str, mode: str,
                  approval_id: str | None, source: str, retrieved: str, packer_label: str = "",
                  note: str = "") -> dict[str, Any]:
    try:
        sha = normalize_sha256(sha256)
    except ValueError as exc:
        raise ServiceError(str(exc)) from None
    if mode not in ("synthetic", "empirical"):
        raise ServiceError("mode must be 'synthetic' or 'empirical'")
    approval = (approval_id or "").strip() or None
    if mode == "empirical" and approval is None:
        raise Forbidden("Gate 3: an empirical sample needs the written institutional approval reference (approval_id)")
    if mode == "empirical" and approval.lower().strip(" .-_") in PLACEHOLDER_APPROVALS:
        raise Forbidden(f"Gate 3: {approval!r} is a placeholder, not an approval reference. Use the reference on "
                        "your written institutional approval, or use demo mode, which needs none.")
    if mode == "synthetic" and approval is not None:
        raise ServiceError("synthetic samples do not take an approval reference")
    if not (source or "").strip():
        raise ServiceError("source must be a non-empty description")
    try:
        retrieved = validate_date(retrieved)
    except RegistryError as exc:
        raise ServiceError(str(exc)) from None
    if conn.execute("SELECT id FROM samples WHERE sha256 = ?", (sha,)).fetchone():
        existing = conn.execute("SELECT id FROM samples WHERE sha256 = ?", (sha,)).fetchone()[0]
        raise Conflict("a sample with this SHA-256 is already registered", existing_id=existing)
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO samples (sha256, label, mode, approval_id, source, retrieved, packer_label, note, created_utc)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sha, (label or "").strip()[:120], mode, approval, source.strip()[:500], retrieved,
             (packer_label or "").strip()[:120], (note or "").strip()[:2000], utcnow()))
    # Keep the pipeline's CSV register in step (provenance only; never opens a file).
    try:
        add_candidate(settings.data_dir / "register.csv", sha, source, retrieved, packer_label, note)
    except RegistryError:
        pass  # already present in the CSV from an earlier database; the DB row is authoritative
    return get_sample(conn, cur.lastrowid)


def list_samples(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("""
        SELECT s.*, (SELECT j.id FROM jobs j WHERE j.sample_id = s.id ORDER BY j.id DESC LIMIT 1) AS last_job_id,
               (SELECT j.status FROM jobs j WHERE j.sample_id = s.id ORDER BY j.id DESC LIMIT 1) AS last_job_status,
               (SELECT COUNT(*) FROM artifacts a WHERE a.sample_id = s.id AND a.superseded = 0) AS artifact_count
        FROM samples s ORDER BY s.id DESC""").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["pe_meta"] = loads(d["pe_meta"])
        out.append(d)
    return out


# ----------------------------------------------------------------------------- artifacts


def current_artifacts(conn: sqlite3.Connection, sample_id: int) -> dict[str, dict[str, Any]]:
    rows = conn.execute("SELECT * FROM artifacts WHERE sample_id = ? AND superseded = 0 ORDER BY id",
                        (sample_id,)).fetchall()
    return {r["kind"]: dict(r) for r in rows}


def list_artifacts(conn: sqlite3.Connection, sample_id: int) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM artifacts WHERE sample_id = ? ORDER BY id DESC", (sample_id,)).fetchall()]


def _insert_artifact(conn: sqlite3.Connection, sample_id: int, kind: str, origin: str, storage_name: str,
                     sha: str, size: int, original_name: str, tool_name: str | None = None,
                     tool_version: str | None = None, derived_from: int | None = None) -> dict[str, Any]:
    dup = conn.execute("SELECT * FROM artifacts WHERE sample_id = ? AND kind = ? AND sha256 = ?",
                       (sample_id, kind, sha)).fetchone()
    if dup is not None:
        raise Conflict(f"this {kind} file (SHA-256 {sha[:12]}...) was already submitted for this sample",
                       existing_id=dup["id"])
    with transaction(conn):
        conn.execute("UPDATE artifacts SET superseded = 1 WHERE sample_id = ? AND kind = ? AND superseded = 0",
                     (sample_id, kind))
        cur = conn.execute(
            "INSERT INTO artifacts (sample_id, kind, origin, storage_name, sha256, size, original_name, tool_name,"
            " tool_version, derived_from, created_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sample_id, kind, origin, storage_name, sha, size, storage.safe_display_name(original_name),
             tool_name, tool_version, derived_from, utcnow()))
    return dict(conn.execute("SELECT * FROM artifacts WHERE id = ?", (cur.lastrowid,)).fetchone())


def ingest_json_bytes(conn: sqlite3.Connection, settings: Settings, sample: dict[str, Any], kind: str,
                      data: bytes, original_name: str, origin: str, **tool: Any) -> dict[str, Any]:
    limit = settings.max_cape_bytes if kind == "cape_report" else settings.max_json_bytes
    if len(data) > limit:
        raise TooLarge(f"{kind} exceeds the {limit // (1024 * 1024)} MB limit")
    try:
        doc = validate_json_artifact(kind, data, sample["sha256"], sample["mode"])
    except ValidationError as exc:
        raise ServiceError(str(exc)) from None
    if kind == "B_recovery":
        payload = current_artifacts(conn, sample["id"]).get("payload_pe")
        if payload and payload["sha256"] != doc["payload_sha256"]:
            raise ServiceError("B_recovery: payload_sha256 does not match the stored payload artifact")
    name, sha = storage.commit_bytes_json(data, settings.data_dir)
    return _insert_artifact(conn, sample["id"], kind, origin, name, sha, len(data), original_name, **tool)


def ingest_upload(conn: sqlite3.Connection, settings: Settings, sample_id: int, kind: str,
                  stream: BinaryIO, filename: str) -> dict[str, Any]:
    sample = get_sample(conn, sample_id)
    if kind not in JSON_KINDS + BINARY_KINDS:
        raise ServiceError(f"unknown artifact kind {kind!r}")
    if kind in BINARY_KINDS:
        _pe_upload_allowed(settings, sample)
        limit = settings.max_pe_bytes
    else:
        limit = settings.max_cape_bytes if kind == "cape_report" else settings.max_json_bytes
    try:
        tmp, sha, size = storage.receive(stream, settings.data_dir, limit)
    except storage.UploadTooLarge as exc:
        raise TooLarge(str(exc)) from None
    try:
        if kind in BINARY_KINDS:
            return _ingest_pe(conn, settings, sample, kind, tmp, sha, size, filename)
        data = tmp.read_bytes()
        return ingest_json_bytes(conn, settings, sample, kind, data, filename, "upload")
    finally:
        tmp.unlink(missing_ok=True)


def _pe_upload_allowed(settings: Settings, sample: dict[str, Any]) -> None:
    if not settings.allow_sample_upload:
        raise Forbidden("storing PE files is disabled (VL_ALLOW_SAMPLE_UPLOAD=false). Use the "
                        "'analyze existing evidence' workflow, or enable it on an isolated analysis host.")
    if sample["mode"] != "empirical" or not sample["approval_id"]:
        raise Forbidden("Gate 3: PE files may only be attached to an empirical sample with an approval reference")


def _ingest_pe(conn, settings, sample, kind, tmp: Path, sha: str, size: int, filename: str) -> dict[str, Any]:
    with open(tmp, "rb") as fh:
        head = fh.read(1024 * 1024)
    try:
        meta = parse_pe_header(head)
    except ValidationError as exc:
        raise ServiceError(str(exc)) from None
    if kind == "sample_pe" and sha != sample["sha256"]:
        raise ServiceError(f"uploaded file SHA-256 {sha[:12]}... does not match the registered sample")
    if kind == "payload_pe":
        rec = current_artifacts(conn, sample["id"]).get("B_recovery")
        if rec is None:
            raise ServiceError("attach the recovery record (B_recovery) before the payload")
        record = json.loads(storage.storage_path(settings.data_dir, rec["storage_name"]).read_text(encoding="utf-8"))
        if record.get("payload_sha256") != sha:
            raise ServiceError("payload SHA-256 does not match payload_sha256 in the recovery record (V2)")
        if sha == sample["sha256"]:
            raise ServiceError("payload is identical to the packed sample (V5)")
    name = storage.commit_quarantine(tmp, settings.data_dir, sha)
    art = _insert_artifact(conn, sample["id"], kind, "upload", name, sha, size, filename)
    if kind == "sample_pe":
        with transaction(conn):
            conn.execute("UPDATE samples SET file_stored = 1, file_size = ?, pe_meta = ? WHERE id = ?",
                         (size, json.dumps(meta), sample["id"]))
    art["pe_meta"] = meta
    return art


def create_sample_from_pe(conn, settings, stream: BinaryIO, filename: str, **fields: Any) -> dict[str, Any]:
    """Register a sample from an uploaded PE: hash it, check Gate 3, store it quarantined."""
    if not settings.allow_sample_upload:
        raise Forbidden("storing PE files is disabled (VL_ALLOW_SAMPLE_UPLOAD=false)")
    if fields.get("mode") != "empirical" or not (fields.get("approval_id") or "").strip():
        raise Forbidden("Gate 3: PE uploads require an empirical sample with an approval reference")
    try:
        tmp, sha, size = storage.receive(stream, settings.data_dir, settings.max_pe_bytes)
    except storage.UploadTooLarge as exc:
        raise TooLarge(str(exc)) from None
    try:
        with open(tmp, "rb") as fh:
            parse_pe_header(fh.read(1024 * 1024))
    except ValidationError as exc:
        tmp.unlink(missing_ok=True)
        raise ServiceError(str(exc)) from None
    try:
        sample = create_sample(conn, settings, sha256=sha, **fields)
        _ingest_pe(conn, settings, sample, "sample_pe", tmp, sha, size, filename)
    finally:
        tmp.unlink(missing_ok=True)
    return get_sample(conn, sample["id"])


def ingest_bundle(conn, settings, sample_id: int, stream: BinaryIO) -> dict[str, Any]:
    sample = get_sample(conn, sample_id)
    try:
        tmp, _, _ = storage.receive(stream, settings.data_dir, settings.max_bundle_bytes)
    except storage.UploadTooLarge as exc:
        raise TooLarge(str(exc)) from None
    try:
        files = read_bundle(tmp.read_bytes(), settings.max_bundle_uncompressed)
    except ValidationError as exc:
        raise ServiceError(str(exc)) from None
    finally:
        tmp.unlink(missing_ok=True)
    # Validate everything first so a bad member rejects the whole bundle.
    for kind, data in files.items():
        try:
            validate_json_artifact(kind, data, sample["sha256"], sample["mode"])
        except ValidationError as exc:
            raise ServiceError(f"bundle rejected: {exc}") from None
    order = ["B_recovery"] + [k for k in files if k != "B_recovery"]
    added, skipped = [], []
    for kind in (k for k in order if k in files):
        try:
            added.append(ingest_json_bytes(conn, settings, sample, kind, files[kind], f"{kind}.json", "bundle"))
        except Conflict as exc:
            skipped.append({"kind": kind, "reason": exc.message})
    return {"added": added, "skipped": skipped}


# ----------------------------------------------------------------------------- jobs


def enqueue_job(conn: sqlite3.Connection, sample_id: int) -> dict[str, Any]:
    get_sample(conn, sample_id)
    with transaction(conn):
        active = conn.execute(
            f"SELECT id FROM jobs WHERE sample_id = ? AND status IN {ACTIVE_JOB_STATES}", (sample_id,)).fetchone()
        if active:
            raise Conflict("an analysis for this sample is already queued or running", existing_id=active["id"])
        cur = conn.execute("INSERT INTO jobs (sample_id, status, message, created_utc) VALUES (?, 'queued', ?, ?)",
                           (sample_id, "waiting for the worker", utcnow()))
        for stage in "ABCS":
            conn.execute("INSERT INTO job_stages (job_id, stage, status) VALUES (?, ?, 'queued')", (cur.lastrowid, stage))
    return get_job(conn, cur.lastrowid)


def get_job(conn: sqlite3.Connection, job_id: int) -> dict[str, Any]:
    row = row_dict(conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())
    if row is None:
        raise NotFound("analysis job not found")
    row.pop("results_json", None)
    row["stages"] = {r["stage"]: {"status": r["status"], "notes": loads(r["notes"], [])}
                     for r in conn.execute("SELECT * FROM job_stages WHERE job_id = ?", (job_id,))}
    row["inputs"] = [dict(r) for r in conn.execute(
        "SELECT ji.key, ji.sha256, ji.artifact_id, a.origin, a.tool_name, a.tool_version, a.original_name"
        " FROM job_inputs ji JOIN artifacts a ON a.id = ji.artifact_id WHERE ji.job_id = ? ORDER BY ji.key", (job_id,))]
    row["outputs"] = [dict(r) for r in conn.execute(
        "SELECT name, sha256 FROM job_outputs WHERE job_id = ? ORDER BY name", (job_id,))]
    row["tools"] = {r["tool"]: r["version"] for r in conn.execute(
        "SELECT tool, version FROM job_tools WHERE job_id = ?", (job_id,))}
    row["events"] = [dict(r) for r in conn.execute(
        "SELECT ts_utc, level, message FROM job_events WHERE job_id = ? ORDER BY id", (job_id,))]
    return row


def job_results(conn: sqlite3.Connection, job_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT results_json FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        raise NotFound("analysis job not found")
    return loads(row["results_json"])


def list_jobs(conn: sqlite3.Connection, sample_id: int | None = None) -> list[dict[str, Any]]:
    sql = ("SELECT j.id, j.sample_id, j.status, j.progress, j.message, j.error, j.created_utc, j.finished_utc,"
           " j.manifest_sha256, j.mapping_version, s.sha256, s.label, s.mode FROM jobs j JOIN samples s ON s.id = j.sample_id")
    args: tuple = ()
    if sample_id is not None:
        sql += " WHERE j.sample_id = ?"
        args = (sample_id,)
    return [dict(r) for r in conn.execute(sql + " ORDER BY j.id DESC", args)]


# ----------------------------------------------------------------------------- synthetic demo


def import_synthetic_demo(conn: sqlite3.Connection, settings: Settings) -> list[dict[str, Any]]:
    """Register the bundled SYNTHETIC fixtures as synthetic samples and queue their analyses.

    The fixture files are imported exactly as they are, with their recorded hashes checked.
    This never runs for empirical samples and is never used to fill a missing stage.
    """
    fixtures = PROJECT_ROOT / "fixtures"
    specs = json.loads((fixtures / "specs.json").read_text(encoding="utf-8"))
    out = []
    for spec in specs:
        existing = conn.execute("SELECT id FROM samples WHERE sha256 = ?", (spec["sha256"],)).fetchone()
        if existing:
            sample = get_sample(conn, existing["id"])
            if sample["mode"] != "synthetic":
                raise Conflict("a non-synthetic sample already uses a fixture hash")
        else:
            sample = create_sample(conn, settings, sha256=spec["sha256"], label=f"{spec['label']} (synthetic)",
                                   mode="synthetic", approval_id=None,
                                   source="bundled synthetic fixture (fictional; not a real sample)",
                                   retrieved="2026-10-27", note="SYNTHETIC demonstration data")
        for key, rel in spec["inputs"].items():
            data = (fixtures / rel).read_bytes()
            if sha256_bytes(data) != spec["input_sha256"][key]:
                raise ServiceError(f"fixture {rel} does not match its recorded hash; rerun tools/build_fixtures.py")
            try:
                ingest_json_bytes(conn, settings, sample, key, data, Path(rel).name, "fixture")
            except Conflict:
                pass
        try:
            job = enqueue_job(conn, sample["id"])
        except Conflict as exc:
            job = get_job(conn, exc.extra["existing_id"])
        out.append({"sample": get_sample(conn, sample["id"]), "job": job})
    return out


# ----------------------------------------------------------------------------- demo mode
#
# Demo samples are ordinary *synthetic* samples whose hash is fictional and whose
# evidence comes from pipeline/synthetic.py. They need no SHA-256, source record or
# approval from the user, and they can never be attached to an empirical sample:
# every demo file is marked "synthetic": true, which empirical samples reject.

DEMO_SOURCE = "VisibilityLab demo mode - fictional data generated by pipeline/synthetic.py"


def create_demo_sample(conn: sqlite3.Connection, settings: Settings, scenario: str,
                       label: str | None = None) -> dict[str, Any]:
    if scenario not in SCENARIOS:
        raise ServiceError(f"unknown demo scenario {scenario!r}; choose one of {list(SCENARIOS)}")
    sha = fake_sha(f"VisibilityLab demo sample {uuid.uuid4().hex} (fictional, not a real file)")
    n = conn.execute("SELECT COUNT(*) FROM samples WHERE demo_scenario IS NOT NULL").fetchone()[0] + 1
    sample = create_sample(
        conn, settings, sha256=sha, label=(label or "").strip() or f"Demo {n} ({scenario} recovery)",
        mode="synthetic", approval_id=None, source=DEMO_SOURCE,
        retrieved=dt.date.today().isoformat(),
        note="SYNTHETIC demo sample: the hash is fictional and no file exists for it.")
    with transaction(conn):
        conn.execute("UPDATE samples SET demo_scenario = ? WHERE id = ?", (scenario, sample["id"]))
    return get_sample(conn, sample["id"])


def _demo_sample(conn: sqlite3.Connection, sample_id: int) -> dict[str, Any]:
    sample = get_sample(conn, sample_id)
    if sample["mode"] != "synthetic" or not sample.get("demo_scenario"):
        raise Forbidden("the demo evidence kit exists only for demo samples; empirical evidence must come "
                        "from your own tools")
    return sample


def demo_kit_file(conn: sqlite3.Connection, sample_id: int, kind: str) -> tuple[str, bytes]:
    sample = _demo_sample(conn, sample_id)
    if kind not in KIT_ORDER:
        raise NotFound(f"no demo file for kind {kind!r}")
    files = scenario_files(sample["demo_scenario"], sample["sha256"], demo_payload_sha(sample["sha256"]))
    name, doc = files[kind]
    return name, dumps(doc)


def demo_kit(conn: sqlite3.Connection, sample_id: int) -> dict[str, Any]:
    sample = _demo_sample(conn, sample_id)
    current = current_artifacts(conn, sample_id)
    items = []
    for kind in KIT_ORDER:
        name, data = demo_kit_file(conn, sample_id, kind)
        sha = sha256_bytes(data)
        items.append({"kind": kind, "file_name": name, "sha256": sha, "size": len(data),
                      "attached": kind in current and current[kind]["sha256"] == sha})
    return {"scenario": sample["demo_scenario"], "description": SCENARIO_DESCRIPTIONS[sample["demo_scenario"]],
            "items": items}


def attach_demo_items(conn: sqlite3.Connection, settings: Settings, sample_id: int,
                      kinds: list[str] | None = None) -> dict[str, Any]:
    """Attach demo files through the normal validated ingest path. Already-attached files are skipped."""
    sample = _demo_sample(conn, sample_id)
    added, skipped = [], []
    for kind in kinds or list(KIT_ORDER):
        name, data = demo_kit_file(conn, sample_id, kind)
        try:
            added.append(ingest_json_bytes(conn, settings, sample, kind, data, name, "fixture"))
        except Conflict as exc:
            skipped.append({"kind": kind, "reason": exc.message})
    return {"added": added, "skipped": skipped}


def demo_scenarios() -> list[dict[str, str]]:
    return [{"name": s, "description": SCENARIO_DESCRIPTIONS[s]} for s in SCENARIOS]
