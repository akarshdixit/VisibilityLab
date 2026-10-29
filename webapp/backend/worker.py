"""Background worker: claims queued jobs from SQLite and runs the existing pipeline on them.

Run it as its own process (never inside the web server):

    python -m webapp.backend.worker            # poll forever
    python -m webapp.backend.worker --once     # process at most one job, then exit

For each job the worker:
 1. resolves the sample's current evidence artifacts;
 2. optionally produces missing A/B/C reports with the pinned capa (only if configured and allowed),
    and derives S from a CAPE report's own ATT&CK labels; otherwise the stage is "awaiting_input";
 3. copies the evidence into the job folder and writes a one-sample specs.json;
 4. calls pipeline.run.run_batch (hash gate, recovery gate, N1-N7, metrics, classification, manifest);
 5. records stages, inputs, outputs, tool and mapping versions and evidence references in SQLite.
Nothing is ever substituted: a missing stage stays missing and its measures are n/d.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import socket
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from pipeline import __version__ as PIPELINE_VERSION
from pipeline.classify import CLASSES
from pipeline.hashing import sha256_file
from pipeline.manifest import verify_manifest
from pipeline.normalize import MappingError, load_mapping
from pipeline.recovery import evaluate_recovery
from pipeline.report import write_sample_report
from pipeline.run import GateError, run_batch

from . import capa_runner, storage
from .config import Settings
from .db import add_event, connect, migrate, transaction, utcnow
from .services import ServiceError, current_artifacts, get_sample, ingest_json_bytes
from .validation import extract_cape_labels

PIPELINE_TO_APP = {"ok": "complete", "failed": "failed", "not_recovered": "not_recovered", "missing": "awaiting_input"}
RESULT_FILES = ("results.json", "normalization_audit.csv", "residual_classification.csv",
                "gain_attribution.csv", "manifest.json", "report.html")


def recover_interrupted(conn: sqlite3.Connection) -> int:
    """Mark jobs left 'running' by a stopped worker as interrupted (they can be resubmitted)."""
    with transaction(conn):
        ids = [r[0] for r in conn.execute("SELECT id FROM jobs WHERE status = 'running'")]
        for job_id in ids:
            conn.execute("UPDATE jobs SET status = 'interrupted', finished_utc = ?, message = ?,"
                         " error = ? WHERE id = ?",
                         (utcnow(), "interrupted", "the worker stopped before this job finished; resubmit it", job_id))
            conn.execute("UPDATE job_stages SET status = 'awaiting_input', notes = ? WHERE job_id = ? AND status IN"
                         " ('queued','running')", (json.dumps(["job interrupted"]), job_id))
            add_event(conn, job_id, "warning", "job marked interrupted at worker start-up")
    return len(ids)


def claim_next(conn: sqlite3.Connection, worker_id: str) -> int | None:
    with transaction(conn):
        row = conn.execute("SELECT id FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        conn.execute("UPDATE jobs SET status = 'running', worker_id = ?, started_utc = ?, heartbeat_utc = ?,"
                     " progress = 5, message = 'started' WHERE id = ? AND status = 'queued'",
                     (worker_id, utcnow(), utcnow(), row["id"]))
        add_event(conn, row["id"], "info", f"claimed by worker {worker_id}")
    return row["id"]


class _Job:
    def __init__(self, conn: sqlite3.Connection, job_id: int):
        self.conn, self.id = conn, job_id

    def progress(self, pct: int, message: str) -> None:
        with transaction(self.conn):
            self.conn.execute("UPDATE jobs SET progress = ?, message = ?, heartbeat_utc = ? WHERE id = ?",
                              (pct, message, utcnow(), self.id))
            add_event(self.conn, self.id, "info", message)

    def stage(self, stage: str, status: str, notes: list[str] | None = None) -> None:
        with transaction(self.conn):
            self.conn.execute("UPDATE job_stages SET status = ?, notes = ? WHERE job_id = ? AND stage = ?",
                              (status, json.dumps(notes or []), self.id, stage))

    def event(self, level: str, message: str) -> None:
        with transaction(self.conn):
            add_event(self.conn, self.id, level, message)


def _blob(settings: Settings, art: dict[str, Any]) -> Path:
    return storage.storage_path(settings.data_dir, art["storage_name"])


def _tool_artifact(job: _Job, settings: Settings, sample: dict, kind: str, src: dict, fmt: str,
                   workdir: Path, tools: dict[str, str]) -> tuple[dict | None, str, str]:
    """Produce a capa report for `kind` from artifact `src`. Returns (artifact | None, stage status, note)."""
    try:
        res = capa_runner.run_capa(settings, _blob(settings, src), fmt, workdir)
    except capa_runner.ToolUnavailable as exc:
        return None, "awaiting_input", str(exc)
    except capa_runner.ToolFailed as exc:
        job.event("error", f"capa for {kind}: {exc}")
        return None, "failed", str(exc)
    tools["capa"] = res.version
    try:
        art = ingest_json_bytes(job.conn, settings, sample, kind, res.stdout, f"capa-{kind}.json", "tool",
                                tool_name="capa", tool_version=res.version, derived_from=src["id"])
    except ServiceError as exc:
        if exc.status_code == 409:
            art = current_artifacts(job.conn, sample["id"])[kind]
        else:
            return None, "failed", f"capa output rejected: {exc.message}"
    job.event("info", f"capa {res.version} produced {kind} ({art['sha256'][:12]}...)")
    return art, "complete", f"produced by capa {res.version} from artifact #{src['id']}"


def process_job(conn: sqlite3.Connection, settings: Settings, job_id: int) -> None:
    job = _Job(conn, job_id)
    try:
        _process(job, settings)
    except Exception as exc:  # recorded, never swallowed silently
        msg = exc.message if isinstance(exc, ServiceError) else f"{type(exc).__name__}: {exc}"
        with transaction(conn):
            conn.execute("UPDATE jobs SET status = 'failed', error = ?, message = 'failed', finished_utc = ?,"
                         " heartbeat_utc = ? WHERE id = ?", (msg[:2000], utcnow(), utcnow(), job_id))
            conn.execute("UPDATE job_stages SET status = 'failed', notes = ? WHERE job_id = ? AND status IN"
                         " ('queued','running')", (json.dumps([msg[:500]]), job_id))
            add_event(conn, job_id, "error", msg)


def _process(job: _Job, settings: Settings) -> None:
    conn = job.conn
    job_row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job.id,)).fetchone()
    sample = get_sample(conn, job_row["sample_id"])
    synthetic = sample["mode"] == "synthetic"
    arts = current_artifacts(conn, sample["id"])
    workdir = storage.job_dir(settings.data_dir, job.id)
    if workdir.exists():
        shutil.rmtree(workdir)
    (workdir / "inputs").mkdir(parents=True)
    tools: dict[str, str] = {}
    notes: dict[str, list[str]] = {k: [] for k in "ABCS"}
    forced: dict[str, str] = {}  # app-level status overriding the pipeline's "missing"

    # Mapping: fictional table for synthetic runs, the official ATT&CK export for empirical runs.
    map_path = settings.synthetic_mapping if synthetic else settings.attack_mapping
    map_version = settings.synthetic_mapping_version if synthetic else settings.attack_mapping_version
    try:
        mapping = load_mapping(map_path, map_version)
    except MappingError as exc:
        raise ServiceError(f"ATT&CK mapping unavailable: {exc}") from None

    job.progress(15, "resolving Stage A")
    if "A" not in arts:
        if "sample_pe" in arts:
            job.stage("A", "running")
            art, status, note = _tool_artifact(job, settings, sample, "A", arts["sample_pe"], "pe", workdir, tools)
            if art:
                arts["A"] = art
            else:
                forced["A"] = status
            notes["A"].append(note)
        else:
            forced["A"] = "awaiting_input"
            notes["A"].append("no Stage A capa report and no stored sample to analyse")

    job.progress(30, "resolving Stage B")
    if "B_recovery" in arts and "B" not in arts:
        record = json.loads(_blob(settings, arts["B_recovery"]).read_text(encoding="utf-8"))
        gate = evaluate_recovery(record, sample["sha256"], "synthetic" if synthetic else "pilot")
        if gate.accepted and "payload_pe" in arts:
            if arts["payload_pe"]["sha256"] != gate.payload_sha256:
                forced["B"] = "awaiting_input"
                notes["B"].append("stored payload does not match payload_sha256 in the recovery record")
            else:
                job.stage("B", "running")
                art, status, note = _tool_artifact(job, settings, sample, "B", arts["payload_pe"], "pe", workdir, tools)
                if art:
                    arts["B"] = art
                else:
                    forced["B"] = status
                notes["B"].append(note)
        elif gate.accepted:
            forced["B"] = "awaiting_input"
            notes["B"].append("recovery accepted; attach the payload capa report (B) or the payload file")
    elif "B_recovery" not in arts and "B" not in arts:
        forced["B"] = "awaiting_input"
        notes["B"].append("no recovery record yet: recovery runs in the operator's separate, validated process")

    job.progress(45, "resolving Stage C and S")
    if "C" not in arts:
        if "cape_report" in arts:
            job.stage("C", "running")
            art, status, note = _tool_artifact(job, settings, sample, "C", arts["cape_report"], "cape", workdir, tools)
            if art:
                arts["C"] = art
            else:
                forced["C"] = status
            notes["C"].append(note)
        else:
            forced["C"] = "awaiting_input"
            notes["C"].append("no Stage C report: import capa dynamic output or a genuine CAPE report")
    if "S" not in arts:
        if "cape_report" in arts:
            report = json.loads(_blob(settings, arts["cape_report"]).read_text(encoding="utf-8"))
            labels = extract_cape_labels(report)
            if labels:
                doc = {"source": "sandbox-native ATT&CK labels extracted from the CAPE report 'ttps' section",
                       "derived_from_sha256": arts["cape_report"]["sha256"], "techniques": labels}
                if synthetic:
                    doc["synthetic"] = True
                data = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
                try:
                    arts["S"] = ingest_json_bytes(conn, settings, sample, "S", data, "S-from-cape.json", "derived",
                                                  derived_from=arts["cape_report"]["id"])
                except ServiceError as exc:
                    if exc.status_code != 409:
                        raise
                    arts["S"] = current_artifacts(conn, sample["id"])["S"]
                notes["S"].append("derived from the CAPE report's own labels")
            else:
                forced["S"] = "awaiting_input"
                notes["S"].append("CAPE report has no 'ttps' labels; import an S label list")
        else:
            forced["S"] = "awaiting_input"
            notes["S"].append("no sandbox label list (S) imported")

    # Assemble a one-sample spec over hash-recorded copies of the evidence.
    job.progress(60, "verifying evidence and running the pipeline")
    keys = [k for k in ("A", "B_recovery", "B", "C", "S", "evidence") if k in arts]
    inputs, hashes = {}, {}
    for k in keys:
        shutil.copyfile(_blob(settings, arts[k]), workdir / "inputs" / f"{k}.json")
        inputs[k], hashes[k] = f"inputs/{k}.json", arts[k]["sha256"]
    spec = {"sha256": sample["sha256"], "label": sample["label"],
            "mode": "synthetic" if synthetic else "pilot", "approval_id": sample["approval_id"],
            "inputs": inputs, "input_sha256": hashes}
    specs_path = workdir / "specs.json"
    specs_path.write_text(json.dumps([spec], indent=2), encoding="utf-8")
    try:
        rows = run_batch(specs_path, mapping, workdir / "results")
    except GateError as exc:
        raise ServiceError(f"REFUSED: {exc}") from None
    if rows[0]["run_status"] != "completed":
        raise ServiceError(f"integrity check failed: {rows[0]['note']}")

    sample_dir = workdir / "results" / sample["sha256"][:12]
    write_sample_report(sample_dir)
    results = json.loads((sample_dir / "results.json").read_text(encoding="utf-8"))
    manifest = json.loads((sample_dir / "manifest.json").read_text(encoding="utf-8"))
    problems = verify_manifest(sample_dir)

    job.progress(90, "recording results")
    tools.update({"pipeline": manifest["tool"]["pipeline"], "python": manifest["tool"]["python"]})
    with transaction(conn):
        for stage in "ABCS":
            status = PIPELINE_TO_APP[results["stages"][stage]["status"]]
            no_attempt = stage == "B" and "B_recovery" not in arts  # nothing to gate yet
            if stage in forced and (status == "awaiting_input" or no_attempt):
                status = forced[stage]
            conn.execute("UPDATE job_stages SET status = ?, notes = ? WHERE job_id = ? AND stage = ?",
                         (status, json.dumps(notes[stage] + results["stages"][stage]["notes"]), job.id, stage))
        for k in keys:
            conn.execute("INSERT INTO job_inputs (job_id, key, artifact_id, sha256) VALUES (?, ?, ?, ?)",
                         (job.id, k, arts[k]["id"], arts[k]["sha256"]))
        for name, sha in manifest["outputs"].items():
            conn.execute("INSERT INTO job_outputs (job_id, name, sha256) VALUES (?, ?, ?)", (job.id, name, sha))
        conn.execute("INSERT INTO job_outputs (job_id, name, sha256) VALUES (?, 'manifest.json', ?)",
                     (job.id, sha256_file(sample_dir / "manifest.json")))
        for tool, version in tools.items():
            conn.execute("INSERT INTO job_tools (job_id, tool, version) VALUES (?, ?, ?)", (job.id, tool, version))
        _record_refs(conn, job.id, sample_dir)
        conn.execute(
            "UPDATE jobs SET status = 'complete', progress = 100, message = ?, finished_utc = ?, heartbeat_utc = ?,"
            " result_dir = ?, manifest_sha256 = ?, mapping_name = ?, mapping_version = ?, mapping_sha256 = ?,"
            " pipeline_version = ?, python_version = ?, results_json = ? WHERE id = ?",
            ("complete" if not problems else "complete, but the seal check reported problems",
             utcnow(), utcnow(), str(sample_dir.relative_to(settings.data_dir)).replace("\\", "/"),
             manifest["manifest_sha256"], mapping.name, mapping.version, mapping.sha256,
             PIPELINE_VERSION, platform.python_version(), json.dumps(results), job.id))
        add_event(conn, job.id, "info" if not problems else "error",
                  "manifest verified: seal holds" if not problems else "seal problems: " + "; ".join(problems))


def _record_refs(conn: sqlite3.Connection, job_id: int, sample_dir: Path) -> None:
    import csv

    for name, kind, label_col in (("residual_classification.csv", "residual", "class"),
                                  ("gain_attribution.csv", "gain", "attribution")):
        with open(sample_dir / name, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                label = row[label_col]
                if kind == "residual" and label not in CLASSES:
                    continue
                conn.execute("INSERT INTO evidence_refs (job_id, kind, technique, label, evidence_ref, reason)"
                             " VALUES (?, ?, ?, ?, ?, ?)",
                             (job_id, kind, row["technique"], label, row["evidence_ref"], row["reason"]))


def run_once(settings: Settings, worker_id: str | None = None) -> int | None:
    conn = connect(settings.db_path)
    try:
        migrate(conn)
        job_id = claim_next(conn, worker_id or _worker_id())
        if job_id is not None:
            process_job(conn, settings, job_id)
        return job_id
    finally:
        conn.close()


def _worker_id() -> str:
    return f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m webapp.backend.worker")
    ap.add_argument("--once", action="store_true", help="process at most one job and exit")
    args = ap.parse_args(argv)
    settings = Settings.from_env()
    settings.ensure_dirs()
    conn = connect(settings.db_path)
    migrate(conn)
    n = recover_interrupted(conn)
    conn.close()
    wid = _worker_id()
    print(f"VisibilityLab worker {wid} | data {settings.data_dir} | interrupted jobs marked: {n}", flush=True)
    print(f"capa: {'configured' if settings.capa_path else 'not configured'} | "
          f"PE static analysis: {'ALLOWED' if settings.pe_analysis_allowed else 'disabled'}", flush=True)
    while True:
        job_id = run_once(settings, wid)
        if job_id is not None:
            print(f"processed job {job_id}", flush=True)
            if args.once:
                return 0
        elif args.once:
            print("no queued job", flush=True)
            return 0
        else:
            time.sleep(settings.worker_poll_s)


if __name__ == "__main__":
    sys.exit(main())
