"""VisibilityLab HTTP API (FastAPI). The API never runs analysis itself; it records requests
and the separate worker process does the work."""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
import zipfile
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from pipeline import __version__ as PIPELINE_VERSION
from pipeline.classify import CLASSES
from pipeline.manifest import verify_manifest
from pipeline.metrics import DEFINITIONS, MEASURES
from pipeline.run import SUMMARY_COLUMNS

from . import capa_runner, services, storage
from .config import ISOLATION_ACK_PHRASE, PROJECT_ROOT, Settings
from .db import connect, migrate, schema_version
from .validation import BINARY_KINDS, JSON_KINDS, KIND_LABELS

log = logging.getLogger("visibilitylab")
RESULT_FILES = ("results.json", "normalization_audit.csv", "residual_classification.csv",
                "gain_attribution.csv", "manifest.json", "report.html")


# ----------------------------------------------------------------------------- models


class SampleCreate(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)
    label: str = Field(default="", max_length=120)
    mode: Literal["synthetic", "empirical"] = "empirical"
    approval_id: str | None = Field(default=None, max_length=200)
    source: str = Field(min_length=1, max_length=500)
    retrieved: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    packer_label: str = Field(default="", max_length=120)
    note: str = Field(default="", max_length=2000)


class Sample(BaseModel):
    id: int
    sha256: str
    label: str
    mode: str
    approval_id: str | None
    source: str
    retrieved: str
    packer_label: str
    note: str
    file_stored: bool
    file_size: int | None
    pe_meta: dict[str, Any] | None
    created_utc: str
    last_job_id: int | None = None
    last_job_status: str | None = None
    artifact_count: int | None = None
    demo_scenario: str | None = None


class DemoSampleCreate(BaseModel):
    scenario: Literal["accepted", "rejected"] = "accepted"
    label: str = Field(default="", max_length=120)


class Artifact(BaseModel):
    id: int
    sample_id: int
    kind: str
    origin: str
    sha256: str
    size: int
    original_name: str
    tool_name: str | None
    tool_version: str | None
    derived_from: int | None
    superseded: bool
    created_utc: str


class StageState(BaseModel):
    status: str
    notes: list[str]


class Job(BaseModel):
    id: int
    sample_id: int
    status: str
    progress: int
    message: str
    error: str | None
    created_utc: str
    started_utc: str | None
    finished_utc: str | None
    manifest_sha256: str | None
    mapping_name: str | None
    mapping_version: str | None
    mapping_sha256: str | None
    pipeline_version: str | None
    python_version: str | None
    stages: dict[str, StageState]
    inputs: list[dict[str, Any]]
    outputs: list[dict[str, Any]]
    tools: dict[str, str]
    events: list[dict[str, Any]]


class JobSummary(BaseModel):
    id: int
    sample_id: int
    status: str
    progress: int
    message: str
    error: str | None
    created_utc: str
    finished_utc: str | None
    manifest_sha256: str | None
    mapping_version: str | None
    sha256: str
    label: str
    mode: str


class SampleDetail(BaseModel):
    sample: Sample
    artifacts: list[Artifact]
    jobs: list[JobSummary]
    readiness: dict[str, str]


class VerifyResult(BaseModel):
    ok: bool
    problems: list[str]


# ----------------------------------------------------------------------------- app


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.ensure_dirs()
    boot = connect(settings.db_path)
    migrate(boot)
    boot.close()

    app = FastAPI(title="VisibilityLab API", version=PIPELINE_VERSION,
                  description="Quantifying Behavioral Visibility Loss Due to Malware Packing")
    app.state.settings = settings
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                       allow_methods=["GET", "POST"], allow_headers=["*"])

    max_request = max(settings.max_cape_bytes, settings.max_pe_bytes, settings.max_bundle_bytes) + (1 << 20)

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > max_request:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.exception_handler(services.ServiceError)
    async def service_error(_: Request, exc: services.ServiceError):
        return JSONResponse({"detail": exc.message, **exc.extra}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception):
        error_id = uuid.uuid4().hex[:10]
        log.exception("unhandled error %s", error_id)
        return JSONResponse({"detail": "internal error", "error_id": error_id}, status_code=500)

    def db():
        conn = connect(settings.db_path)
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------ meta

    @app.get("/api/health")
    def health(conn=Depends(db)) -> dict[str, Any]:
        return {"status": "ok", "pipeline_version": PIPELINE_VERSION, "schema_version": schema_version(conn)}

    @app.get("/api/settings")
    def get_settings() -> dict[str, Any]:
        capa = {"configured": settings.capa_path is not None, "path": str(settings.capa_path or ""),
                "expected_version": settings.capa_expected_version, "status": "not configured"}
        if settings.capa_path is not None:
            try:
                capa["status"] = f"ok (version {capa_runner.check_version(settings, settings.data_dir / 'tmp')})"
            except (capa_runner.ToolUnavailable, capa_runner.ToolFailed) as exc:
                capa["status"] = str(exc)
        prov_path = settings.attack_mapping.with_name(settings.attack_mapping.stem + ".provenance.json")
        provenance = json.loads(prov_path.read_text(encoding="utf-8")) if prov_path.exists() else None
        return {
            "pipeline_version": PIPELINE_VERSION,
            "data_dir": str(settings.data_dir),
            "bind": f"{settings.host}:{settings.port}",
            "limits_mb": {"json": settings.max_json_bytes >> 20, "cape_report": settings.max_cape_bytes >> 20,
                          "pe": settings.max_pe_bytes >> 20, "bundle": settings.max_bundle_bytes >> 20},
            "safety": {"allow_sample_upload": settings.allow_sample_upload,
                       "static_analysis_enabled": settings.static_analysis_enabled,
                       "isolation_acknowledged": settings.isolation_ack == ISOLATION_ACK_PHRASE,
                       "pe_analysis_allowed": settings.pe_analysis_allowed,
                       "dynamic_execution": "never performed by VisibilityLab; import CAPE reports produced in an isolated sandbox"},
            "capa": capa,
            "mapping": {"empirical": {"path": _rel(settings.attack_mapping), "version": settings.attack_mapping_version,
                                      "exists": settings.attack_mapping.exists(), "provenance": provenance},
                        "synthetic": {"path": _rel(settings.synthetic_mapping), "version": settings.synthetic_mapping_version}},
            "artifact_kinds": {k: KIND_LABELS[k] for k in JSON_KINDS + BINARY_KINDS},
            "measures": {k: DEFINITIONS[k] for k in (*MEASURES, "S_overlap_C")},
            "classes": CLASSES,
        }

    @app.get("/api/overview")
    def overview(conn=Depends(db)) -> dict[str, Any]:
        count = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
        return {
            "samples": count("SELECT COUNT(*) FROM samples"),
            "synthetic_samples": count("SELECT COUNT(*) FROM samples WHERE mode = 'synthetic'"),
            "empirical_samples": count("SELECT COUNT(*) FROM samples WHERE mode = 'empirical'"),
            "jobs": {r[0]: r[1] for r in conn.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status")},
            "recent_jobs": services.list_jobs(conn)[:8],
        }

    # ------------------------------------------------------------------ samples

    @app.get("/api/samples", response_model=list[Sample])
    def samples(conn=Depends(db)):
        return services.list_samples(conn)

    @app.post("/api/samples", response_model=Sample, status_code=201)
    def create(body: SampleCreate, conn=Depends(db)):
        return services.create_sample(conn, settings, **body.model_dump())

    @app.post("/api/samples/from-pe", response_model=Sample, status_code=201)
    def create_from_pe(file: UploadFile = File(...), label: str = Form(""), approval_id: str = Form(""),
                       source: str = Form(...), retrieved: str = Form(...), packer_label: str = Form(""),
                       note: str = Form(""), conn=Depends(db)):
        return services.create_sample_from_pe(conn, settings, file.file, file.filename or "", label=label,
                                              mode="empirical", approval_id=approval_id, source=source,
                                              retrieved=retrieved, packer_label=packer_label, note=note)

    @app.get("/api/samples/{sample_id}", response_model=SampleDetail)
    def sample_detail(sample_id: int, conn=Depends(db)):
        sample = services.get_sample(conn, sample_id)
        current = services.current_artifacts(conn, sample_id)
        return {"sample": sample, "artifacts": services.list_artifacts(conn, sample_id),
                "jobs": services.list_jobs(conn, sample_id), "readiness": _readiness(current, settings)}

    @app.post("/api/samples/{sample_id}/artifacts", response_model=Artifact, status_code=201)
    def upload_artifact(sample_id: int, kind: str = Form(...), file: UploadFile = File(...), conn=Depends(db)):
        return services.ingest_upload(conn, settings, sample_id, kind, file.file, file.filename or "")

    @app.post("/api/samples/{sample_id}/bundle", status_code=201)
    def upload_bundle(sample_id: int, file: UploadFile = File(...), conn=Depends(db)) -> dict[str, Any]:
        return services.ingest_bundle(conn, settings, sample_id, file.file)

    @app.post("/api/samples/{sample_id}/jobs", response_model=Job, status_code=202)
    def start_job(sample_id: int, conn=Depends(db)):
        return services.enqueue_job(conn, sample_id)

    @app.get("/api/artifacts/{artifact_id}/download")
    def download_artifact(artifact_id: int, conn=Depends(db)):
        row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        if row is None:
            raise services.NotFound("artifact not found")
        if row["kind"] in BINARY_KINDS:
            raise services.Forbidden("PE files are quarantined and are never served by VisibilityLab")
        path = storage.storage_path(settings.data_dir, row["storage_name"])
        return FileResponse(path, media_type="application/json",
                            filename=f"artifact-{row['id']}-{row['kind']}.json")

    # ------------------------------------------------------------------ jobs

    @app.get("/api/jobs", response_model=list[JobSummary])
    def jobs(conn=Depends(db)):
        return services.list_jobs(conn)

    @app.get("/api/jobs/{job_id}", response_model=Job)
    def job(job_id: int, conn=Depends(db)):
        return services.get_job(conn, job_id)

    @app.get("/api/jobs/{job_id}/results")
    def results(job_id: int, conn=Depends(db)) -> dict[str, Any]:
        res = services.job_results(conn, job_id)
        if res is None:
            raise services.Conflict("results are not available until the job completes")
        return res

    @app.get("/api/jobs/{job_id}/audit")
    def audit(job_id: int, conn=Depends(db)) -> dict[str, Any]:
        d = _result_dir(conn, settings, job_id)
        return {name.removesuffix(".csv"): _csv_rows(d / name)
                for name in ("normalization_audit.csv", "residual_classification.csv", "gain_attribution.csv")}

    @app.get("/api/jobs/{job_id}/files/{name}")
    def job_file(job_id: int, name: str, conn=Depends(db)):
        if name not in RESULT_FILES + ("summary_metrics.csv",):
            raise services.NotFound("unknown result file")
        d = _result_dir(conn, settings, job_id)
        path = (d.parent / name) if name == "summary_metrics.csv" else (d / name)
        if not path.exists():
            raise services.NotFound("file not produced for this job")
        media = {"json": "application/json", "csv": "text/csv", "html": "text/html"}[name.rsplit(".", 1)[1]]
        disposition = "inline" if name == "report.html" else "attachment"
        return FileResponse(path, media_type=media, filename=f"job{job_id}-{name}",
                            content_disposition_type=disposition)

    @app.get("/api/jobs/{job_id}/export.zip")
    def export_zip(job_id: int, conn=Depends(db)):
        d = _result_dir(conn, settings, job_id)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    zf.write(p, p.relative_to(d.parent).as_posix())
            zf.write(d.parent / "summary_metrics.csv", "summary_metrics.csv")
        return Response(buf.getvalue(), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="visibilitylab-job{job_id}.zip"'})

    @app.post("/api/jobs/{job_id}/verify", response_model=VerifyResult)
    def verify(job_id: int, conn=Depends(db)):
        problems = verify_manifest(_result_dir(conn, settings, job_id))
        return {"ok": not problems, "problems": problems}

    @app.get("/api/evidence")
    def evidence(conn=Depends(db)) -> list[dict[str, Any]]:
        return [dict(r) for r in conn.execute(
            "SELECT e.job_id, e.kind, e.technique, e.label, e.evidence_ref, e.reason, s.sha256, s.label AS sample_label,"
            " s.mode FROM evidence_refs e JOIN jobs j ON j.id = e.job_id JOIN samples s ON s.id = j.sample_id"
            " ORDER BY e.job_id DESC, e.kind, e.technique")]

    @app.get("/api/export/summary.csv")
    def summary_csv(conn=Depends(db)):
        rows = conn.execute(
            "SELECT j.id FROM jobs j WHERE j.status = 'complete' AND j.id = (SELECT MAX(j2.id) FROM jobs j2"
            " WHERE j2.sample_id = j.sample_id AND j2.status = 'complete') ORDER BY j.sample_id").fetchall()
        out = io.StringIO()
        w = csv.DictWriter(out, fieldnames=["job_id", *SUMMARY_COLUMNS], lineterminator="\n")
        w.writeheader()
        for r in rows:
            d = _result_dir(conn, settings, r["id"])
            for row in _csv_rows(d.parent / "summary_metrics.csv"):
                w.writerow({"job_id": r["id"], **row})
        return PlainTextResponse(out.getvalue(), media_type="text/csv",
                                 headers={"Content-Disposition": 'attachment; filename="summary_metrics.csv"'})

    # ------------------------------------------------------------------ demo

    @app.get("/api/demo/scenarios")
    def scenarios() -> list[dict[str, str]]:
        return services.demo_scenarios()

    @app.post("/api/demo/samples", response_model=Sample, status_code=201)
    def demo_sample(body: DemoSampleCreate, conn=Depends(db)):
        return services.create_demo_sample(conn, settings, body.scenario, body.label)

    @app.get("/api/samples/{sample_id}/demo-kit")
    def demo_kit(sample_id: int, conn=Depends(db)) -> dict[str, Any]:
        return services.demo_kit(conn, sample_id)

    @app.post("/api/samples/{sample_id}/demo-kit", status_code=201)
    def demo_kit_attach_all(sample_id: int, conn=Depends(db)) -> dict[str, Any]:
        return services.attach_demo_items(conn, settings, sample_id)

    @app.post("/api/samples/{sample_id}/demo-kit/{kind}", status_code=201)
    def demo_kit_attach(sample_id: int, kind: str, conn=Depends(db)) -> dict[str, Any]:
        services.demo_kit_file(conn, sample_id, kind)  # 403/404 before any write
        return services.attach_demo_items(conn, settings, sample_id, [kind])

    @app.get("/api/samples/{sample_id}/demo-kit/{kind}/download")
    def demo_kit_download(sample_id: int, kind: str, conn=Depends(db)):
        name, data = services.demo_kit_file(conn, sample_id, kind)
        return Response(data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="SYNTHETIC-{name}"'})

    @app.post("/api/demo/synthetic", status_code=201)
    def demo(conn=Depends(db)) -> list[dict[str, Any]]:
        return services.import_synthetic_demo(conn, settings)

    return app


def _rel(p: Path) -> str:
    try:
        return p.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(p)


def _readiness(arts: dict[str, Any], settings: Settings) -> dict[str, str]:
    capa = "capa configured" if settings.capa_path or settings.extra.get("capa_command") else "capa not configured"
    out = {}
    out["A"] = ("report imported" if "A" in arts else
                f"sample stored; {capa}" + ("" if settings.pe_analysis_allowed else " / PE analysis disabled")
                if "sample_pe" in arts else "awaiting input")
    if "B_recovery" not in arts:
        out["B"] = "awaiting recovery record" + (" (B report present but unusable without it)" if "B" in arts else "")
    elif "B" in arts:
        out["B"] = "recovery record + payload report imported (gate decides at run time)"
    elif "payload_pe" in arts:
        out["B"] = f"recovery record + payload stored; {capa}"
    else:
        out["B"] = "recovery record imported; awaiting payload report"
    out["C"] = ("report imported" if "C" in arts else f"CAPE report imported; {capa}"
                if "cape_report" in arts else "awaiting input")
    out["S"] = ("labels imported" if "S" in arts else "will be derived from the CAPE report"
                if "cape_report" in arts else "awaiting input")
    return out


def _result_dir(conn, settings: Settings, job_id: int) -> Path:
    row = conn.execute("SELECT status, result_dir FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        raise services.NotFound("analysis job not found")
    if row["status"] != "complete" or not row["result_dir"]:
        raise services.Conflict("results are not available until the job completes")
    d = (settings.data_dir / row["result_dir"]).resolve()
    if settings.data_dir.resolve() not in d.parents:
        raise services.Forbidden("result path outside the data directory")
    return d


def _csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))
