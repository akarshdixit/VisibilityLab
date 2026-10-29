"""End-to-end API + worker workflows, failure handling and exports."""

import io
import json
import zipfile

from webapp.backend import worker
from webapp.backend.__main__ import _is_loopback
from webapp.backend.db import connect

from .conftest import capa_doc, enable_fake_capa, make_pe, new_sample, recovery_doc, run_worker, sha, upload

S1 = sha(b"test-double sample one")
P1 = sha(b"test-double payload one")


def _job(client, sample_id):
    r = client.post(f"/api/samples/{sample_id}/jobs")
    assert r.status_code == 202, r.text
    return r.json()["id"]


def _evidence_sample(client, *, recovery=None, b=True, c=True, s=True):
    smp = new_sample(client, S1)
    sid = smp["id"]
    assert upload(client, sid, "A", capa_doc(S1, {"a1": ["T1055"], "a2": ["T1027"]})).status_code == 201
    if recovery is not None:
        assert upload(client, sid, "B_recovery", recovery).status_code == 201
    if b:
        assert upload(client, sid, "B", capa_doc(P1, {"b1": ["T1055", "T1112"]})).status_code == 201
    if c:
        assert upload(client, sid, "C", capa_doc(S1, {"c1": ["T1055"], "c2": ["T1112"], "c3": ["T1086"]})).status_code == 201
    if s:
        assert upload(client, sid, "S", json.dumps({"techniques": ["T1055"]}).encode()).status_code == 201
    return sid


def test_synthetic_demo_through_api_and_worker(client, settings):
    r = client.post("/api/demo/synthetic")
    assert r.status_code == 201 and len(r.json()) == 2
    assert run_worker(settings) == [1, 2]
    j1, j2 = client.get("/api/jobs/1").json(), client.get("/api/jobs/2").json()
    assert j1["status"] == "complete" and {k: v["status"] for k, v in j1["stages"].items()} == \
        {"A": "complete", "B": "complete", "C": "complete", "S": "complete"}
    res = client.get("/api/jobs/1/results").json()
    assert res["synthetic"] is True and res["measures"]["QA"] == 0.75 and res["measures"]["IB"] == 0.6
    assert res["measure_inputs"]["QA"] == {"numerator": 3, "denominator": 4}
    assert j1["mapping_version"].startswith("Synthetic mapping") and j1["tools"]["pipeline"]
    assert j2["stages"]["B"]["status"] == "not_recovered"
    assert client.get("/api/jobs/2/results").json()["measures"]["VB"] == "n/d"
    assert client.post("/api/jobs/1/verify").json() == {"ok": True, "problems": []}
    report = client.get("/api/jobs/1/files/report.html").text
    assert "SYNTHETIC RUN" in report and "not ground truth" in report
    refs = client.get("/api/evidence").json()
    assert {(e["technique"], e["label"]) for e in refs if e["kind"] == "residual"} >= {("T1112", "P"), ("T1620", "K")}


def test_existing_evidence_workflow_with_official_mapping(client, settings):
    sid = _evidence_sample(client, recovery=recovery_doc(S1, P1))
    job_id = _job(client, sid)
    run_worker(settings)
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "complete", job
    assert job["mapping_version"] == "ATT&CK Enterprise v20.0" and len(job["mapping_sha256"]) == 64
    res = client.get(f"/api/jobs/{job_id}/results").json()
    assert res["synthetic"] is False and res["approval_id"]
    assert "T1059.001" in res["sets"]["C"]  # revoked T1086 replaced using the official v20.0 table
    assert res["measures"]["VB"] == round(2 / 3, 4) and res["measure_inputs"]["VB"] == {"numerator": 2, "denominator": 3}
    audit = client.get(f"/api/jobs/{job_id}/audit").json()["normalization_audit"]
    assert any(r["raw_id"] == "T1086" and r["status"] == "revoked_replaced" for r in audit)
    assert "EMPIRICAL RUN" in client.get(f"/api/jobs/{job_id}/files/report.html").text


def test_failed_recovery_keeps_sample_with_nd_measures(client, settings):
    sid = _evidence_sample(client, recovery=recovery_doc(S1, P1, v4_errors=2, used=25, limit=20))
    job_id = _job(client, sid)
    run_worker(settings)
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "complete" and job["stages"]["B"]["status"] == "not_recovered"
    assert any("budget exceeded (25 > 20)" in n for n in job["stages"]["B"]["notes"])
    m = client.get(f"/api/jobs/{job_id}/results").json()["measures"]
    assert m["VA"] == round(1 / 3, 4) and all(m[k] == "n/d" for k in ("QA", "VB", "DB", "IB", "G", "L", "M", "O"))


def test_missing_stage_b_and_absent_cape_report_await_input(client, settings):
    sid = _evidence_sample(client, recovery=None, b=False, c=False, s=False)
    job_id = _job(client, sid)
    run_worker(settings)
    job = client.get(f"/api/jobs/{job_id}").json()
    st = {k: v["status"] for k, v in job["stages"].items()}
    assert st == {"A": "complete", "B": "awaiting_input", "C": "awaiting_input", "S": "awaiting_input"}
    m = client.get(f"/api/jobs/{job_id}/results").json()["measures"]
    assert set(m.values()) == {"n/d"}  # nothing substituted, nothing reported as zero


def test_accepted_recovery_without_payload_report_awaits_input(client, settings):
    sid = _evidence_sample(client, recovery=recovery_doc(S1, P1), b=False)
    job_id = _job(client, sid)
    run_worker(settings)
    assert client.get(f"/api/jobs/{job_id}").json()["stages"]["B"]["status"] == "awaiting_input"


def test_payload_report_without_recovery_record_is_refused(client, settings):
    sid = _evidence_sample(client, recovery=None, b=True)
    job_id = _job(client, sid)
    run_worker(settings)
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "failed" and job["error"].startswith("REFUSED:") and "recovery record" in job["error"]
    assert client.get(f"/api/jobs/{job_id}/results").status_code == 409


def test_tampered_evidence_fails_the_hash_gate(client, settings):
    sid = _evidence_sample(client, recovery=None, b=False)
    conn = connect(settings.db_path)
    name = conn.execute("SELECT storage_name FROM artifacts WHERE kind = 'C'").fetchone()[0]
    path = settings.data_dir / name
    path.chmod(0o666)
    path.write_bytes(path.read_bytes().replace(b"T1112", b"T1113"))
    job_id = _job(client, sid)
    run_worker(settings)
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "failed" and "integrity" in job["error"] and "SHA-256" in job["error"]


def test_duplicate_submission_and_interrupted_jobs(client, settings):
    sid = _evidence_sample(client, recovery=None, b=False)
    job_id = _job(client, sid)
    r = client.post(f"/api/samples/{sid}/jobs")
    assert r.status_code == 409 and r.json()["existing_id"] == job_id
    conn = connect(settings.db_path)
    assert worker.claim_next(conn, "test-worker") == job_id  # worker "crashes" after claiming
    assert worker.recover_interrupted(conn) == 1
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "interrupted" and "resubmit" in job["error"]
    new_id = _job(client, sid)  # resubmission is allowed again
    assert run_worker(settings) == [new_id]


def test_capa_tool_workflow_with_test_double(client, settings):
    enable_fake_capa(settings)
    pe = make_pe(b"sample")
    payload = make_pe(b"PAYLOAD")
    smp = new_sample(client, sha(pe))
    sid = smp["id"]
    assert upload(client, sid, "sample_pe", pe, "s.exe").status_code == 201
    assert upload(client, sid, "B_recovery", recovery_doc(sha(pe), sha(payload))).status_code == 201
    assert upload(client, sid, "payload_pe", payload, "p.bin").status_code == 201
    cape = {"target": {"file": {"sha256": sha(pe)}}, "ttps": [{"signature": "x", "ttps": ["T1055", "T1486"]}]}
    assert upload(client, sid, "cape_report", json.dumps(cape).encode()).status_code == 201
    job_id = _job(client, sid)
    run_worker(settings)
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "complete", job
    assert {k: v["status"] for k, v in job["stages"].items()} == dict.fromkeys("ABCS", "complete")
    assert job["tools"]["capa"] == "9.9.9-test-double"
    origins = {i["key"]: (i["origin"], i["tool_version"]) for i in job["inputs"]}
    assert origins["A"] == ("tool", "9.9.9-test-double") and origins["S"][0] == "derived"
    res = client.get(f"/api/jobs/{job_id}/results").json()
    assert res["sets"]["S"] == ["T1055", "T1486"] and res["secondary"]["S_overlap_C"] == 1
    assert res["measures"]["VB"] == 1.0 and res["measures"]["G"] == 1


def test_capa_unavailable_mismatched_disabled_or_failing(client, settings):
    settings.allow_sample_upload = True
    pe = make_pe(b"FAIL")
    sid = new_sample(client, sha(pe))["id"]
    assert upload(client, sid, "sample_pe", pe).status_code == 201

    def stage_a():
        job_id = _job(client, sid)
        run_worker(settings)
        return client.get(f"/api/jobs/{job_id}").json()["stages"]["A"]

    a = stage_a()  # capa not configured at all
    assert a["status"] == "awaiting_input" and "disabled" in a["notes"][0]
    enable_fake_capa(settings)
    settings.isolation_ack = ""  # configured, but the operator has not confirmed an isolated VM
    assert stage_a()["status"] == "awaiting_input"
    enable_fake_capa(settings)
    settings.capa_expected_version = "7.4.0"  # pinned version differs from the tool
    a = stage_a()
    assert a["status"] == "awaiting_input" and "version mismatch" in a["notes"][0]
    enable_fake_capa(settings)
    a = stage_a()  # the tool runs and fails (b"FAIL" in the test file)
    assert a["status"] == "failed" and "exited with code 1" in a["notes"][0]


def test_exports_and_result_file_allowlist(client, settings):
    client.post("/api/demo/synthetic")
    assert client.get("/api/jobs/1/results").status_code == 409  # not complete yet
    run_worker(settings)
    for name in ("results.json", "normalization_audit.csv", "residual_classification.csv",
                 "gain_attribution.csv", "manifest.json", "summary_metrics.csv"):
        assert client.get(f"/api/jobs/1/files/{name}").status_code == 200, name
    assert client.get("/api/jobs/1/files/..%2F..%2Fvisibilitylab.sqlite3").status_code == 404
    assert client.get("/api/jobs/1/files/specs.json").status_code == 404
    z = zipfile.ZipFile(io.BytesIO(client.get("/api/jobs/1/export.zip").content))
    assert any(n.endswith("/manifest.json") for n in z.namelist()) and "summary_metrics.csv" in z.namelist()
    summary = client.get("/api/export/summary.csv").text.splitlines()
    assert summary[0].startswith("job_id,sample_sha256") and len(summary) == 3


def test_api_meta_endpoints_and_loopback_guard(client):
    assert client.get("/api/health").json()["schema_version"] >= 1
    st = client.get("/api/settings").json()
    assert st["safety"]["pe_analysis_allowed"] is False and st["capa"]["configured"] is False
    assert st["mapping"]["empirical"]["provenance"]["attack_version"] == "20.0"
    assert client.get("/api/samples/999").status_code == 404
    assert _is_loopback("127.0.0.1") and _is_loopback("localhost") and not _is_loopback("0.0.0.0")
