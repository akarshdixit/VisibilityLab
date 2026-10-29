"""Demo mode: a fully synthetic workflow that needs no SHA-256, source record or approval,
kept strictly apart from the empirical workflow."""

import json
import sqlite3

import pytest

from pipeline.synthetic import KIT_ORDER, SCENARIOS, demo_payload_sha, dumps, fake_sha, scenario_files
from webapp.backend.db import MIGRATIONS, connect, migrate

from .conftest import APPROVAL, new_sample, run_worker, sha, upload

GUIDE = {"QA": 0.75, "VA": 0.4, "VB": 0.4, "DB": 0.0, "IB": 0.6, "G": 1, "L": 0, "M": 2, "O": 2}


def _demo(client, scenario="accepted", **body):
    r = client.post("/api/demo/samples", json={"scenario": scenario, **body})
    assert r.status_code == 201, r.text
    return r.json()


def _run(client, settings, sample_id):
    r = client.post(f"/api/samples/{sample_id}/jobs")
    assert r.status_code == 202, r.text
    run_worker(settings)
    return client.get(f"/api/jobs/{r.json()['id']}").json()


def test_demo_sample_needs_no_empirical_fields_and_is_labelled_synthetic(client):
    s = _demo(client)  # no sha256, source, retrieval date or approval supplied
    assert s["mode"] == "synthetic" and s["approval_id"] is None and s["demo_scenario"] == "accepted"
    assert "demo mode" in s["source"] and "fictional" in s["note"]
    assert len(s["sha256"]) == 64
    other = _demo(client, label="my demo")
    assert other["sha256"] != s["sha256"] and other["label"] == "my demo"  # fresh fictional hash each time
    assert client.get("/api/demo/scenarios").json()[0]["name"] in SCENARIOS


def test_demo_accepted_scenario_runs_end_to_end_with_guide_values(client, settings):
    s = _demo(client)
    kit = client.get(f"/api/samples/{s['id']}/demo-kit").json()
    assert [i["kind"] for i in kit["items"]] == list(KIT_ORDER) and not any(i["attached"] for i in kit["items"])
    r = client.post(f"/api/samples/{s['id']}/demo-kit")
    assert r.status_code == 201 and len(r.json()["added"]) == 6
    assert all(i["attached"] for i in client.get(f"/api/samples/{s['id']}/demo-kit").json()["items"])
    job = _run(client, settings, s["id"])
    assert job["status"] == "complete" and job["mapping_version"].startswith("Synthetic mapping")
    res = client.get(f"/api/jobs/{job['id']}/results").json()
    assert res["synthetic"] is True and "SYNTHETIC" in res["notice"]
    assert res["measures"] == GUIDE and res["residual_classification"]["pk_summary"] == "P=1, K=1 (P+K=2)"
    assert "SYNTHETIC RUN" in client.get(f"/api/jobs/{job['id']}/files/report.html").text
    assert client.post(f"/api/jobs/{job['id']}/verify").json()["ok"] is True


def test_demo_rejected_scenario_keeps_failed_recovery_with_nd(client, settings):
    s = _demo(client, "rejected")
    client.post(f"/api/samples/{s['id']}/demo-kit")
    job = _run(client, settings, s["id"])
    assert job["stages"]["B"]["status"] == "not_recovered"
    m = client.get(f"/api/jobs/{job['id']}/results").json()["measures"]
    assert m["VA"] == 0.4 and all(m[k] == "n/d" for k in ("QA", "VB", "DB", "IB", "G", "L", "M", "O"))


def test_demo_step_by_step_shows_awaiting_input_for_missing_stages(client, settings):
    s = _demo(client)
    for kind in ("A", "C"):
        assert client.post(f"/api/samples/{s['id']}/demo-kit/{kind}").status_code == 201
    again = client.post(f"/api/samples/{s['id']}/demo-kit/A").json()
    assert again["added"] == [] and "already submitted" in again["skipped"][0]["reason"]
    job = _run(client, settings, s["id"])
    st = {k: v["status"] for k, v in job["stages"].items()}
    assert st == {"A": "complete", "B": "awaiting_input", "C": "complete", "S": "awaiting_input"}
    m = client.get(f"/api/jobs/{job['id']}/results").json()["measures"]
    assert m["VA"] == 0.4 and m["QA"] == "n/d"  # nothing filled in for the missing stages


def test_downloaded_demo_files_work_through_the_normal_upload_path(client, settings):
    s = _demo(client)
    for kind in KIT_ORDER:
        r = client.get(f"/api/samples/{s['id']}/demo-kit/{kind}/download")
        assert r.status_code == 200 and json.loads(r.content)["synthetic"] is True
        assert "SYNTHETIC-" in r.headers["content-disposition"]
        assert upload(client, s["id"], kind, r.content, f"{kind}.json").status_code == 201
    assert _run(client, settings, s["id"])["status"] == "complete"


def test_demo_kit_is_unavailable_to_empirical_and_fixture_samples(client):
    emp = new_sample(client, sha(b"empirical test double"))
    for call in (client.get(f"/api/samples/{emp['id']}/demo-kit"),
                 client.post(f"/api/samples/{emp['id']}/demo-kit"),
                 client.post(f"/api/samples/{emp['id']}/demo-kit/A"),
                 client.get(f"/api/samples/{emp['id']}/demo-kit/A/download")):
        assert call.status_code == 403
    assert client.get(f"/api/samples/{emp['id']}").json()["artifacts"] == []
    client.post("/api/demo/synthetic")  # the original bundled demo still works...
    fixture_sample = client.get("/api/samples").json()[-1]
    assert client.get(f"/api/samples/{fixture_sample['id']}/demo-kit").status_code == 403  # ...but has no kit
    s = _demo(client)
    assert client.post(f"/api/samples/{s['id']}/demo-kit/exe").status_code == 404
    assert client.post("/api/demo/samples", json={"scenario": "made-up"}).status_code == 422


def test_demo_files_cannot_be_attached_to_an_empirical_sample(client):
    s = _demo(client)
    data = client.get(f"/api/samples/{s['id']}/demo-kit/A/download").content
    emp = new_sample(client, s["sha256"][::-1].replace("x", "0"))
    r = upload(client, emp["id"], "A", data)
    assert r.status_code == 400 and "marked synthetic" in r.json()["detail"]


@pytest.mark.parametrize("approval", [None, "", "  ", "N/A", "tbd", "demo", "Pending", "test"])
def test_empirical_mode_still_requires_a_real_looking_approval_reference(client, approval):
    r = client.post("/api/samples", json={"sha256": sha(b"x"), "mode": "empirical", "approval_id": approval,
                                          "source": "s", "retrieved": "2026-10-27"})
    assert r.status_code == 403 and "Gate 3" in r.json()["detail"]


def test_empirical_mode_still_requires_hash_source_and_date(client):
    base = {"mode": "empirical", "approval_id": APPROVAL, "source": "documented source", "retrieved": "2026-10-27"}
    assert client.post("/api/samples", json={**base}).status_code == 422  # no sha256
    assert client.post("/api/samples", json={**base, "sha256": "z" * 64}).status_code == 400
    assert client.post("/api/samples", json={**base, "sha256": sha(b"y"), "source": ""}).status_code == 422
    assert client.post("/api/samples", json={**base, "sha256": sha(b"y"), "retrieved": "yesterday"}).status_code == 422
    assert client.post("/api/samples", json={**base, "sha256": sha(b"y")}).status_code == 201
    syn = client.post("/api/samples", json={**base, "sha256": sha(b"z"), "mode": "synthetic"})
    assert syn.status_code == 400  # synthetic samples never carry an approval reference


def test_scenario_builder_reproduces_the_bundled_fixtures_byte_for_byte():
    from webapp.backend.config import PROJECT_ROOT

    fixtures = PROJECT_ROOT / "fixtures"
    specs = json.loads((fixtures / "specs.json").read_text(encoding="utf-8"))
    for spec, scenario, tag in ((specs[0], "accepted", "SYNTH-001"), (specs[1], "rejected", "SYNTH-002")):
        payload = fake_sha(f"{tag} fictional recovered payload (not a real file)")
        files = scenario_files(scenario, spec["sha256"], payload)
        for kind, (_, doc) in files.items():
            assert sha(dumps(doc)) == spec["input_sha256"][kind], (scenario, kind)
    assert demo_payload_sha("a" * 64) != demo_payload_sha("b" * 64)


def test_migration_2_upgrades_an_existing_version_1_database(tmp_path):
    path = tmp_path / "old.sqlite3"
    conn = connect(path)
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, description TEXT NOT NULL,"
                 " applied_utc TEXT NOT NULL)")
    version, desc, sql = MIGRATIONS[0]
    for stmt in (x.strip() for x in sql.split(";")):
        if stmt:
            conn.execute(stmt)
    conn.execute("INSERT INTO schema_migrations VALUES (1, ?, 'then')", (desc,))
    conn.execute("INSERT INTO samples (sha256, mode, source, retrieved, created_utc) "
                 "VALUES (?, 'synthetic', 's', '2026-10-27', 'then')", ("c" * 64,))
    assert migrate(conn) == 2
    row = conn.execute("SELECT sha256, demo_scenario FROM samples").fetchone()
    assert row["sha256"] == "c" * 64 and row["demo_scenario"] is None  # existing data preserved
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE samples SET demo_scenario = 'invented'")
