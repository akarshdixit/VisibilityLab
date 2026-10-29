"""I/O, registry, manifest, CLI and end-to-end runs on synthetic fixtures."""

import csv
import json
from pathlib import Path

import pytest

from pipeline.__main__ import main
from pipeline.capa_io import ReportFormatError, parse_json_bytes, techniques_from_capa, techniques_from_labels
from pipeline.manifest import verify_manifest
from pipeline.registry import RegistryError, add_candidate, read_register
from pipeline.run import GateError, run_batch

from .conftest import read_specs, rewrite_input, write_specs

HASH = "AB" * 32

# ----------------------------------------------------------------------------- capa_io


def test_capa_reader_maps_ids_to_rules_and_skips_unmapped_rules():
    doc = {"rules": {
        "r1": {"meta": {"attack": [{"id": "T1055"}, {"id": "T1027"}]}},
        "r2": {"meta": {"attack": [{"id": "T1055"}]}},
        "r3": {"meta": {}},
    }}
    assert techniques_from_capa(doc) == {"T1027": ["r1"], "T1055": ["r1", "r2"]}


def test_capa_reader_rejects_missing_rules_and_bad_entries():
    with pytest.raises(ReportFormatError, match="missing 'rules'"):
        techniques_from_capa({"meta": {}})
    with pytest.raises(ReportFormatError, match="without an 'id'"):
        techniques_from_capa({"rules": {"r": {"meta": {"attack": [{"technique": "x"}]}}}})


def test_malformed_json_is_rejected_not_read_as_empty():
    with pytest.raises(ReportFormatError, match="malformed JSON"):
        parse_json_bytes(b'{"rules": {', "A")


def test_label_reader_needs_techniques_list():
    assert techniques_from_labels({"techniques": ["T1055"]}) == {"T1055": ["sandbox_label"]}
    with pytest.raises(ReportFormatError, match="techniques"):
        techniques_from_labels({"labels": ["T1055"]})


# ----------------------------------------------------------------------------- registry


def test_registry_adds_lowercased_candidate(tmp_path):
    f = tmp_path / "register.csv"
    row = add_candidate(f, HASH, "synthetic test", "2026-10-27", packer_label="UPX?")
    assert row["sha256"] == HASH.lower() and row["status"] == "candidate"
    assert read_register(f) == [row]


@pytest.mark.parametrize(
    "sha, source, date, message",
    [
        ("abc", "src", "2026-10-27", "64 hex"),
        (HASH, "   ", "2026-10-27", "non-empty"),
        (HASH, "src", "27/10/2026", "YYYY-MM-DD"),
        (HASH, "src", "2026-02-30", "not a real date"),
    ],
)
def test_registry_rules(tmp_path, sha, source, date, message):
    with pytest.raises(RegistryError, match=message):
        add_candidate(tmp_path / "r.csv", sha, source, date)


def test_registry_rejects_duplicate_hash(tmp_path):
    f = tmp_path / "r.csv"
    add_candidate(f, HASH, "src", "2026-10-27")
    with pytest.raises(RegistryError, match="already"):
        add_candidate(f, HASH.lower(), "src2", "2026-10-28")


# ----------------------------------------------------------------------------- end to end


def _results(out: Path, sha: str) -> dict:
    return json.loads((out / sha[:12] / "results.json").read_text(encoding="utf-8"))


def test_sample1_end_to_end_reproduces_worked_example(fx, mapping, tmp_path):
    out = tmp_path / "out"
    rows = run_batch(fx / "specs.json", mapping, out)
    sha = read_specs(fx)[0]["sha256"]
    res = _results(out, sha)
    assert res["synthetic"] is True and "SYNTHETIC" in res["notice"]
    assert res["measures"] == {"QA": 0.75, "VA": 0.4, "VB": 0.4, "DB": 0.0, "IB": 0.6,
                               "G": 1, "L": 0, "M": 2, "O": 2}
    assert res["secondary"]["S_overlap_C"] == 1
    assert res["sets"]["B"] == ["T1027", "T1055", "T1082", "T1497"]  # T0001 -> T1027
    assert res["residual_classification"]["pk_summary"] == "P=1, K=1 (P+K=2)"
    assert res["residual_classification"]["class_counts"]["U"] == 1

    d = out / sha[:12]
    for name in ("results.json", "normalization_audit.csv", "residual_classification.csv",
                 "gain_attribution.csv", "manifest.json", "raw/A.json", "raw/B.json", "raw/C.json",
                 "raw/S.json", "raw/B_recovery.json", "raw/evidence.json"):
        assert (d / name).exists(), name
    audit = list(csv.DictReader(open(d / "normalization_audit.csv", encoding="utf-8")))
    status = {(r["stage"], r["raw_id"]): r["status"] for r in audit}
    assert status[("B", "T0001")] == "revoked_replaced" and status[("C", "T9998")] == "unmapped"
    assert rows[0]["run_status"] == "completed" and (out / "summary_metrics.csv").exists()


def test_sample2_gate_rejects_and_b_measures_are_nd(fx, mapping, tmp_path):
    out = tmp_path / "out"
    run_batch(fx / "specs.json", mapping, out)
    res = _results(out, read_specs(fx)[1]["sha256"])
    assert res["stages"]["B"]["status"] == "not_recovered"
    assert "budget exceeded (25 > 20)" in res["recovery_gate"]["reasons"]
    assert any(r.startswith("V4 not passed") for r in res["recovery_gate"]["reasons"])
    assert res["sets"]["B"] == "n/d"  # B file present, but never used
    assert res["measures"]["VA"] == 0.4
    assert all(res["measures"][k] == "n/d" for k in ("QA", "VB", "DB", "IB", "G", "L", "M", "O"))
    assert res["residual_classification"]["status"] == "n/d"


def test_manifest_is_deterministic_and_detects_tampering(fx, mapping, tmp_path):
    run_batch(fx / "specs.json", mapping, tmp_path / "run1")
    run_batch(fx / "specs.json", mapping, tmp_path / "run2")
    for sha in (s["sha256"][:12] for s in read_specs(fx)):
        m1 = json.loads((tmp_path / "run1" / sha / "manifest.json").read_text(encoding="utf-8"))
        m2 = json.loads((tmp_path / "run2" / sha / "manifest.json").read_text(encoding="utf-8"))
        assert m1["manifest_sha256"] == m2["manifest_sha256"]
        assert m1["mapping"]["version"] == "Synthetic mapping v1" and len(m1["mapping"]["sha256"]) == 64
        assert verify_manifest(tmp_path / "run1" / sha) == []
    victim = tmp_path / "run1" / read_specs(fx)[0]["sha256"][:12]
    (victim / "results.json").write_text("{}", encoding="utf-8")
    assert verify_manifest(victim) == ["output changed since sealing: results.json"]


def test_gate3_pilot_without_approval_refuses_whole_run(fx, mapping, tmp_path, capsys):
    specs = read_specs(fx)
    specs[0]["mode"] = "pilot"
    write_specs(fx, specs)
    with pytest.raises(GateError, match="Gate 3"):
        run_batch(fx / "specs.json", mapping, tmp_path / "out")
    assert not (tmp_path / "out").exists()  # refused before anything was written
    code = main(["run", "--specs", str(fx / "specs.json"), "--mapping", str(fx / "attack_map.csv"),
                 "--mapping-version", "v", "--out", str(tmp_path / "out")])
    assert code == 2 and "REFUSED:" in capsys.readouterr().err


def test_payload_without_recovery_record_is_refused(fx, mapping, tmp_path):
    specs = read_specs(fx)
    del specs[0]["inputs"]["B_recovery"], specs[0]["input_sha256"]["B_recovery"]
    write_specs(fx, specs)
    with pytest.raises(GateError, match="without a recovery record"):
        run_batch(fx / "specs.json", mapping, tmp_path / "out")


def test_changed_input_aborts_only_that_sample(fx, mapping, tmp_path):
    specs = read_specs(fx)
    rewrite_input(fx, specs[0], "C", {"synthetic": True, "rules": {}}, rehash=False)
    rows = run_batch(fx / "specs.json", mapping, tmp_path / "out")
    assert rows[0]["run_status"] == "aborted_integrity" and "SHA-256 is" in rows[0]["note"]
    assert not (tmp_path / "out" / specs[0]["sha256"][:12]).exists()
    assert rows[1]["run_status"] == "completed"


def test_malformed_report_is_a_failed_stage_not_an_empty_one(fx, mapping, tmp_path):
    specs = read_specs(fx)
    rewrite_input(fx, specs[0], "A", '{"synthetic": true, "rules": [')
    write_specs(fx, specs)
    run_batch(fx / "specs.json", mapping, tmp_path / "out")
    res = _results(tmp_path / "out", specs[0]["sha256"])
    assert res["stages"]["A"]["status"] == "failed" and "malformed JSON" in res["stages"]["A"]["notes"][0]
    assert res["measures"]["QA"] == "n/d" and res["measures"]["VB"] == 0.4


def test_synthetic_mode_refuses_inputs_not_marked_synthetic(fx, mapping, tmp_path):
    specs = read_specs(fx)
    doc = json.loads((fx / specs[0]["inputs"]["C"]).read_text(encoding="utf-8"))
    doc.pop("synthetic")
    rewrite_input(fx, specs[0], "C", doc)
    write_specs(fx, specs)
    run_batch(fx / "specs.json", mapping, tmp_path / "out")
    res = _results(tmp_path / "out", specs[0]["sha256"])
    assert res["stages"]["C"]["status"] == "failed" and "pilot mode" in res["stages"]["C"]["notes"][0]


def test_bad_evidence_marks_classification_failed(fx, mapping, tmp_path):
    specs = read_specs(fx)
    rewrite_input(fx, specs[0], "evidence", {"synthetic": True, "residual": [
        {"technique": "T1055", "class": "P", "evidence_ref": "C#rules"}]})
    write_specs(fx, specs)
    run_batch(fx / "specs.json", mapping, tmp_path / "out")
    res = _results(tmp_path / "out", specs[0]["sha256"])
    assert res["residual_classification"]["status"] == "failed"
    assert "not in C" in res["residual_classification"]["reason"]


def test_cli_demo_and_verify(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path / "demo")]) == 0
    out = capsys.readouterr().out
    assert "SYNTHETIC" in out and "QA=0.75" in out and "budget exceeded (25 > 20)" in out
    assert "SYNTHETIC DEMONSTRATION DATA" in (tmp_path / "demo" / "report.html").read_text(encoding="utf-8")
    assert main(["verify", "--dir", str(tmp_path / "demo")]) == 0
    assert capsys.readouterr().out.count("seal holds") == 2
