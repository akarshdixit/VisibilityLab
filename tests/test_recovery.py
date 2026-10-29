"""Recovery gate (V1-V5, source, budget) and evidence-based classification."""

import copy
import json

import pytest

from pipeline.classify import (
    ClassificationError,
    attribute_gains,
    class_counts,
    classify_residual,
    pk_summary,
)
from pipeline.recovery import CHECKS, evaluate_recovery

from .conftest import FIXTURES

SPECS = json.loads((FIXTURES / "specs.json").read_text(encoding="utf-8"))
SAMPLE1 = SPECS[0]["sha256"]
GOOD = json.loads((FIXTURES / "sample_001" / "B_recovery.json").read_text(encoding="utf-8"))
REJECTED = json.loads((FIXTURES / "sample_002" / "B_recovery.json").read_text(encoding="utf-8"))


def rec(**changes):
    r = copy.deepcopy(GOOD)
    r.update(changes)
    return r


# ----------------------------------------------------------------------------- gate


def test_complete_operator_record_is_accepted():
    g = evaluate_recovery(GOOD, SAMPLE1)
    assert g.accepted and g.reasons == [] and g.payload_sha256 == GOOD["payload_sha256"]
    assert all(g.checks[c] for c in CHECKS)


@pytest.mark.parametrize("check", CHECKS)
def test_any_single_failed_check_rejects(check):
    r = rec()
    r["checks"][check]["passed"] = False
    g = evaluate_recovery(r, SAMPLE1)
    assert not g.accepted and g.reasons == [f"{check} not passed"]


def test_valid_pe_alone_is_not_enough():
    r = rec(checks={"V1": GOOD["checks"]["V1"]})
    g = evaluate_recovery(r, SAMPLE1)
    assert not g.accepted
    assert sum("missing from record" in x for x in g.reasons) == 4


def test_truthy_values_are_not_a_pass():
    r = rec()
    r["checks"]["V2"]["passed"] = "yes"
    r["checks"]["V4"]["passed"] = 1
    g = evaluate_recovery(r, SAMPLE1)
    assert not g.accepted and {"V2 not passed", "V4 not passed"} <= set(g.reasons)


@pytest.mark.parametrize(
    "check, field, value, message",
    [
        ("V1", "dos_magic", "ZM", "signatures"),
        ("V2", "stored_payload_sha256", "0" * 64, "differs from payload_sha256"),
        ("V3", "entry_point_rva", 0x50000, "lies in no listed section"),
        ("V4", "import_errors", 2, "import_errors=2"),
    ],
)
def test_claimed_pass_must_agree_with_recorded_evidence(check, field, value, message):
    r = rec()
    r["checks"][check][field] = value
    g = evaluate_recovery(r, SAMPLE1)
    assert not g.accepted and any(message in x for x in g.reasons)


def test_v5_rejects_payload_identical_to_packed_input():
    r = rec(payload_sha256=SAMPLE1)
    r["checks"]["V2"]["stored_payload_sha256"] = SAMPLE1
    g = evaluate_recovery(r, SAMPLE1)
    assert any("equals the packed input" in x for x in g.reasons)


def test_sandbox_source_is_always_rejected():
    g = evaluate_recovery(rec(check_source="sandbox"), SAMPLE1)
    assert not g.accepted and "sandbox trace" in g.reasons[0]


def test_budget_rules():
    assert "budget exceeded (21 > 20)" in evaluate_recovery(rec(budget_used=21), SAMPLE1).reasons
    r = rec()
    del r["budget_limit"]
    assert any("budget_used and budget_limit" in x for x in evaluate_recovery(r, SAMPLE1).reasons)


def test_missing_payload_hash_and_wrong_sample_are_rejected():
    r = rec()
    del r["payload_sha256"]
    reasons = evaluate_recovery(r, "f" * 64).reasons
    assert "payload hash missing or malformed" in reasons
    assert any("different sample" in x for x in reasons)


def test_every_reason_is_kept_for_the_rejected_fixture():
    g = evaluate_recovery(REJECTED, SPECS[1]["sha256"])
    assert not g.accepted
    assert "budget exceeded (25 > 20)" in g.reasons
    assert any(x.startswith("V4 not passed") for x in g.reasons)
    assert len(g.reasons) == 2


def test_synthetic_record_is_rejected_in_pilot_mode():
    g = evaluate_recovery(GOOD, SAMPLE1, mode="pilot")
    assert any("pilot mode" in x for x in g.reasons)


# ----------------------------------------------------------------------------- classification

DOCS = {"B_recovery": GOOD, "C": {"rules": {"dyn-rule-4": {}}}}
RESIDUAL = {"T1112", "T1620", "T9998"}


def test_evidence_sets_class_and_missing_evidence_defaults_to_u():
    ev = {"residual": [
        {"technique": "T1112", "class": "P", "evidence_ref": "B_recovery#checks.V3"},
        {"technique": "T1620", "class": "K", "evidence_ref": "C#rules.dyn-rule-4"},
    ]}
    rows = classify_residual(RESIDUAL, ev, DOCS)
    assert [(r["technique"], r["class"]) for r in rows] == [("T1112", "P"), ("T1620", "K"), ("T9998", "U")]
    assert pk_summary(class_counts(rows)) == "P=1, K=1 (P+K=2)"


def test_class_without_evidence_or_with_dangling_reference_becomes_u():
    ev = {"residual": [
        {"technique": "T1112", "class": "O"},
        {"technique": "T1620", "class": "E", "evidence_ref": "C#rules.no-such-rule"},
    ]}
    rows = {r["technique"]: r for r in classify_residual(RESIDUAL, ev, DOCS)}
    assert rows["T1112"]["class"] == "U" and "no evidence reference" in rows["T1112"]["reason"]
    assert rows["T1620"]["class"] == "U" and "does not resolve" in rows["T1620"]["reason"]


def test_unknown_class_letter_is_an_error():
    with pytest.raises(ClassificationError, match="unknown class"):
        classify_residual(RESIDUAL, {"residual": [{"technique": "T1112", "class": "X", "evidence_ref": "C#rules"}]}, DOCS)


def test_evidence_outside_residual_is_an_error():
    with pytest.raises(ClassificationError, match="not in C"):
        classify_residual(RESIDUAL, {"residual": [{"technique": "T1055", "class": "P", "evidence_ref": "C#rules"}]}, DOCS)


def test_pk_always_printed_together():
    assert pk_summary({"P": 2, "K": 1}) == "P=2, K=1 (P+K=3)"
    assert pk_summary({"P": 0, "K": 0, "U": 4}) == "P=0, K=0 (P+K=0)"


def test_gain_attribution_defaults_to_uncertain_and_validates():
    rows = attribute_gains({"T1497", "T1112"}, {"gains": [
        {"technique": "T1497", "attribution": "payload", "evidence_ref": "C#rules"}]}, DOCS)
    assert {r["technique"]: r["attribution"] for r in rows} == {"T1112": "uncertain", "T1497": "payload"}
    with pytest.raises(ClassificationError, match="unknown gain attribution"):
        attribute_gains({"T1497"}, {"gains": [{"technique": "T1497", "attribution": "magic"}]}, DOCS)
    with pytest.raises(ClassificationError, match="not in B"):
        attribute_gains({"T1497"}, {"gains": [{"technique": "T1055", "attribution": "payload"}]}, DOCS)
