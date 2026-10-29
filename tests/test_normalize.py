"""Normalization rules N1-N7 (working interpretations) and mapping-table validation."""

import pytest

from pipeline.hashing import sha256_bytes
from pipeline.normalize import MappingError, normalize_stage, parse_mapping

TABLE_CSV = (
    "technique_id,status,replacement\n"
    "T1055,current,\nT1055.001,current,\nT1027,current,\nT0001,revoked,T1027\n"
).encode()


@pytest.fixture
def table():
    return parse_mapping(TABLE_CSV, "test_map.csv", "test v1")


def _one(raw, table, collapse=False):
    s, audit = normalize_stage("A", {raw: ["r1"]}, table, collapse)
    assert len(audit) == 1
    return s, audit[0]


def test_n1_trims_and_uppercases(table):
    s, row = _one(" t1055 ", table)
    assert s == {"T1055"} and row["status"] == "current" and row["raw_id"] == " t1055 "


def test_n2_invalid_format_is_flagged_and_kept(table):
    s, row = _one("TA0005", table)
    assert s == {"TA0005"}
    assert row["status"] == "invalid_format" and "N2:invalid" in row["rules_applied"]


def test_n4_revoked_is_replaced(table):
    s, row = _one("T0001", table)
    assert s == {"T1027"} and row["status"] == "revoked_replaced"
    assert "N4:revoked->T1027" in row["rules_applied"]


def test_n4_unknown_is_kept_and_flagged_unmapped(table):
    s, row = _one("T9998", table)
    assert s == {"T9998"} and row["status"] == "unmapped"


def test_n3_subtechnique_kept_by_default_and_collapsed_on_request(table):
    assert _one("T1055.001", table)[0] == {"T1055.001"}
    s, row = _one("T1055.001", table, collapse=True)
    assert s == {"T1055"} and "N3:collapsed" in row["rules_applied"]


def test_n5_dedupes_and_n6_audits_every_raw_id(table):
    raw = {"T1027": ["r1"], "t1027": ["r2"], "T0001": ["r3", "r4"]}
    s, audit = normalize_stage("B", raw, table)
    assert s == {"T1027"}
    assert len(audit) == 3  # one row per raw ID, none dropped
    assert sum("N5:merged" in r["rules_applied"] for r in audit) == 2
    assert {r["source_rules"] for r in audit} == {"r1", "r2", "r3;r4"}


def test_n7_table_provenance_is_recorded(table):
    assert table.provenance() == {"name": "test_map.csv", "version": "test v1",
                                  "sha256": sha256_bytes(TABLE_CSV)}


@pytest.mark.parametrize(
    "body, message",
    [
        ("T10X5,current,\n", "invalid technique_id"),
        ("T1055,active,\n", "status must be"),
        ("T0001,revoked,\n", "needs a valid replacement"),
        ("T1055,current,\nT1055,current,\n", "duplicate"),
        ("T0001,revoked,T1027\n", "not a current row"),
    ],
)
def test_bad_mapping_rows_are_rejected(body, message):
    with pytest.raises(MappingError, match=message):
        parse_mapping(("technique_id,status,replacement\n" + body).encode(), "bad.csv", "v")


def test_n4_deprecated_is_kept_and_flagged():
    t = parse_mapping(b"technique_id,status,replacement\nT1055,current,\nT1064,deprecated,\n", "m.csv", "v")
    s, audit = normalize_stage("C", {"T1064": ["r1"]}, t)
    assert s == {"T1064"} and audit[0]["status"] == "deprecated" and "N4:deprecated" in audit[0]["rules_applied"]
    with pytest.raises(MappingError, match="must not have a replacement"):
        parse_mapping(b"technique_id,status,replacement\nT1055,current,\nT1064,deprecated,T1055\n", "m.csv", "v")
