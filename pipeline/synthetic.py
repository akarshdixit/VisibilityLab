"""Builders for SYNTHETIC (fictional) evidence files.

Used by tools/build_fixtures.py (the bundled fixtures) and by VisibilityLab's
demo mode. Everything produced here is marked ``"synthetic": true``, describes
no real file, and is not tool output. Sample hashes are SHA-256 digests of
descriptive strings, not of any binary.

Scenarios:
  accepted  the guide's worked example: the recovery gate accepts
            (QA 0.75, VA 0.4, VB 0.4, DB 0.0, IB 0.6, G 1, L 0, M 2, O 2, S∩C 1)
  rejected  V4 fails and the budget is exceeded (25 > 20): B is not recovered,
            and B-dependent measures are n/d while VA stays 0.4
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

NOTE = "SYNTHETIC FIXTURE - fictional data for pipeline testing; not real tool output"
SCENARIOS = ("accepted", "rejected")
SCENARIO_DESCRIPTIONS = {
    "accepted": "Recovery gate accepts: the guide's worked example (QA 0.75, VA 0.4, VB 0.4, DB 0.0, IB 0.6).",
    "rejected": "Recovery gate rejects (V4 fails, budget 25 > 20): Stage B is not recovered and its measures are n/d.",
}
# Evidence kinds in the order a user would normally attach them.
KIT_ORDER = ("A", "B_recovery", "B", "C", "S", "evidence")


def fake_sha(text: str) -> str:
    """A fictional 'sample hash': the digest of a label, not of any binary."""
    return hashlib.sha256(text.encode()).hexdigest()


def dumps(obj: Any) -> bytes:
    """The exact byte form used for every synthetic file."""
    return (json.dumps(obj, indent=2) + "\n").encode("utf-8")


def capa(sample_sha: str, rules: dict[str, list[str]]) -> dict:
    return {
        "synthetic": True,
        "note": NOTE,
        "meta": {"sample": {"sha256": sample_sha}},
        "rules": {
            name: {"meta": {"attack": [{"id": t} for t in ids]} if ids else {}}
            for name, ids in rules.items()
        },
    }


def recovery(sample_sha: str, payload_sha: str, *, v4_errors: int, used: int, limit: int) -> dict:
    sections = [
        {"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x6000},
        {"name": ".rdata", "virtual_address": 0x7000, "virtual_size": 0x2000},
        {"name": ".data", "virtual_address": 0x9000, "virtual_size": 0x1000},
    ]
    return {
        "synthetic": True,
        "note": NOTE + ". Structural checks are asserted by this synthetic record; "
        "they are not an independent validation of any executable.",
        "sample_sha256": sample_sha,
        "check_source": "operator_tool",
        "tool": {"name": "synthetic-operator-tool", "version": "0.0-fixture"},
        "payload_sha256": payload_sha,
        "budget_used": used,
        "budget_limit": limit,
        "budget_unit": "minutes",
        "checks": {
            "V1": {"passed": True, "dos_magic": "MZ", "nt_signature": "PE", "number_of_sections": 3},
            "V2": {"passed": True, "stored_payload_sha256": payload_sha},
            "V3": {"passed": True, "entry_point_rva": 0x1A40, "sections": sections},
            "V4": {"passed": v4_errors == 0, "imports_resolved": 40 - v4_errors, "import_errors": v4_errors,
                   **({"detail": f"{v4_errors} imports failed to resolve"} if v4_errors else {})},
            "V5": {"passed": True},
        },
    }


def labels(ids: list[str]) -> dict:
    return {"synthetic": True, "note": NOTE, "source": "synthetic sandbox label list", "techniques": ids}


def scenario_files(scenario: str, sample_sha: str, payload_sha: str) -> dict[str, tuple[str, dict]]:
    """{kind: (file name, document)} for one scenario, bound to the given fictional hashes."""
    if scenario == "accepted":
        return {
            "A": ("A_packed_capa.json", capa(sample_sha, {
                "packed-rule-1": ["T1055"], "packed-rule-2": ["T1027"],
                "packed-rule-3": ["T1082"], "packed-rule-4 (no ATT&CK mapping)": [],
            })),
            "B_recovery": ("B_recovery.json", recovery(sample_sha, payload_sha, v4_errors=0, used=12, limit=20)),
            "B": ("B_payload_capa.json", capa(payload_sha, {
                "payload-rule-1": ["T1055"], "payload-rule-2": ["T1027", "T1082"],
                "payload-rule-3": ["T1497"], "payload-rule-4": ["T0001"],
            })),
            "C": ("C_dynamic_capa.json", capa(sample_sha, {
                "dyn-rule-1": ["T1055"], "dyn-rule-2": ["T1027"], "dyn-rule-3": ["T1112"],
                "dyn-rule-4": ["T1620"], "dyn-rule-5": ["T9998"],
            })),
            "S": ("S_sandbox_labels.json", labels(["T1055", "T1486"])),
            "evidence": ("evidence.json", {
                "synthetic": True,
                "note": NOTE + ". Evidence shows how the rule works; it is not a conclusion about any sample.",
                "residual": [
                    {"technique": "T1112", "class": "P", "evidence_ref": "B_recovery#checks.V3",
                     "reason": "synthetic: points at the payload check"},
                    {"technique": "T1620", "class": "K", "evidence_ref": "C#rules.dyn-rule-4",
                     "reason": "synthetic: points at the dynamic rule"},
                ],
                "gains": [
                    {"technique": "T1497", "attribution": "payload", "evidence_ref": "B#rules.payload-rule-3",
                     "reason": "synthetic: payload rule reports it"},
                ],
            }),
        }
    if scenario == "rejected":
        return {
            "A": ("A_packed_capa.json", capa(sample_sha, {
                "packed-rule-1": ["T1055"], "packed-rule-2": ["T1027"], "packed-rule-3": ["T1082"],
            })),
            "B_recovery": ("B_recovery.json", recovery(sample_sha, payload_sha, v4_errors=3, used=25, limit=20)),
            "B": ("B_payload_capa.json", capa(payload_sha, {"payload-rule-1": ["T1055", "T1497", "T1112"]})),
            "C": ("C_dynamic_capa.json", capa(sample_sha, {
                "dyn-rule-1": ["T1055"], "dyn-rule-2": ["T1027"], "dyn-rule-3": ["T1112"],
                "dyn-rule-4": ["T1620"], "dyn-rule-5": ["T1105"],
            })),
            "S": ("S_sandbox_labels.json", labels(["T1055", "T1105"])),
            "evidence": ("evidence.json", {"synthetic": True, "note": NOTE, "residual": [], "gains": []}),
        }
    raise ValueError(f"unknown synthetic scenario {scenario!r}; choose one of {SCENARIOS}")


def demo_payload_sha(sample_sha: str) -> str:
    """The fictional payload hash paired with a demo sample hash."""
    return fake_sha(f"VisibilityLab demo payload for {sample_sha} (fictional, not a real file)")
