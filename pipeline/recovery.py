"""Recovery gate: decides whether a recovered payload may be used for Stage B.

The pipeline never unpacks anything. Unpacking and the V1-V5 checks run in the
operator's validated tool, which writes a *recovery record*. This module only
checks that record. A claimed pass is accepted only when it is a literal
``true`` AND the evidence fields recorded with it are consistent with it.

Working definitions of V1-V5 (named in Review 1, not defined there; confirm
before a pilot):

V1  the payload parses as a structurally valid PE file
    evidence: dos_magic == "MZ", nt_signature == "PE", number_of_sections > 0
    (and equal to the number of sections listed under V3, when listed)
V2  the payload hash is recorded and matches the stored payload
    evidence: stored_payload_sha256 == record payload_sha256
V3  the entry point lies inside a section of the payload
    evidence: entry_point_rva within [virtual_address, virtual_address + virtual_size)
V4  the import table resolves without errors
    evidence: import_errors == 0
V5  the payload differs from the packed input
    evidence: payload_sha256 != sample_sha256

Record shape (all fields required)::

    {
      "sample_sha256": "<packed file SHA-256>",
      "check_source": "operator_tool",
      "payload_sha256": "<payload SHA-256>",
      "budget_used": 12, "budget_limit": 20,
      "checks": {"V1": {"passed": true, ...evidence}, ..., "V5": {"passed": true}}
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .hashing import is_sha256

CHECKS = ("V1", "V2", "V3", "V4", "V5")
CHECK_DEFINITIONS = {
    "V1": "payload parses as a structurally valid PE file",
    "V2": "payload hash is recorded and matches the stored payload",
    "V3": "entry point lies inside a section of the payload",
    "V4": "import table resolves without errors",
    "V5": "payload differs from the packed input",
}
ACCEPTED_SOURCE = "operator_tool"


@dataclass
class GateResult:
    accepted: bool
    reasons: list[str] = field(default_factory=list)
    payload_sha256: str | None = None
    checks: dict[str, bool] = field(default_factory=dict)  # effective outcome per check

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "reasons": list(self.reasons),
            "payload_sha256": self.payload_sha256,
            "checks": dict(self.checks),
        }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_v1(c: dict, record: dict) -> str | None:
    if c.get("dos_magic") != "MZ" or c.get("nt_signature") != "PE":
        return "V1 claimed passed but DOS/NT signatures are not MZ/PE"
    n = c.get("number_of_sections")
    if not _is_int(n) or n <= 0:
        return "V1 claimed passed but number_of_sections is not a positive integer"
    sections = record.get("checks", {}).get("V3", {}).get("sections")
    if isinstance(sections, list) and len(sections) != n:
        return f"V1 claimed passed but number_of_sections={n} disagrees with {len(sections)} sections under V3"
    return None


def _check_v2(c: dict, record: dict) -> str | None:
    stored = c.get("stored_payload_sha256")
    if not is_sha256(stored):
        return "V2 claimed passed but stored_payload_sha256 is missing or malformed"
    if stored != record.get("payload_sha256"):
        return "V2 claimed passed but stored payload hash differs from payload_sha256"
    return None


def _check_v3(c: dict, record: dict) -> str | None:
    ep = c.get("entry_point_rva")
    sections = c.get("sections")
    if not _is_int(ep) or not isinstance(sections, list) or not sections:
        return "V3 claimed passed but entry_point_rva or sections are missing"
    for s in sections:
        va, size = (s.get("virtual_address"), s.get("virtual_size")) if isinstance(s, dict) else (None, None)
        if not _is_int(va) or not _is_int(size):
            return "V3 claimed passed but a section lacks integer virtual_address/virtual_size"
        if va <= ep < va + size:
            return None
    return f"V3 claimed passed but entry point 0x{ep:x} lies in no listed section"


def _check_v4(c: dict, record: dict) -> str | None:
    errors = c.get("import_errors")
    if not _is_int(errors):
        return "V4 claimed passed but import_errors is not recorded as an integer"
    if errors != 0:
        return f"V4 claimed passed but import_errors={errors}"
    return None


def _check_v5(c: dict, record: dict) -> str | None:
    if record.get("payload_sha256") == record.get("sample_sha256"):
        return "V5 claimed passed but the payload hash equals the packed input hash"
    return None


_CONSISTENCY = {"V1": _check_v1, "V2": _check_v2, "V3": _check_v3, "V4": _check_v4, "V5": _check_v5}


def evaluate_recovery(record: Any, packed_sha256: str, mode: str = "synthetic") -> GateResult:
    """Return accepted/rejected with every reason. Never short-circuits on the first failure."""
    if not isinstance(record, dict):
        return GateResult(False, ["recovery record is not a JSON object"])
    reasons: list[str] = []

    source = record.get("check_source")
    if source != ACCEPTED_SOURCE:
        reasons.append(
            f"check_source is {source!r}, not {ACCEPTED_SOURCE!r}; "
            "a sandbox trace or other source cannot prove recovery"
        )

    if record.get("sample_sha256") != packed_sha256:
        reasons.append("recovery record is for a different sample (sample_sha256 mismatch)")

    payload = record.get("payload_sha256")
    if not is_sha256(payload):
        reasons.append("payload hash missing or malformed")
        payload = None

    if mode == "pilot" and record.get("synthetic") is True:
        reasons.append("synthetic recovery record cannot be used in pilot mode")

    used, limit = record.get("budget_used"), record.get("budget_limit")
    if not _is_int(used) or not _is_int(limit) or used < 0 or limit < 0:
        reasons.append("budget_used and budget_limit must both be recorded as non-negative integers")
    elif used > limit:
        reasons.append(f"budget exceeded ({used} > {limit})")

    checks = record.get("checks")
    effective: dict[str, bool] = {}
    if not isinstance(checks, dict):
        reasons.append("checks object missing")
        checks = {}
    for name in CHECKS:
        c = checks.get(name)
        if not isinstance(c, dict):
            reasons.append(f"{name} missing from record ({CHECK_DEFINITIONS[name]})")
            effective[name] = False
            continue
        if c.get("passed") is not True:
            detail = f" ({c['detail']})" if isinstance(c.get("detail"), str) else ""
            reasons.append(f"{name} not passed{detail}")
            effective[name] = False
            continue
        problem = _CONSISTENCY[name](c, record)
        if problem:
            reasons.append(problem)
        effective[name] = problem is None

    return GateResult(accepted=not reasons, reasons=reasons, payload_sha256=payload, checks=effective)
