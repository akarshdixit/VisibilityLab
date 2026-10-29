"""Evidence-based classification of residual differences (C \\ B) and gains (B \\ A).

No class is inferred from a missing technique. A class other than U is kept
only when the analyst supplied an evidence reference that resolves to a field
of one of the sample's recorded inputs, written ``<input key>#<dotted.path>``,
e.g. ``B_recovery#checks.V3`` or ``C#rules.dyn-rule-4``.
"""

from __future__ import annotations

from typing import Any

CLASSES = {
    "P": "Incomplete or incorrect payload recovery",
    "K": "Behaviour of the packer or unpacking stub",
    "O": "Other run-time obfuscation within the payload",
    "E": "Behaviour outside the analysed file",
    "T": "Rule scope or rule coverage",
    "M": "Mapping difference",
    "U": "Unresolved: default when there is no evidence",
}
GAIN_ATTRIBUTIONS = ("payload", "dump_artifact", "uncertain")

RESIDUAL_COLUMNS = ["technique", "class", "class_meaning", "evidence_ref", "reason"]
GAIN_COLUMNS = ["technique", "attribution", "evidence_ref", "reason"]


class ClassificationError(ValueError):
    """The evidence file is malformed or contradicts the computed sets."""


def resolve_ref(ref: str, docs: dict[str, Any]) -> bool:
    """True if ``key#a.b.c`` names an existing field in the parsed input ``docs[key]``."""
    if not isinstance(ref, str) or "#" not in ref:
        return False
    key, _, path = ref.partition("#")
    if key not in docs:
        return False
    node = docs[key]
    for part in path.split(".") if path else []:
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return False
    return True


def _entries(evidence: Any, section: str) -> list[dict[str, Any]]:
    if evidence is None:
        return []
    if not isinstance(evidence, dict):
        raise ClassificationError("evidence file must be a JSON object")
    items = evidence.get(section, [])
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        raise ClassificationError(f"evidence '{section}' must be a list of objects")
    seen: set[str] = set()
    cleaned = []
    for item in items:
        tid = item.get("technique")
        if not isinstance(tid, str) or not tid.strip():
            raise ClassificationError(f"evidence '{section}' entry without a technique")
        item = {**item, "technique": tid.strip().upper()}
        if item["technique"] in seen:
            raise ClassificationError(f"evidence '{section}' lists {item['technique']} twice")
        seen.add(item["technique"])
        cleaned.append(item)
    return cleaned


def _evidence_problem(ref: Any, docs: dict[str, Any]) -> str | None:
    if not isinstance(ref, str) or not ref.strip():
        return "no evidence reference"
    if not resolve_ref(ref, docs):
        return f"evidence reference {ref!r} does not resolve to a recorded input"
    return None


def classify_residual(
    residual: set[str], evidence: Any, docs: dict[str, Any]
) -> list[dict[str, str]]:
    """One row per technique in C \\ B. Missing or unresolvable evidence -> U."""
    by_tid = {}
    for item in _entries(evidence, "residual"):
        tid = item["technique"]
        if tid not in residual:
            raise ClassificationError(f"evidence given for {tid}, which is not in C \\ B")
        cls = item.get("class")
        if cls not in CLASSES:
            raise ClassificationError(f"unknown class {cls!r} for {tid}")
        by_tid[tid] = item

    rows = []
    for tid in sorted(residual):
        item = by_tid.get(tid)
        if item is None:
            rows.append(_row(tid, "U", "", "no evidence record; default U"))
            continue
        cls, ref = item["class"], item.get("evidence_ref", "")
        note = item.get("reason", "") if isinstance(item.get("reason"), str) else ""
        if cls == "U":
            rows.append(_row(tid, "U", ref or "", note or "analyst recorded U"))
            continue
        problem = _evidence_problem(ref, docs)
        if problem:
            rows.append(_row(tid, "U", ref or "", f"class {cls} given with {problem}; defaulted to U"))
        else:
            rows.append(_row(tid, cls, ref, note or "recorded evidence"))
    return rows


def _row(tid: str, cls: str, ref: str, reason: str) -> dict[str, str]:
    return {"technique": tid, "class": cls, "class_meaning": CLASSES[cls], "evidence_ref": ref, "reason": reason}


def class_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts = {c: 0 for c in CLASSES}
    for r in rows:
        counts[r["class"]] += 1
    return counts


def pk_summary(counts: dict[str, int]) -> str:
    """P and K are always reported together, e.g. 'P=2, K=1 (P+K=3)'."""
    p, k = counts.get("P", 0), counts.get("K", 0)
    return f"P={p}, K={k} (P+K={p + k})"


def attribute_gains(gains: set[str], evidence: Any, docs: dict[str, Any]) -> list[dict[str, str]]:
    """One row per technique in B \\ A: payload, dump_artifact or uncertain (default)."""
    by_tid = {}
    for item in _entries(evidence, "gains"):
        tid = item["technique"]
        if tid not in gains:
            raise ClassificationError(f"gain evidence given for {tid}, which is not in B \\ A")
        if item.get("attribution") not in GAIN_ATTRIBUTIONS:
            raise ClassificationError(f"unknown gain attribution {item.get('attribution')!r} for {tid}")
        by_tid[tid] = item

    rows = []
    for tid in sorted(gains):
        item = by_tid.get(tid)
        if item is None:
            rows.append({"technique": tid, "attribution": "uncertain", "evidence_ref": "", "reason": "no attribution evidence; default uncertain"})
            continue
        attr, ref = item["attribution"], item.get("evidence_ref", "")
        problem = None if attr == "uncertain" else _evidence_problem(ref, docs)
        if problem:
            rows.append({"technique": tid, "attribution": "uncertain", "evidence_ref": ref or "", "reason": f"{attr} given with {problem}; defaulted to uncertain"})
        else:
            rows.append({"technique": tid, "attribution": attr, "evidence_ref": ref or "", "reason": item.get("reason", "") or "recorded evidence"})
    return rows
