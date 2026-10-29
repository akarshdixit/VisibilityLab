"""Readers for capa JSON reports and sandbox label lists.

Assumed capa shape (to be confirmed against the approved capa version)::

    {"rules": {"<rule name>": {"meta": {"attack": [{"id": "T1055"}, ...]}}}}

Both readers return a map ``raw ATT&CK ID -> sorted list of source names``.
IDs are returned exactly as written in the report; cleaning happens in
normalize.py so that every raw value appears in the audit.
"""

from __future__ import annotations

import json
from typing import Any

SANDBOX_SOURCE = "sandbox_label"


class ReportFormatError(ValueError):
    """A report is not valid JSON or does not have the expected structure."""


def parse_json_bytes(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise ReportFormatError(f"{label}: not UTF-8 text ({exc.reason})") from None
    except json.JSONDecodeError as exc:
        raise ReportFormatError(f"{label}: malformed JSON ({exc.msg} at line {exc.lineno})") from None


def techniques_from_capa(doc: Any, label: str = "capa report") -> dict[str, list[str]]:
    """Extract {raw ATT&CK ID: [rule names]} from a parsed capa report.

    A report without a ``rules`` object is rejected rather than read as empty.
    Rules with no ATT&CK entry are skipped; malformed ATT&CK entries are errors.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), dict):
        raise ReportFormatError(f"{label}: not capa JSON (missing 'rules' object)")
    found: dict[str, set[str]] = {}
    for rule_name, rule in doc["rules"].items():
        if not isinstance(rule, dict):
            raise ReportFormatError(f"{label}: rule {rule_name!r} is not an object")
        meta = rule.get("meta", {})
        if not isinstance(meta, dict):
            raise ReportFormatError(f"{label}: rule {rule_name!r} has a non-object 'meta'")
        attack = meta.get("attack")
        if not attack:
            continue
        if not isinstance(attack, list):
            raise ReportFormatError(f"{label}: rule {rule_name!r} 'meta.attack' is not a list")
        for entry in attack:
            raw = entry.get("id") if isinstance(entry, dict) else None
            if not isinstance(raw, str) or not raw.strip():
                raise ReportFormatError(
                    f"{label}: rule {rule_name!r} has an ATT&CK entry without an 'id' string"
                )
            found.setdefault(raw, set()).add(rule_name)
    return {raw: sorted(rules) for raw, rules in sorted(found.items())}


def techniques_from_labels(doc: Any, label: str = "sandbox labels") -> dict[str, list[str]]:
    """Extract {raw ATT&CK ID: ["sandbox_label"]} from a label file's 'techniques' list."""
    if not isinstance(doc, dict) or not isinstance(doc.get("techniques"), list):
        raise ReportFormatError(f"{label}: missing 'techniques' list")
    found: dict[str, list[str]] = {}
    for raw in doc["techniques"]:
        if not isinstance(raw, str) or not raw.strip():
            raise ReportFormatError(f"{label}: every technique must be a non-empty string")
        found[raw] = [SANDBOX_SOURCE]
    return dict(sorted(found.items()))


def reported_sample_sha256(doc: Any) -> str | None:
    """The sample hash a capa report says it describes (meta.sample.sha256), if stated."""
    if not isinstance(doc, dict):
        return None
    sample = doc.get("meta", {}).get("sample", {}) if isinstance(doc.get("meta"), dict) else {}
    value = sample.get("sha256") if isinstance(sample, dict) else None
    return value.strip().lower() if isinstance(value, str) else None
