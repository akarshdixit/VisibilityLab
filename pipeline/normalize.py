"""ATT&CK ID normalization, rules N1-N7 (working interpretations).

Review 1 names N1-N7 but does not define them. The definitions below follow the
Review 2 guide and must be confirmed before a pilot:

N1  trim whitespace, upper-case
N2  check format T#### or T####.###; invalid IDs are flagged and kept
N3  keep sub-techniques; collapse to the parent only when configured
N4  look up the mapping table: current -> kept, revoked -> replaced,
    deprecated (no replacement exists) -> kept and flagged ``deprecated``,
    absent -> kept and flagged ``unmapped``
N5  stage sets remove duplicates (each technique counts once)
N6  one audit row per raw ID, listing every rule applied
N7  mapping table name, version and SHA-256 are recorded in the manifest
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path

from .hashing import sha256_bytes

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
STATUS_CURRENT = "current"
STATUS_REVOKED = "revoked"
STATUS_DEPRECATED = "deprecated"
TABLE_STATUSES = (STATUS_CURRENT, STATUS_REVOKED, STATUS_DEPRECATED)

# Audit statuses
OK = "current"
REPLACED = "revoked_replaced"
UNMAPPED = "unmapped"
INVALID = "invalid_format"
DEPRECATED = "deprecated"

AUDIT_COLUMNS = ["stage", "raw_id", "normalized_id", "status", "rules_applied", "source_rules"]


class MappingError(ValueError):
    """The mapping table is unreadable or contains an invalid row."""


@dataclass(frozen=True)
class MappingTable:
    name: str
    version: str
    sha256: str
    rows: dict[str, tuple[str, str]] = field(default_factory=dict)  # id -> (status, replacement)

    def provenance(self) -> dict[str, str]:
        """N7: what the manifest records about the table."""
        return {"name": self.name, "version": self.version, "sha256": self.sha256}


def parse_mapping(data: bytes, name: str, version: str) -> MappingTable:
    """Parse a CSV with columns technique_id,status[,replacement,...]."""
    if not version or not version.strip():
        raise MappingError("a mapping version must be given")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise MappingError(f"{name}: not UTF-8 text") from None
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"technique_id", "status"} <= set(reader.fieldnames):
        raise MappingError(f"{name}: needs columns 'technique_id' and 'status'")
    rows: dict[str, tuple[str, str]] = {}
    for line_no, row in enumerate(reader, start=2):
        tid = (row.get("technique_id") or "").strip().upper()
        status = (row.get("status") or "").strip().lower()
        repl = (row.get("replacement") or "").strip().upper()
        where = f"{name} line {line_no}"
        if not TECHNIQUE_RE.match(tid):
            raise MappingError(f"{where}: invalid technique_id {row.get('technique_id')!r}")
        if status not in TABLE_STATUSES:
            raise MappingError(f"{where}: status must be one of {TABLE_STATUSES}, got {status!r}")
        if tid in rows:
            raise MappingError(f"{where}: duplicate technique_id {tid}")
        if status == STATUS_REVOKED and not TECHNIQUE_RE.match(repl):
            raise MappingError(f"{where}: revoked {tid} needs a valid replacement")
        if status in (STATUS_CURRENT, STATUS_DEPRECATED) and repl:
            raise MappingError(f"{where}: {status} {tid} must not have a replacement")
        rows[tid] = (status, repl)
    for tid, (status, repl) in rows.items():
        if status == STATUS_REVOKED and rows.get(repl, ("", ""))[0] != STATUS_CURRENT:
            raise MappingError(f"{name}: replacement {repl} for {tid} is not a current row")
    return MappingTable(name=name, version=version.strip(), sha256=sha256_bytes(data), rows=rows)


def load_mapping(path: str | Path, version: str, name: str | None = None) -> MappingTable:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise MappingError(f"cannot read mapping table {path}: {exc.strerror}") from None
    return parse_mapping(data, name or path.name, version)


def normalize_id(raw: str, table: MappingTable, collapse: bool = False) -> tuple[str, str, list[str]]:
    """Apply N1-N4 to one raw ID. Returns (normalized ID, status, rules applied)."""
    rules = ["N1"]
    tid = raw.strip().upper()
    if not TECHNIQUE_RE.match(tid):
        rules.append("N2:invalid")
        return tid, INVALID, rules
    rules.append("N2")

    def _collapse(value: str) -> str:
        return value.split(".", 1)[0] if collapse else value

    if collapse and "." in tid:
        rules.append("N3:collapsed")
    else:
        rules.append("N3")
    tid = _collapse(tid)

    entry = table.rows.get(tid)
    if entry is None:
        rules.append("N4:unmapped")
        return tid, UNMAPPED, rules
    status, repl = entry
    if status == STATUS_DEPRECATED:
        rules.append("N4:deprecated")
        return tid, DEPRECATED, rules
    if status == STATUS_REVOKED:
        rules.append(f"N4:revoked->{repl}")
        return _collapse(repl), REPLACED, rules
    rules.append("N4")
    return tid, OK, rules


def normalize_stage(
    stage: str,
    raw_map: dict[str, list[str]],
    table: MappingTable,
    collapse: bool = False,
) -> tuple[set[str], list[dict[str, str]]]:
    """Normalize every raw ID of one stage. Returns (technique set, audit rows).

    Nothing is dropped: invalid and unmapped IDs stay in the set, flagged in the audit.
    """
    techniques: set[str] = set()
    audit: list[dict[str, str]] = []
    for raw in sorted(raw_map):
        norm, status, rules = normalize_id(raw, table, collapse)
        rules.append("N5:merged" if norm in techniques else "N5")
        rules.append("N6")
        techniques.add(norm)
        audit.append(
            {
                "stage": stage,
                "raw_id": raw,
                "normalized_id": norm,
                "status": status,
                "rules_applied": ";".join(rules),
                "source_rules": ";".join(raw_map[raw]),
            }
        )
    return techniques, audit
