"""Candidate register: provenance of each candidate sample, keyed by SHA-256.

The register stores metadata only. It never fetches, opens or executes a file.
"""

from __future__ import annotations

import csv
import datetime as dt
import re
from pathlib import Path

from .hashing import normalize_sha256

COLUMNS = ["sha256", "source", "retrieved", "status", "packer_label", "note"]
INITIAL_STATUS = "candidate"
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class RegistryError(ValueError):
    """A register row breaks one of the register rules."""


def read_register(path: str | Path) -> list[dict[str, str]]:
    path = Path(path)
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            raise RegistryError(
                f"{path.name}: unexpected columns {reader.fieldnames}; expected {COLUMNS}"
            )
        return list(reader)


def validate_date(value: str) -> str:
    value = (value or "").strip()
    if not _DATE_RE.match(value):
        raise RegistryError(f"retrieval date must be YYYY-MM-DD, got {value!r}")
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        raise RegistryError(f"retrieval date is not a real date: {value!r}") from None
    return value


def add_candidate(
    path: str | Path,
    sha256: str,
    source: str,
    retrieved: str,
    packer_label: str = "",
    note: str = "",
) -> dict[str, str]:
    """Append one candidate row and return it. Raises RegistryError on any rule violation."""
    try:
        sha = normalize_sha256(sha256)
    except ValueError as exc:
        raise RegistryError(str(exc)) from None
    source = (source or "").strip()
    if not source:
        raise RegistryError("source must be a non-empty description")
    retrieved = validate_date(retrieved)

    path = Path(path)
    rows = read_register(path)
    if any(r["sha256"] == sha for r in rows):
        raise RegistryError(f"SHA-256 {sha} is already in the register")

    row = {
        "sha256": sha,
        "source": source,
        "retrieved": retrieved,
        "status": INITIAL_STATUS,
        "packer_label": (packer_label or "").strip(),
        "note": (note or "").strip(),
    }
    new_file = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)
    return row
