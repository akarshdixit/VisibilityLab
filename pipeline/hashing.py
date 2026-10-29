"""SHA-256 hashing, input-integrity checks and canonical JSON serialization."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(Exception):
    """An input file is missing or does not match the SHA-256 recorded for it."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def is_sha256(value: Any) -> bool:
    """True if value is already a 64-character lowercase hex string."""
    return isinstance(value, str) and bool(SHA256_RE.match(value))


def normalize_sha256(value: Any) -> str:
    """Trim and lower-case a SHA-256 string; raise ValueError if it is not 64 hex chars."""
    if not isinstance(value, str):
        raise ValueError("SHA-256 must be a string")
    cleaned = value.strip().lower()
    if not SHA256_RE.match(cleaned):
        raise ValueError(f"not a SHA-256 (need 64 hex characters): {value!r}")
    return cleaned


def read_verified(path: str | Path, expected_sha256: str) -> bytes:
    """Read a file once and check its bytes against the recorded hash.

    The same bytes that were hashed are returned, so the content that is later
    parsed is exactly the content that was verified.
    """
    path = Path(path)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise IntegrityError(f"input file not found: {path}") from None
    actual = sha256_bytes(data)
    if actual != expected_sha256.strip().lower():
        raise IntegrityError(
            f"{path.name}: SHA-256 is {actual} but the spec records {expected_sha256}"
        )
    return data


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_json(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj))


def write_json(path: str | Path, obj: Any) -> None:
    """Write human-readable JSON with LF line endings on every platform."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
