"""Per-sample manifest: a hash-linked seal over inputs, outputs, tools and mapping.

``manifest_sha256`` is the SHA-256 of the canonical JSON of every field except
``created_utc`` and ``manifest_sha256`` itself, so identical inputs and tools
give an identical hash on a rerun.
"""

from __future__ import annotations

import datetime as dt
import json
import platform
from pathlib import Path
from typing import Any

from . import __version__
from .hashing import sha256_file, sha256_json, write_json

MANIFEST_NAME = "manifest.json"
_EXCLUDED = ("created_utc", "manifest_sha256")


def manifest_hash(manifest: dict[str, Any]) -> str:
    return sha256_json({k: v for k, v in manifest.items() if k not in _EXCLUDED})


def build_manifest(
    *,
    sample_sha256: str,
    mode: str,
    approval_id: str | None,
    synthetic: bool,
    mapping: dict[str, str],
    stages: dict[str, str],
    inputs: dict[str, dict[str, str]],
    outputs: dict[str, str],
    collapse_subtechniques: bool,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "sample_sha256": sample_sha256,
        "mode": mode,
        "approval_id": approval_id,
        "synthetic": synthetic,
        "tool": {"pipeline": __version__, "python": platform.python_version()},
        "mapping": dict(mapping),
        "options": {"collapse_subtechniques": collapse_subtechniques},
        "stages": dict(stages),
        "inputs": {k: dict(v) for k, v in sorted(inputs.items())},
        "outputs": dict(sorted(outputs.items())),
    }
    body["manifest_sha256"] = manifest_hash(body)
    body["created_utc"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return body


def hash_outputs(sample_dir: Path, names: list[str]) -> dict[str, str]:
    return {name: sha256_file(sample_dir / name) for name in names}


def write_manifest(sample_dir: Path, manifest: dict[str, Any]) -> Path:
    path = sample_dir / MANIFEST_NAME
    write_json(path, manifest)
    return path


def verify_manifest(sample_dir: str | Path) -> list[str]:
    """Return a list of problems; an empty list means the seal holds."""
    sample_dir = Path(sample_dir)
    path = sample_dir / MANIFEST_NAME
    if not path.exists():
        return [f"{path}: no manifest"]
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path}: unreadable ({exc.msg})"]
    problems = []
    if manifest_hash(manifest) != manifest.get("manifest_sha256"):
        problems.append("manifest_sha256 does not match the manifest contents")
    for name, expected in manifest.get("outputs", {}).items():
        file = sample_dir / name
        if not file.exists():
            problems.append(f"output missing: {name}")
        elif sha256_file(file) != expected:
            problems.append(f"output changed since sealing: {name}")
    return problems
