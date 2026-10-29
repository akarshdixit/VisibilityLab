"""Shared helpers. Tests run on copies of the synthetic fixtures in a temp folder."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from pipeline.hashing import sha256_file
from pipeline.normalize import load_mapping

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


@pytest.fixture
def fx(tmp_path: Path) -> Path:
    """A private copy of fixtures/ that a test may modify."""
    dst = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, dst)
    return dst


@pytest.fixture
def mapping():
    return load_mapping(FIXTURES / "attack_map.csv", "Synthetic mapping v1")


def read_specs(fx: Path) -> list[dict]:
    return json.loads((fx / "specs.json").read_text(encoding="utf-8"))


def write_specs(fx: Path, specs: list[dict]) -> None:
    (fx / "specs.json").write_text(json.dumps(specs, indent=2), encoding="utf-8")


def rewrite_input(fx: Path, spec: dict, key: str, obj, rehash: bool = True) -> None:
    """Replace one input file; optionally record its new hash in the spec (a legitimate edit)."""
    path = fx / spec["inputs"][key]
    text = obj if isinstance(obj, str) else json.dumps(obj, indent=2)
    path.write_text(text, encoding="utf-8")
    if rehash:
        spec["input_sha256"][key] = sha256_file(path)
