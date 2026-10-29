"""Backend test helpers.

Empirical-mode tests below use small hand-written JSON documents and a constructed
PE *header* (no code) as TEST DOUBLES inside a temporary data directory. They
exercise validation and plumbing only; they are not results and are never shipped.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)
from fastapi.testclient import TestClient  # noqa: E402

from webapp.backend import worker  # noqa: E402
from webapp.backend.api import create_app  # noqa: E402
from webapp.backend.config import ISOLATION_ACK_PHRASE, Settings  # noqa: E402

FAKE_CAPA = Path(__file__).with_name("fake_capa.py")
APPROVAL = "TEST-APPROVAL-0001"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings()
    s.data_dir = tmp_path / "data"
    s.max_json_bytes = 64 * 1024
    s.max_pe_bytes = 64 * 1024
    return s


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def enable_fake_capa(settings: Settings, pe: bool = True) -> None:
    """Point the runner at a test double that emits capa-shaped JSON. Mimics an operator enabling it."""
    settings.extra["capa_command"] = [sys.executable, str(FAKE_CAPA)]
    settings.capa_expected_version = "9.9.9-test-double"
    if pe:
        settings.allow_sample_upload = True
        settings.static_analysis_enabled = True
        settings.isolation_ack = ISOLATION_ACK_PHRASE


def run_worker(settings: Settings) -> list[int]:
    done = []
    while (job_id := worker.run_once(settings)) is not None:
        done.append(job_id)
    return done


def make_pe(marker: bytes = b"") -> bytes:
    """A structurally valid PE32 header with one section and no code (test double)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    fh = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x0102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<H", opt, 68, 2)
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<III", sec, 8, 0x1000, 0x1000, 0x200)
    return bytes(dos) + b"PE\0\0" + fh + bytes(opt) + bytes(sec) + marker.ljust(64, b"\0")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capa_doc(sample_sha: str, rules: dict[str, list[str]]) -> bytes:
    return json.dumps({"meta": {"sample": {"sha256": sample_sha}},
                       "rules": {n: {"meta": {"attack": [{"id": t} for t in ids]}} for n, ids in rules.items()}}).encode()


def recovery_doc(sample_sha: str, payload_sha: str, *, v4_errors: int = 0, used: int = 5, limit: int = 20,
                 source: str = "operator_tool") -> bytes:
    sections = [{"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x1000}]
    return json.dumps({
        "sample_sha256": sample_sha, "check_source": source, "payload_sha256": payload_sha,
        "budget_used": used, "budget_limit": limit,
        "checks": {
            "V1": {"passed": True, "dos_magic": "MZ", "nt_signature": "PE", "number_of_sections": 1},
            "V2": {"passed": True, "stored_payload_sha256": payload_sha},
            "V3": {"passed": True, "entry_point_rva": 0x1000, "sections": sections},
            "V4": {"passed": v4_errors == 0, "import_errors": v4_errors},
            "V5": {"passed": True},
        }}).encode()


def new_sample(client: TestClient, sample_sha: str, mode: str = "empirical", **kw) -> dict:
    body = {"sha256": sample_sha, "label": kw.pop("label", "test"), "mode": mode,
            "approval_id": APPROVAL if mode == "empirical" else None,
            "source": "test double", "retrieved": "2026-10-27", **kw}
    r = client.post("/api/samples", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def upload(client: TestClient, sample_id: int, kind: str, data: bytes, name: str = "f.json"):
    return client.post(f"/api/samples/{sample_id}/artifacts", data={"kind": kind},
                       files={"file": (name, io.BytesIO(data), "application/octet-stream")})
