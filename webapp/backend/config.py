"""VisibilityLab settings, read from environment variables (see webapp/.env.example).

Nothing here is a secret. Unsafe capabilities are off unless explicitly enabled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ISOLATION_ACK_PHRASE = "I_CONFIRM_THIS_WORKER_RUNS_IN_AN_ISOLATED_ANALYSIS_VM"


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw and raw.strip() else default


def _path(name: str, default: Path | None) -> Path | None:
    raw = os.environ.get(name)
    if raw and raw.strip():
        p = Path(raw.strip())
        return p if p.is_absolute() else (PROJECT_ROOT / p)
    return default


@dataclass
class Settings:
    data_dir: Path = PROJECT_ROOT / "webapp" / "data"
    host: str = "127.0.0.1"
    port: int = 8000
    allow_remote: bool = False
    cors_origins: tuple[str, ...] = ("http://localhost:3000", "http://127.0.0.1:3000")

    # Upload limits (bytes)
    max_json_bytes: int = 25 * 1024 * 1024
    max_cape_bytes: int = 150 * 1024 * 1024
    max_pe_bytes: int = 50 * 1024 * 1024
    max_bundle_bytes: int = 60 * 1024 * 1024
    max_bundle_uncompressed: int = 250 * 1024 * 1024

    # Gate 3 / safety switches
    allow_sample_upload: bool = False  # storing PE files at all
    static_analysis_enabled: bool = False  # running capa on PE files
    isolation_ack: str = ""  # must equal ISOLATION_ACK_PHRASE for PE analysis

    # capa (pinned)
    capa_path: Path | None = None
    capa_expected_version: str = ""
    capa_rules: Path | None = None
    capa_timeout_s: int = 600
    capa_max_output_bytes: int = 200 * 1024 * 1024

    # ATT&CK mapping for empirical runs
    attack_mapping: Path = PROJECT_ROOT / "mappings" / "attack_enterprise_v20.0.csv"
    attack_mapping_version: str = "ATT&CK Enterprise v20.0"
    # Synthetic runs use the fictional fixture table
    synthetic_mapping: Path = PROJECT_ROOT / "fixtures" / "attack_map.csv"
    synthetic_mapping_version: str = "Synthetic mapping v1 (fixture, not the official ATT&CK export)"

    worker_poll_s: float = 1.0
    extra: dict = field(default_factory=dict)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "visibilitylab.sqlite3"

    @property
    def pe_analysis_allowed(self) -> bool:
        has_capa = self.capa_path is not None or bool(self.extra.get("capa_command"))
        return self.static_analysis_enabled and self.isolation_ack == ISOLATION_ACK_PHRASE and has_capa

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls()
        s.data_dir = _path("VL_DATA_DIR", s.data_dir)
        s.host = os.environ.get("VL_HOST", s.host).strip() or s.host
        s.port = _int("VL_PORT", s.port)
        s.allow_remote = _bool("VL_ALLOW_REMOTE", False)
        origins = os.environ.get("VL_CORS_ORIGINS")
        if origins:
            s.cors_origins = tuple(o.strip() for o in origins.split(",") if o.strip())
        mb = 1024 * 1024
        s.max_json_bytes = _int("VL_MAX_JSON_MB", 25) * mb
        s.max_cape_bytes = _int("VL_MAX_CAPE_MB", 150) * mb
        s.max_pe_bytes = _int("VL_MAX_PE_MB", 50) * mb
        s.max_bundle_bytes = _int("VL_MAX_BUNDLE_MB", 60) * mb
        s.allow_sample_upload = _bool("VL_ALLOW_SAMPLE_UPLOAD", False)
        s.static_analysis_enabled = _bool("VL_STATIC_ANALYSIS_ENABLED", False)
        s.isolation_ack = os.environ.get("VL_ISOLATION_ACK", "").strip()
        s.capa_path = _path("VL_CAPA_PATH", None)
        s.capa_expected_version = os.environ.get("VL_CAPA_EXPECTED_VERSION", "").strip()
        s.capa_rules = _path("VL_CAPA_RULES", None)
        s.capa_timeout_s = _int("VL_CAPA_TIMEOUT_S", 600)
        s.attack_mapping = _path("VL_ATTACK_MAPPING", s.attack_mapping)
        s.attack_mapping_version = os.environ.get("VL_ATTACK_MAPPING_VERSION", s.attack_mapping_version)
        return s

    def ensure_dirs(self) -> None:
        for sub in ("evidence", "quarantine", "jobs", "tmp"):
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)
