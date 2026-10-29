"""Run a pinned capa executable in a subprocess. capa analyses files statically; it does not run them.

Safety properties:
* the executable is an explicitly configured absolute path, never looked up on PATH;
* its reported version must equal the pinned VL_CAPA_EXPECTED_VERSION;
* arguments are a list (no shell), stdin is closed, the environment is minimal,
  a timeout and an output size cap are enforced;
* PE files are analysed only when static analysis is enabled AND the isolation
  acknowledgement is set, i.e. the operator states that this worker runs in an
  isolated analysis VM (Review 1: "Isolated VM, no network route").
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .config import Settings


class ToolUnavailable(RuntimeError):
    """capa is not configured, not allowed, or not the pinned version. The stage awaits input."""


class ToolFailed(RuntimeError):
    """capa ran but failed (exit code, timeout or unusable output)."""


@dataclass
class CapaResult:
    stdout: bytes
    version: str


def _env() -> dict[str, str]:
    keep = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["PATH"] = os.environ.get("SYSTEMROOT", "") or ""
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _run(cmd: list[str], timeout: int, max_out: int, cwd: Path) -> subprocess.CompletedProcess:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                              cwd=cwd, env=_env(), shell=False, creationflags=flags)
    except subprocess.TimeoutExpired:
        raise ToolFailed(f"capa timed out after {timeout} s") from None
    except OSError as exc:
        raise ToolUnavailable(f"capa could not be started: {exc.strerror}") from None
    if len(proc.stdout) > max_out:
        raise ToolFailed("capa output exceeded the configured size cap")
    return proc


def base_command(settings: Settings) -> list[str]:
    """The configured capa command. Tests may set settings.extra['capa_command'] to a test double."""
    if settings.extra.get("capa_command"):
        return list(settings.extra["capa_command"])
    if settings.capa_path is None:
        raise ToolUnavailable("capa is not configured (set VL_CAPA_PATH to a pinned capa executable)")
    if not settings.capa_path.is_file():
        raise ToolUnavailable(f"configured capa executable not found: {settings.capa_path}")
    return [str(settings.capa_path)]


def check_version(settings: Settings, cwd: Path) -> str:
    cmd = base_command(settings)
    if not settings.capa_expected_version:
        raise ToolUnavailable("VL_CAPA_EXPECTED_VERSION is not set; capa must be version-pinned")
    proc = _run(cmd + ["--version"], 60, 1 << 16, cwd)
    text = (proc.stdout + proc.stderr).decode("utf-8", "replace").strip()
    if settings.capa_expected_version not in text:
        raise ToolUnavailable(
            f"capa version mismatch: expected {settings.capa_expected_version!r}, tool reports {text[:80]!r}")
    return settings.capa_expected_version


def run_capa(settings: Settings, input_path: Path, fmt: str, cwd: Path) -> CapaResult:
    """Run capa -j on one input. fmt is 'pe' (Stages A/B) or 'cape' (Stage C, CAPE report JSON)."""
    if fmt not in ("pe", "cape"):
        raise ValueError("fmt must be 'pe' or 'cape'")
    if fmt == "pe" and not settings.pe_analysis_allowed:
        raise ToolUnavailable(
            "static analysis of PE files is disabled: set VL_STATIC_ANALYSIS_ENABLED=true, VL_CAPA_PATH and "
            "VL_ISOLATION_ACK only on an isolated analysis VM")
    version = check_version(settings, cwd)
    cmd = base_command(settings) + ["-j", "-f", fmt]
    if settings.capa_rules is not None:
        cmd += ["-r", str(settings.capa_rules)]
    cmd.append(str(input_path))
    proc = _run(cmd, settings.capa_timeout_s, settings.capa_max_output_bytes, cwd)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["(no message)"]
        raise ToolFailed(f"capa exited with code {proc.returncode}: {err[0][:300]}")
    return CapaResult(stdout=proc.stdout, version=version)
