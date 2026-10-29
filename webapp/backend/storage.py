"""Content-addressed file storage with generated names.

Layout under the data directory (never inside the frontend's public folder):

    evidence/<aa>/<sha256>.json   raw, immutable JSON evidence (reports, records)
    quarantine/<sha256>.sample    PE files (sample or payload); read-only, no
                                  executable extension, never served back
    jobs/<job id>/                derived results (pipeline outputs)
    tmp/                          in-progress uploads

User-supplied filenames are stored only as metadata; they never form a path.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO

from pipeline.hashing import is_sha256

CHUNK = 1 << 16
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


class UploadTooLarge(ValueError):
    pass


class StorageError(ValueError):
    pass


def safe_display_name(name: str | None) -> str:
    """Sanitized original filename for display/audit only (never used as a path)."""
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    return _SAFE_NAME.sub("_", base)[:200]


def receive(stream: BinaryIO, data_dir: Path, limit: int) -> tuple[Path, str, int]:
    """Copy an upload stream to a temp file, hashing as it goes and enforcing the size limit."""
    tmp_dir = data_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=tmp_dir, prefix="upload-", suffix=".part")
    h, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise UploadTooLarge(f"file exceeds the {limit // (1024 * 1024)} MB limit")
                h.update(chunk)
                out.write(chunk)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name), h.hexdigest(), size


def _inside(base: Path, target: Path) -> Path:
    base_r, target_r = base.resolve(), target.resolve()
    if base_r != target_r and base_r not in target_r.parents:
        raise StorageError("resolved path escapes the data directory")
    return target_r


def storage_path(data_dir: Path, storage_name: str) -> Path:
    """Resolve an internal storage name, refusing anything outside the data directory."""
    if not re.fullmatch(r"(evidence/[0-9a-f]{2}/[0-9a-f]{64}\.json|quarantine/[0-9a-f]{64}\.sample)", storage_name):
        raise StorageError("invalid storage name")
    return _inside(data_dir, data_dir / storage_name)


def commit_json(tmp: Path, data_dir: Path, sha256: str) -> str:
    if not is_sha256(sha256):
        raise StorageError("bad hash")
    name = f"evidence/{sha256[:2]}/{sha256}.json"
    dest = _inside(data_dir, data_dir / name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        tmp.unlink(missing_ok=True)
    else:
        shutil.move(str(tmp), dest)
        _read_only(dest)
    return name


def commit_bytes_json(data: bytes, data_dir: Path) -> tuple[str, str]:
    sha = hashlib.sha256(data).hexdigest()
    fd, name = tempfile.mkstemp(dir=data_dir / "tmp", suffix=".part")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return commit_json(Path(name), data_dir, sha), sha


def commit_quarantine(tmp: Path, data_dir: Path, sha256: str) -> str:
    if not is_sha256(sha256):
        raise StorageError("bad hash")
    name = f"quarantine/{sha256}.sample"
    dest = _inside(data_dir, data_dir / name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        tmp.unlink(missing_ok=True)
    else:
        shutil.move(str(tmp), dest)
        _read_only(dest)
    return name


def _read_only(path: Path) -> None:
    path.chmod(stat.S_IREAD)


def job_dir(data_dir: Path, job_id: int) -> Path:
    return _inside(data_dir, data_dir / "jobs" / str(int(job_id)))
