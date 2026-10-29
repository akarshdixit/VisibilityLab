"""Validation of untrusted uploads: PE headers, JSON evidence schemas and analysis bundles.

Nothing here executes or loads code from an upload. PE parsing reads fixed-size
header structures with explicit bounds checks; JSON is parsed with the standard
library and then checked against the shape each artifact kind requires.
"""

from __future__ import annotations

import io
import struct
import zipfile
from typing import Any

from pipeline.capa_io import (
    ReportFormatError,
    parse_json_bytes,
    reported_sample_sha256,
    techniques_from_capa,
    techniques_from_labels,
)
from pipeline.hashing import is_sha256

JSON_KINDS = ("A", "B_recovery", "B", "C", "S", "evidence", "cape_report")
BINARY_KINDS = ("sample_pe", "payload_pe")
BUNDLE_NAMES = {f"{k}.json": k for k in JSON_KINDS}

KIND_LABELS = {
    "A": "capa JSON for the packed file (Stage A)",
    "B_recovery": "recovery record from the operator's validated tool (gate for Stage B)",
    "B": "capa JSON for the recovered payload (Stage B)",
    "C": "capa JSON produced by capa dynamic mode on the CAPE report (Stage C)",
    "S": "sandbox ATT&CK label list (secondary reference S)",
    "evidence": "analyst evidence file for residual classes and gain attribution",
    "cape_report": "genuine CAPE report JSON for the same sample (input to Stage C / S)",
    "sample_pe": "packed Windows PE sample (quarantined, never executed)",
    "payload_pe": "recovered payload PE from the separate recovery process (quarantined, never executed)",
}

_MACHINES = {0x14C: "i386", 0x8664: "amd64", 0x1C0: "arm", 0xAA64: "arm64"}


class ValidationError(ValueError):
    """An upload is rejected; the message is safe to show to the user."""


# ----------------------------------------------------------------------------- PE


def parse_pe_header(data: bytes) -> dict[str, Any]:
    """Read PE header metadata with bounds checks. Raises ValidationError if not a PE file."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValidationError("not a Windows PE file (missing MZ header)")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data) or e_lfanew > 0x10000:
        raise ValidationError("not a Windows PE file (bad e_lfanew)")
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValidationError("not a Windows PE file (missing PE signature)")
    machine, nsec, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    if opt + opt_size > len(data) or opt_size < 2:
        raise ValidationError("truncated PE optional header")
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic not in (0x10B, 0x20B):
        raise ValidationError("unknown PE optional header magic")
    pe32plus = magic == 0x20B
    meta: dict[str, Any] = {
        "machine": _MACHINES.get(machine, f"0x{machine:04x}"),
        "format": "PE32+" if pe32plus else "PE32",
        "number_of_sections": nsec,
        "timestamp": timestamp,
        "is_dll": bool(characteristics & 0x2000),
    }
    if opt_size >= 20:
        (meta["entry_point_rva"],) = struct.unpack_from("<I", data, opt + 16)
    subsys_off = opt + 68
    if subsys_off + 2 <= opt + opt_size:
        (meta["subsystem"],) = struct.unpack_from("<H", data, subsys_off)
    dd_base = opt + (112 if pe32plus else 96)
    clr = dd_base + 14 * 8
    meta["is_dotnet"] = bool(clr + 8 <= opt + opt_size and any(struct.unpack_from("<II", data, clr)))
    sections = []
    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rawsize = struct.unpack_from("<III", data, off + 8)
        sections.append({"name": name, "virtual_address": va, "virtual_size": vsize, "raw_size": rawsize})
    meta["sections"] = sections
    warnings = []
    if meta["is_dotnet"]:
        warnings.append(".NET assembly: the proposal scopes native PE files only")
    meta["warnings"] = warnings
    return meta


# ----------------------------------------------------------------------------- JSON evidence


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ValidationError(message)


def validate_json_artifact(kind: str, data: bytes, sample_sha256: str, mode: str) -> dict[str, Any]:
    """Parse and check one JSON evidence file. Returns the parsed document."""
    if kind not in JSON_KINDS:
        raise ValidationError(f"unknown artifact kind {kind!r}")
    try:
        doc = parse_json_bytes(data, kind)
    except ReportFormatError as exc:
        raise ValidationError(str(exc)) from None
    _require(isinstance(doc, dict), f"{kind}: top level must be a JSON object")

    marked = doc.get("synthetic") is True
    if mode == "synthetic":
        _require(marked, f"{kind}: synthetic samples accept only inputs marked \"synthetic\": true")
    else:
        _require(not marked, f"{kind}: input is marked synthetic and cannot be attached to an empirical sample")

    try:
        if kind in ("A", "B", "C"):
            techniques_from_capa(doc, kind)
        elif kind == "S":
            techniques_from_labels(doc, kind)
    except ReportFormatError as exc:
        raise ValidationError(str(exc)) from None

    if kind in ("A", "C"):
        stated = reported_sample_sha256(doc)
        _require(stated is None or stated == sample_sha256,
                 f"{kind}: report describes sample {str(stated)[:12]}..., not this sample")
    elif kind == "B_recovery":
        for key, typ in (("sample_sha256", str), ("check_source", str), ("payload_sha256", str),
                         ("checks", dict), ("budget_used", int), ("budget_limit", int)):
            _require(isinstance(doc.get(key), typ) and not isinstance(doc.get(key), bool),
                     f"B_recovery: field '{key}' missing or not a {typ.__name__}")
        _require(doc["sample_sha256"].lower() == sample_sha256,
                 "B_recovery: record is for a different sample (sample_sha256 mismatch)")
        _require(is_sha256(doc["payload_sha256"]), "B_recovery: payload_sha256 is not a lowercase SHA-256")
    elif kind == "evidence":
        for section in ("residual", "gains"):
            items = doc.get(section, [])
            _require(isinstance(items, list) and all(isinstance(i, dict) for i in items),
                     f"evidence: '{section}' must be a list of objects")
            for item in items:
                _require(isinstance(item.get("technique"), str), f"evidence: every '{section}' entry needs a technique")
    elif kind == "cape_report":
        target = doc.get("target", {})
        file_sha = target.get("file", {}).get("sha256") if isinstance(target, dict) and isinstance(target.get("file"), dict) else None
        _require(isinstance(file_sha, str), "cape_report: missing target.file.sha256, so the report cannot be tied to this sample")
        _require(file_sha.lower() == sample_sha256,
                 "cape_report: report is for a different file (target.file.sha256 mismatch)")
    return doc


def extract_cape_labels(report: dict[str, Any]) -> list[str]:
    """Sandbox-native ATT&CK labels from a CAPE report's ``ttps`` section (assumed CAPEv2 shape).

    Accepts entries of the form {"ttps": ["T1055", ...]} or {"ttp": "T1055"}.
    Returns an empty list when the section is absent; the caller then leaves S awaiting input.
    """
    labels: set[str] = set()
    for entry in report.get("ttps", []) or []:
        if not isinstance(entry, dict):
            continue
        values = entry.get("ttps")
        if isinstance(values, list):
            labels.update(v for v in values if isinstance(v, str) and v.strip())
        elif isinstance(entry.get("ttp"), str):
            labels.add(entry["ttp"])
    return sorted(labels)


# ----------------------------------------------------------------------------- bundles


def read_bundle(data: bytes, max_uncompressed: int) -> dict[str, bytes]:
    """Read a .zip analysis bundle in memory. Only flat, known names are accepted; nothing is extracted to disk."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValidationError("bundle is not a valid .zip file") from None
    infos = zf.infolist()
    _require(0 < len(infos) <= 16, "bundle must contain between 1 and 16 files")
    total = sum(i.file_size for i in infos)
    _require(total <= max_uncompressed, "bundle expands beyond the allowed size")
    files: dict[str, bytes] = {}
    for info in infos:
        if info.is_dir():
            continue
        name = info.filename
        _require(name in BUNDLE_NAMES,
                 f"bundle member {name[:60]!r} not allowed; use only {sorted(BUNDLE_NAMES)} at the top level")
        _require(info.flag_bits & 0x1 == 0, "encrypted bundle members are not accepted")
        content = zf.read(info)
        _require(len(content) == info.file_size, "bundle member size mismatch")
        files[BUNDLE_NAMES[name]] = content
    _require(bool(files), "bundle contains no recognised files")
    return files
