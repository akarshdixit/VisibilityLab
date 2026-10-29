"""End-to-end processing of one specs file: gates, normalization, metrics, classification, seal.

Spec file: a JSON list, one object per sample::

    {
      "sha256": "<packed sample SHA-256>",
      "mode": "synthetic" | "pilot",
      "approval_id": "<institutional approval reference>" | null,
      "label": "optional display name",
      "inputs":       {"A": "rel/path.json", "B_recovery": ..., "B": ..., "C": ..., "S": ..., "evidence": ...},
      "input_sha256": {"A": "<sha256>", ...}
    }

Input paths are relative to the specs file. Only reports and records are read;
no sample binary is ever opened, copied or executed.
"""

from __future__ import annotations

import csv
import shutil
from pathlib import Path
from typing import Any

from .capa_io import (
    ReportFormatError,
    parse_json_bytes,
    reported_sample_sha256,
    techniques_from_capa,
    techniques_from_labels,
)
from .classify import (
    GAIN_COLUMNS,
    RESIDUAL_COLUMNS,
    ClassificationError,
    attribute_gains,
    class_counts,
    classify_residual,
    pk_summary,
)
from .hashing import IntegrityError, is_sha256, normalize_sha256, read_verified, write_json
from .manifest import build_manifest, hash_outputs, write_manifest
from .metrics import ND, MEASURES, compute_metrics
from .normalize import AUDIT_COLUMNS, MappingTable, normalize_stage
from .recovery import GateResult, evaluate_recovery

KNOWN_INPUTS = ("A", "B_recovery", "B", "C", "S", "evidence")
MODES = ("synthetic", "pilot")
STAGES = ("A", "B", "C", "S")
SYNTHETIC_NOTICE = (
    "SYNTHETIC DEMONSTRATION DATA - fictional inputs; not a result about any real sample"
)
SUMMARY_NAME = "summary_metrics.csv"
CLASS_LETTERS = ("P", "K", "O", "E", "T", "M", "U")


class GateError(Exception):
    """The whole run is refused (bad spec, missing approval, payload without recovery record)."""


# ----------------------------------------------------------------------------- spec validation


def load_specs(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    try:
        doc = parse_json_bytes(path.read_bytes(), path.name)
    except FileNotFoundError:
        raise GateError(f"specs file not found: {path}") from None
    except ReportFormatError as exc:
        raise GateError(str(exc)) from None
    if not isinstance(doc, list) or not doc:
        raise GateError("specs file must be a non-empty JSON list of sample objects")
    for i, spec in enumerate(doc):
        validate_spec(spec, i)
    shas = [s["sha256"] for s in doc]
    if len(set(shas)) != len(shas):
        raise GateError("specs file lists the same sample SHA-256 more than once")
    return doc


def validate_spec(spec: Any, index: int = 0) -> None:
    """Raise GateError if the spec breaks any rule. Normalizes the sha256 in place."""
    where = f"spec #{index}"
    if not isinstance(spec, dict):
        raise GateError(f"{where}: must be a JSON object")
    try:
        spec["sha256"] = normalize_sha256(spec.get("sha256"))
    except ValueError as exc:
        raise GateError(f"{where}: {exc}") from None
    where = f"spec {spec.get('label') or spec['sha256'][:12]}"

    mode = spec.get("mode")
    if mode not in MODES:
        raise GateError(f"{where}: mode must be one of {MODES}, got {mode!r}")
    approval = spec.get("approval_id")
    if mode == "pilot" and (not isinstance(approval, str) or not approval.strip()):
        raise GateError(
            f"{where}: Gate 3 - pilot mode requires an approval_id "
            "(written institutional approval must exist first)"
        )

    inputs, hashes = spec.get("inputs"), spec.get("input_sha256")
    if not isinstance(inputs, dict) or not isinstance(hashes, dict):
        raise GateError(f"{where}: 'inputs' and 'input_sha256' must be objects")
    unknown = sorted(set(inputs) - set(KNOWN_INPUTS))
    if unknown:
        raise GateError(f"{where}: unknown input keys {unknown}; known keys are {list(KNOWN_INPUTS)}")
    for key, rel in inputs.items():
        if not isinstance(rel, str) or not rel.strip():
            raise GateError(f"{where}: input {key} must be a path string")
        if not is_sha256(hashes.get(key)):
            raise GateError(f"{where}: input {key} has no valid recorded SHA-256 in input_sha256")
    if "B" in inputs and "B_recovery" not in inputs:
        raise GateError(f"{where}: a payload report B was given without a recovery record (B_recovery)")


# ----------------------------------------------------------------------------- one sample


def _stage(status: str, notes: list[str] | None = None) -> dict[str, Any]:
    return {"status": status, "notes": list(notes or [])}


def _load_stage(
    key: str, parsed: dict[str, Any], errors: dict[str, str], expected_sample: str | None
) -> tuple[dict[str, Any], dict[str, list[str]] | None]:
    """Turn a parsed input into (stage record, raw ID map). Failures are recorded, not fatal."""
    if key not in parsed and key not in errors:
        return _stage("missing", ["input not supplied"]), None
    if key in errors:
        return _stage("failed", [errors[key]]), None
    doc = parsed[key]
    try:
        raw = techniques_from_labels(doc, key) if key == "S" else techniques_from_capa(doc, key)
    except ReportFormatError as exc:
        return _stage("failed", [str(exc)]), None
    notes = []
    if key != "S":
        stated = reported_sample_sha256(doc)
        if stated is None:
            notes.append("report does not state meta.sample.sha256; sample link not cross-checked")
        elif expected_sample and stated != expected_sample:
            return _stage("failed", [f"report describes sample {stated[:12]}..., expected {expected_sample[:12]}..."]), None
    return _stage("ok", notes), raw


def run_sample(
    spec: dict[str, Any],
    base_dir: Path,
    mapping: MappingTable,
    out_dir: Path,
    collapse: bool = False,
) -> dict[str, Any]:
    """Process one sample and write its folder. Raises IntegrityError if any input hash differs."""
    sha, mode = spec["sha256"], spec["mode"]
    synthetic = mode == "synthetic"
    inputs: dict[str, str] = spec["inputs"]

    # 2 - hash gate: every input is read once and checked before anything is parsed.
    raw_bytes: dict[str, bytes] = {}
    for key in sorted(inputs):
        raw_bytes[key] = read_verified(base_dir / inputs[key], spec["input_sha256"][key])

    sample_dir = out_dir / sha[:12]
    if sample_dir.exists():
        shutil.rmtree(sample_dir)
    (sample_dir / "raw").mkdir(parents=True)

    parsed: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for key, data in raw_bytes.items():
        try:
            doc = parse_json_bytes(data, key)
        except ReportFormatError as exc:
            errors[key] = str(exc)
            continue
        if synthetic and not (isinstance(doc, dict) and doc.get("synthetic") is True):
            errors[key] = (
                f"{key}: synthetic mode accepts only inputs marked \"synthetic\": true; "
                "real outputs need pilot mode with an approval_id"
            )
            continue
        parsed[key] = doc

    # 3 - A, C, S load independently.
    stages: dict[str, dict[str, Any]] = {}
    raw_maps: dict[str, dict[str, list[str]] | None] = {}
    for key in ("A", "C", "S"):
        stages[key], raw_maps[key] = _load_stage(key, parsed, errors, sha)

    # 4 - recovery gate.
    gate: GateResult | None = None
    if "B_recovery" in errors:
        gate = GateResult(False, [f"recovery record unusable: {errors['B_recovery']}"])
    elif "B_recovery" in parsed:
        gate = evaluate_recovery(parsed["B_recovery"], sha, mode)

    # 5 - B only if the gate accepts.
    if gate is None:
        stages["B"], raw_maps["B"] = _stage("not_recovered", ["no recovery record supplied"]), None
    elif not gate.accepted:
        notes = list(gate.reasons)
        if "B" in inputs:
            notes.append("payload report B supplied but not used because the gate rejected recovery")
        stages["B"], raw_maps["B"] = _stage("not_recovered", notes), None
    else:
        stages["B"], raw_maps["B"] = _load_stage("B", parsed, errors, gate.payload_sha256)

    # 6 - normalization (N1-N6).
    sets: dict[str, set[str] | None] = {}
    audit: list[dict[str, str]] = []
    for key in STAGES:
        if raw_maps[key] is None:
            sets[key] = None
            continue
        sets[key], rows = normalize_stage(key, raw_maps[key], mapping, collapse)
        audit.extend(rows)
        stages[key]["raw_ids"] = len(raw_maps[key])
        stages[key]["techniques"] = len(sets[key])
        flagged = sorted({r["normalized_id"] for r in rows if r["status"] in ("unmapped", "invalid_format", "deprecated")})
        if flagged:
            stages[key]["notes"].append(f"flagged (kept): {', '.join(flagged)}")

    # 7 - metrics.
    A, B, C, S = (sets[k] for k in STAGES)
    m = compute_metrics(A, B, C, S)

    # 8 - classification of residuals and gains.
    evidence_doc = parsed.get("evidence")
    residual_rows: list[dict[str, str]] = []
    gain_rows: list[dict[str, str]] = []
    residual = {"status": ND, "reason": "", "techniques": ND, "class_counts": ND, "pk_summary": ND}
    gains = {"status": ND, "reason": "", "techniques": ND, "attribution_counts": ND}
    if "evidence" in errors:
        evidence_problem = errors["evidence"]
    else:
        evidence_problem = None

    if B is None or C is None:
        residual["reason"] = "B or C not available, so C \\ B is not defined"
    elif evidence_problem:
        residual.update(status="failed", reason=evidence_problem)
    else:
        try:
            residual_rows = classify_residual(C - B, evidence_doc, parsed)
            counts = class_counts(residual_rows)
            residual.update(
                status="ok",
                techniques=sorted(C - B),
                class_counts=counts,
                pk_summary=pk_summary(counts),
            )
        except ClassificationError as exc:
            residual.update(status="failed", reason=str(exc))

    if A is None or B is None:
        gains["reason"] = "A or B not available, so B \\ A is not defined"
    elif evidence_problem:
        gains.update(status="failed", reason=evidence_problem)
    else:
        try:
            gain_rows = attribute_gains(B - A, evidence_doc, parsed)
            attr: dict[str, int] = {"payload": 0, "dump_artifact": 0, "uncertain": 0}
            for r in gain_rows:
                attr[r["attribution"]] += 1
            gains.update(status="ok", techniques=sorted(B - A), attribution_counts=attr)
        except ClassificationError as exc:
            gains.update(status="failed", reason=str(exc))

    results = {
        "notice": SYNTHETIC_NOTICE if synthetic else "pilot-mode run on approved inputs",
        "synthetic": synthetic,
        "label": spec.get("label", ""),
        "sample_sha256": sha,
        "mode": mode,
        "approval_id": spec.get("approval_id"),
        "stages": stages,
        "recovery_gate": gate.to_dict() if gate else {"accepted": False, "reasons": ["no recovery record supplied"]},
        "sets": {k: (sorted(v) if v is not None else ND) for k, v in sets.items()},
        "measures": m["measures"],
        "measure_inputs": m["inputs"],
        "secondary": {"S_overlap_C": m["S_overlap_C"], "S_inputs": m["S_inputs"],
                      "note": "sandbox labels S are reported beside the measures, never inside them"},
        "residual_classification": residual,
        "gain_attribution": gains,
        "research_questions": _research_questions(A, B, C),
    }

    # Write outputs, then seal.
    write_json(sample_dir / "results.json", results)
    _write_csv(sample_dir / "normalization_audit.csv", AUDIT_COLUMNS, audit)
    _write_csv(sample_dir / "residual_classification.csv", RESIDUAL_COLUMNS, residual_rows)
    _write_csv(sample_dir / "gain_attribution.csv", GAIN_COLUMNS, gain_rows)
    raw_names = []
    for key, data in raw_bytes.items():
        name = f"raw/{key}.json"
        (sample_dir / name).write_bytes(data)
        raw_names.append(name)

    output_names = ["results.json", "normalization_audit.csv", "residual_classification.csv",
                    "gain_attribution.csv", *sorted(raw_names)]
    manifest = build_manifest(
        sample_sha256=sha,
        mode=mode,
        approval_id=spec.get("approval_id"),
        synthetic=synthetic,
        mapping=mapping.provenance(),
        stages={k: stages[k]["status"] for k in STAGES},
        inputs={k: {"path": inputs[k], "sha256": spec["input_sha256"][k]} for k in inputs},
        outputs=hash_outputs(sample_dir, output_names),
        collapse_subtechniques=collapse,
    )
    write_manifest(sample_dir, manifest)
    results["manifest_sha256"] = manifest["manifest_sha256"]
    results["output_dir"] = str(sample_dir)
    return results


def _research_questions(A, B, C) -> dict[str, Any]:
    def s(x):
        return sorted(x) if x is not None else ND

    both = lambda *xs: all(x is not None for x in xs)  # noqa: E731
    return {
        "RQ1_packed_static_visible": s(A),
        "RQ1_packed_also_in_dynamic": s(A & C) if both(A, C) else ND,
        "RQ2_gained_after_unpacking": s(B - A) if both(A, B) else ND,
        "RQ2_kept": s(A & B) if both(A, B) else ND,
        "RQ2_lost": s(A - B) if both(A, B) else ND,
        "RQ2_dynamic_only_after_unpacking": s((B & C) - A) if both(A, B, C) else ND,
        "RQ3_residual_C_minus_B": s(C - B) if both(B, C) else ND,
    }


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


# ----------------------------------------------------------------------------- batch

SUMMARY_COLUMNS = (
    ["sample_sha256", "label", "mode", "synthetic", "run_status",
     "stage_A", "stage_B", "stage_C", "stage_S"]
    + list(MEASURES)
    + ["S_overlap_C"]
    + [f"class_{c}" for c in CLASS_LETTERS]
    + ["pk_summary", "manifest_sha256", "note"]
)


def run_batch(
    specs_path: str | Path,
    mapping: MappingTable,
    out_dir: str | Path,
    collapse: bool = False,
) -> list[dict[str, Any]]:
    """Validate every spec first (any refusal stops the whole run), then process each sample.

    An integrity failure aborts only that sample; it is recorded in the summary.
    """
    specs_path = Path(specs_path)
    specs = load_specs(specs_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base_dir = specs_path.parent

    summary: list[dict[str, Any]] = []
    for spec in specs:
        row: dict[str, Any] = {c: "" for c in SUMMARY_COLUMNS}
        row.update(sample_sha256=spec["sha256"], label=spec.get("label", ""), mode=spec["mode"],
                   synthetic=spec["mode"] == "synthetic")
        try:
            res = run_sample(spec, base_dir, mapping, out_dir, collapse)
        except IntegrityError as exc:
            row.update(run_status="aborted_integrity", note=str(exc))
            stale = out_dir / spec["sha256"][:12]
            if stale.exists():
                shutil.rmtree(stale)
            summary.append(row)
            continue
        row["run_status"] = "completed"
        for k in STAGES:
            row[f"stage_{k}"] = res["stages"][k]["status"]
        row.update(res["measures"])
        row["S_overlap_C"] = res["secondary"]["S_overlap_C"]
        counts = res["residual_classification"]["class_counts"]
        for c in CLASS_LETTERS:
            row[f"class_{c}"] = counts[c] if isinstance(counts, dict) else ND
        row["pk_summary"] = res["residual_classification"]["pk_summary"]
        row["manifest_sha256"] = res["manifest_sha256"]
        row["note"] = "; ".join(res["recovery_gate"]["reasons"]) if not res["recovery_gate"]["accepted"] else ""
        summary.append(row)

    _write_csv(out_dir / SUMMARY_NAME, SUMMARY_COLUMNS, summary)
    return summary
