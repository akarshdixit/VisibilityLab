"""Static HTML overview of a batch output folder (standard library only, no scripts)."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .metrics import DEFINITIONS, MEASURES

_CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#14202b;background:#fff;max-width:1100px}
h1{font-size:22px}h2{font-size:18px;margin-top:28px;border-bottom:2px solid #1fa89a;padding-bottom:4px}
.warn{background:#fff3cd;border:1px solid #e0a82e;padding:10px 14px;border-radius:6px;font-weight:600}
table{border-collapse:collapse;margin:8px 0 16px;font-size:14px}
th,td{border:1px solid #c9d3dc;padding:5px 10px;text-align:left;vertical-align:top}
th{background:#10202e;color:#fff}.nd{color:#9a6b00;font-style:italic}.mono{font-family:Consolas,monospace;font-size:12px}
"""


def _cell(v) -> str:
    if v == "n/d":
        return '<td class="nd">n/d</td>'
    if isinstance(v, list):
        v = ", ".join(v) if v else "∅"
    return f"<td>{html.escape(str(v))}</td>"


def write_report(out_dir: str | Path, sample_shas: list[str]) -> Path:
    """Write out_dir/report.html covering the given samples (those completed in this batch)."""
    out_dir = Path(out_dir)
    results = [json.loads((out_dir / sha[:12] / "results.json").read_text(encoding="utf-8"))
               for sha in sample_shas]
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>Visibility Loss Report</title>"
             f"<style>{_CSS}</style></head><body><h1>Behavioral visibility loss - batch report</h1>"]
    if any(r.get("synthetic") for r in results):
        parts.append("<p class='warn'>SYNTHETIC DEMONSTRATION DATA. All IDs, hashes and reports are "
                     "fictional. Nothing here is a result about real malware.</p>")

    parts.append("<h2>Measures</h2><table><tr><th>Sample</th><th>B stage</th>"
                 + "".join(f"<th>{m}</th>" for m in MEASURES) + "<th>S∩C</th><th>Residual classes</th></tr>")
    for r in results:
        parts.append(f"<tr><td>{html.escape(r.get('label') or r['sample_sha256'][:12])}</td>"
                     + _cell(r["stages"]["B"]["status"])
                     + "".join(_cell(r["measures"][m]) for m in MEASURES)
                     + _cell(r["secondary"]["S_overlap_C"])
                     + _cell(r["residual_classification"]["pk_summary"]) + "</tr>")
    parts.append("</table><table><tr><th>Measure</th><th>Formula</th></tr>"
                 + "".join(f"<tr><td>{k}</td><td>{html.escape(v)}</td></tr>" for k, v in DEFINITIONS.items())
                 + "</table>")

    for r in results:
        parts.append(f"<h2>{html.escape(r.get('label') or '')} <span class='mono'>{r['sample_sha256']}</span></h2>")
        parts.append("<table><tr><th>Set</th><th>Status</th><th>Techniques (normalized)</th><th>Notes</th></tr>")
        for k in "ABCS":
            st = r["stages"][k]
            parts.append(f"<tr><td>{k}</td>{_cell(st['status'])}{_cell(r['sets'][k])}"
                         f"{_cell('; '.join(st['notes']))}</tr>")
        parts.append("</table>")
        gate = r["recovery_gate"]
        parts.append(f"<p><b>Recovery gate:</b> {'accepted' if gate['accepted'] else 'rejected'}"
                     + (": " + html.escape("; ".join(gate["reasons"])) if gate["reasons"] else "") + "</p>")
        parts.append("<table><tr><th>Research question</th><th>Techniques</th></tr>"
                     + "".join(f"<tr><td>{html.escape(k)}</td>{_cell(v)}</tr>"
                               for k, v in r["research_questions"].items()) + "</table>")
        rows_path = out_dir / r["sample_sha256"][:12] / "residual_classification.csv"
        lines = rows_path.read_text(encoding="utf-8").strip().splitlines()[1:]
        if lines:
            parts.append("<p><b>Residual classification (C \\ B)</b></p><pre class='mono'>"
                         + html.escape("\n".join(lines)) + "</pre>")
    parts.append("</body></html>")
    path = out_dir / "report.html"
    path.write_text("\n".join(parts), encoding="utf-8", newline="\n")
    return path


LIMITATIONS = [
    "Stage C (capa dynamic mode on a CAPE report) is a tool-generated reference, not ground truth: "
    "one sandbox run, one configuration, limited duration.",
    "capa rule coverage and scope limit what any stage can report (class T).",
    "ATT&CK mapping is ambiguous across tools; IDs are normalized against the recorded table and audited.",
    "Unpacking may fail; failed recovery is kept in the experiment and B-dependent measures are n/d, never 0.",
    "The measures describe overlap with a tool-generated reference, not the share of a sample's true capabilities.",
    "Results describe only this sample; no population or detection-rate claim is made.",
]

_PRINT_CSS = _CSS + """
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;border:1px solid #889}
.ok{background:#dff5ec}.failed{background:#fde2e1}.not_recovered{background:#fff1d6}.missing{background:#eef0f3}
@media print{body{margin:0;max-width:none}h2{break-after:avoid}table{break-inside:avoid}}
"""

_STAGE_NAMES = {"A": "A - packed static", "B": "B - payload static",
                "C": "C - dynamic reference", "S": "S - sandbox labels (secondary)"}


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _ref_table(rows: list[dict[str, str]], label_key: str, label_fmt) -> str:
    esc = html.escape
    return ("<table><tr><th>Technique</th><th>" + esc(label_key) + "</th><th>Evidence reference</th><th>Reason</th></tr>"
            + "".join(f"<tr><td>{esc(x['technique'])}</td><td>{esc(label_fmt(x))}</td>"
                      f"<td class='mono'>{esc(x['evidence_ref'] or '(none)')}</td><td>{esc(x['reason'])}</td></tr>"
                      for x in rows)
            + "</table>")


def write_sample_report(sample_dir: str | Path) -> Path:
    """Write sample_dir/report.html: a printable, self-contained per-sample research report.

    It renders the sealed outputs (results.json, CSVs, manifest.json) and is not itself sealed.
    """
    d = Path(sample_dir)
    r = json.loads((d / "results.json").read_text(encoding="utf-8"))
    m = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    esc = html.escape
    synthetic = r.get("synthetic", False)
    p = [f"<!doctype html><html><head><meta charset='utf-8'><title>Sample Report {esc(r['sample_sha256'][:12])}</title>"
         f"<style>{_PRINT_CSS}</style></head><body>",
         "<h1>Quantifying Behavioral Visibility Loss Due to Malware Packing - per-sample report</h1>"]
    if synthetic:
        p.append("<p class='warn'>SYNTHETIC RUN. All inputs are fictional fixtures. Nothing in this report "
                 "is a result about real malware.</p>")
    else:
        p.append(f"<p class='warn'>EMPIRICAL RUN on approved inputs (approval reference: "
                 f"{esc(str(r.get('approval_id')))}). Results describe this sample only.</p>")

    p.append("<h2>Sample and provenance</h2><table>"
             f"<tr><th>Sample SHA-256</th><td class='mono'>{esc(r['sample_sha256'])}</td></tr>"
             f"<tr><th>Label</th><td>{esc(r.get('label') or '')}</td></tr>"
             f"<tr><th>Run type</th><td>{'synthetic' if synthetic else 'empirical'} (pipeline mode {esc(r['mode'])})</td></tr>"
             f"<tr><th>Pipeline / Python</th><td>{esc(m['tool']['pipeline'])} / {esc(m['tool']['python'])}</td></tr>"
             f"<tr><th>ATT&amp;CK mapping</th><td>{esc(m['mapping']['name'])} - {esc(m['mapping']['version'])}"
             f"<br><span class='mono'>{esc(m['mapping']['sha256'])}</span></td></tr>"
             f"<tr><th>Manifest SHA-256</th><td class='mono'>{esc(m['manifest_sha256'])}</td></tr></table>")

    p.append("<h2>Stages</h2><table><tr><th>Stage</th><th>Status</th><th>Techniques</th><th>Notes</th></tr>")
    for k in "ABCS":
        st = r["stages"][k]
        p.append(f"<tr><td>{_STAGE_NAMES[k]}</td><td><span class='badge {esc(st['status'])}'>{esc(st['status'])}</span></td>"
                 f"{_cell(r['sets'][k])}{_cell('; '.join(st['notes']))}</tr>")
    p.append("</table>")
    gate = r["recovery_gate"]
    p.append(f"<p><b>Recovery gate (V1-V5, source, budget):</b> {'accepted' if gate['accepted'] else 'rejected'}"
             + (" - " + esc("; ".join(gate["reasons"])) if gate.get("reasons") else "") + "</p>")

    p.append("<h2>Inputs (hash-verified before use)</h2><table><tr><th>Key</th><th>Path</th><th>SHA-256</th></tr>")
    for k, v in m["inputs"].items():
        p.append(f"<tr><td>{esc(k)}</td><td>{esc(v['path'])}</td><td class='mono'>{esc(v['sha256'])}</td></tr>")
    p.append("</table>")

    p.append("<h2>Measures</h2><table><tr><th>Measure</th><th>Definition</th><th>Value</th><th>Counts</th></tr>")
    for k in MEASURES:
        inp = r["measure_inputs"][k]
        counts = (f"{inp['numerator']} / {inp['denominator']}" if "numerator" in inp
                  else str(inp["count"]) if "count" in inp else f"n/d: {inp.get('reason', '')}")
        p.append(f"<tr><td>{k}</td><td>{esc(DEFINITIONS[k])}</td>{_cell(r['measures'][k])}<td>{esc(counts)}</td></tr>")
    so = r["secondary"]
    so_count = so["S_inputs"].get("count", so["S_inputs"].get("reason", ""))
    p.append(f"<tr><td>S_overlap_C</td><td>{esc(DEFINITIONS['S_overlap_C'])} (secondary, outside the measures)</td>"
             f"{_cell(so['S_overlap_C'])}<td>{esc(str(so_count))}</td></tr></table>")

    p.append("<h2>Research questions</h2><table><tr><th>Item</th><th>Techniques</th></tr>"
             + "".join(f"<tr><td>{esc(k)}</td>{_cell(v)}</tr>" for k, v in r["research_questions"].items())
             + "</table>")

    rc = r["residual_classification"]
    head = f"<h2>Residual classification (C \\ B)</h2><p>Status: {esc(str(rc['status']))}"
    if rc.get("reason"):
        head += f" - {esc(rc['reason'])}"
    if rc.get("pk_summary") not in (None, "n/d"):
        head += f" &middot; {esc(rc['pk_summary'])}"
    p.append(head + "</p>")
    rows = _read_csv_rows(d / "residual_classification.csv")
    if rows:
        p.append(_ref_table(rows, "Class", lambda x: f"{x['class']} - {x['class_meaning']}"))

    p.append("<h2>Gain attribution (B \\ A)</h2>")
    gains = _read_csv_rows(d / "gain_attribution.csv")
    if gains:
        p.append(_ref_table(gains, "Attribution", lambda x: x["attribution"]))
    else:
        p.append(f"<p>{esc(str(r['gain_attribution'].get('reason') or 'B minus A is empty.'))}</p>")

    p.append("<h2>Normalization audit</h2><table><tr><th>Stage</th><th>Raw ID</th><th>Normalized</th>"
             "<th>Status</th><th>Rules</th><th>Source rules</th></tr>"
             + "".join(f"<tr><td>{esc(x['stage'])}</td><td>{esc(x['raw_id'])}</td><td>{esc(x['normalized_id'])}</td>"
                       f"<td>{esc(x['status'])}</td><td class='mono'>{esc(x['rules_applied'])}</td>"
                       f"<td class='mono'>{esc(x['source_rules'])}</td></tr>"
                       for x in _read_csv_rows(d / "normalization_audit.csv"))
             + "</table>")

    p.append("<h2>Limitations</h2><ul>" + "".join(f"<li>{esc(x)}</li>" for x in LIMITATIONS) + "</ul>")
    p.append("<p class='mono'>This report renders the sealed outputs listed in manifest.json; verify them with "
             "<code>python -m pipeline verify --dir &lt;folder&gt;</code>. The report file itself is not sealed.</p>"
             "</body></html>")
    path = d / "report.html"
    path.write_text("\n".join(p), encoding="utf-8", newline="\n")
    return path
