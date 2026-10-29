# Architecture

The pipeline is a pure report processor. It reads JSON reports and records written by other tools,
checks them, and writes measurements and an audit trail. It never handles a sample binary.

## Data flow for one sample (`run.run_sample`)

| # | Step | Module | On failure |
|---|------|--------|------------|
| 1 | Validate spec: SHA-256 format, mode, approval, known input keys, B needs B_recovery | `run.validate_spec` | **whole run refused** (`GateError`, exit 2), before any output is written |
| 2 | Hash gate: each input is read **once**, and its bytes are checked against `input_sha256` | `hashing.read_verified` | **sample aborted** (`IntegrityError`), recorded in the summary; other samples continue |
| 3 | Parse JSON; in synthetic mode, every input must carry `"synthetic": true` | `capa_io.parse_json_bytes` | that stage `failed`, with the error text kept |
| 4 | Load A, C, S independently; cross-check `meta.sample.sha256` when the report states it | `capa_io` | that stage `failed`; the others still run |
| 5 | Recovery gate on `B_recovery` | `recovery.evaluate_recovery` | B = `not_recovered`, every reason listed |
| 6 | Load B **only if** the gate accepts; B's stated sample hash must equal `payload_sha256` | `capa_io` | B `failed` |
| 7 | Normalize A, B, C, S → sets + audit rows | `normalize.normalize_stage` | nothing is dropped; bad IDs are flagged |
| 8 | Metrics | `metrics.compute_metrics` | `n/d` where undefined |
| 9 | Classify C \ B, attribute B \ A | `classify` | bad evidence → classification `failed` |
| 10 | Write outputs, copy raw inputs, seal the manifest | `run`, `manifest` | — |

`run.run_batch` validates **every** spec before it processes any sample, so a refusal never leaves
partial output. It then processes each sample and writes `summary_metrics.csv`. `__main__` adds
`report.html`.

## Modules

| Module | Responsibility | Key rules |
|--------|---------------|-----------|
| `hashing.py` | SHA-256 of bytes and files, `read_verified`, canonical JSON | the parsed bytes are the hashed bytes (no check-then-reread gap) |
| `registry.py` | candidate register CSV | 64-hex SHA-256 (upper case converted), unique, non-empty source, real `YYYY-MM-DD` date, status `candidate`; never opens a sample |
| `capa_io.py` | capa → `{raw ID: [rule names]}`; labels → `{raw ID: ["sandbox_label"]}` | missing `rules` object is an error, not an empty report; rules without ATT&CK are skipped; ATT&CK entries without an `id` are errors |
| `normalize.py` | N1–N7 and the mapping table loader | invalid and unmapped IDs are kept and flagged; table rows are validated (format, status, duplicates, revoked → current replacement) |
| `recovery.py` | recovery gate | all of V1–V5 must be literal `true` **and** agree with the recorded evidence fields; `check_source == "operator_tool"`; integer budget with used ≤ limit; payload hash present; record matches the sample; synthetic records rejected in pilot mode |
| `metrics.py` | QA VA VB DB IB G L M O, S_overlap_C | `n/d` when a stage is unavailable or a denominator is empty; ratios rounded to 4 d.p.; counts are `int` |
| `classify.py` | residual classes, gain attribution | evidence references must resolve to a field of a recorded input, otherwise the default (U or uncertain) applies |
| `manifest.py` | build, write, verify the seal | sorted keys, no whitespace; `created_utc` excluded from the hash |
| `run.py` | orchestration, output writing, batch summary | see table above |
| `report.py` | static HTML overview | no scripts, no external resources |
| `__main__.py` | CLI `registry-add`, `run`, `demo`, `verify` | `REFUSED: <reason>` and exit 2 on refusal |

## Recovery gate

Unpacking and the V1–V5 checks happen **outside** the pipeline, in the operator's validated tool.
That tool writes a recovery record. The gate accepts the record only if every condition holds, and
it lists **all** failing conditions, not just the first one:

```
check_source == "operator_tool"            (a sandbox trace is never proof)
sample_sha256 == spec sha256                 (record belongs to this sample)
payload_sha256 is a SHA-256                  (payload hash present)
budget_used, budget_limit integers, used ≤ limit
V1..V5 each present, "passed": true (not merely truthy), and consistent with its evidence:
  V1 dos_magic "MZ", nt_signature "PE", number_of_sections > 0 (= len(V3.sections))
  V2 stored_payload_sha256 == payload_sha256
  V3 entry_point_rva inside some [virtual_address, virtual_address + virtual_size)
  V4 import_errors == 0
  V5 payload_sha256 != sample_sha256
pilot mode: record must not be marked synthetic
```

A record holding only a valid PE header (V1) is rejected, because V2–V5 are missing.

## Integrity

* **Hash gate (input):** a changed or missing input aborts that sample. Its output folder is
  removed, so no stale results remain.
* **Seal (output):** `manifest.json` stores the SHA-256 of every output file and of the raw input
  copies, plus `manifest_sha256` over the whole manifest (excluding `created_utc`).
  `python -m pipeline verify --dir out_demo` recomputes both. A rerun with the same inputs, tools
  and mapping gives the same `manifest_sha256`, and a test checks this.
* **Gate 3:** `mode: "pilot"` needs a non-empty `approval_id`. In `synthetic` mode, only inputs
  marked `"synthetic": true` are accepted, so real reports cannot slip in without approval. This is
  a guard against mistakes, not a security boundary, and it does not replace written institutional
  approval.

## Output artifacts

```
out_demo/
├── summary_metrics.csv
├── report.html
├── f81dbb79c0e9/            SYNTH-001
│   ├── results.json
│   ├── normalization_audit.csv
│   ├── residual_classification.csv
│   ├── gain_attribution.csv
│   ├── manifest.json
│   └── raw/A.json B.json B_recovery.json C.json S.json evidence.json
└── 9cbe176c1651/            SYNTH-002 (same files; CSVs for residual/gains have headers only)
```
