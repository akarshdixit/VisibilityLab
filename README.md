# Quantifying Behavioral Visibility Loss Due to Malware Packing

**VisibilityLab** is a research pipeline and local web application for measuring how much of a
program's behaviour, expressed as MITRE ATT&CK techniques, is hidden from static analysis when the
program is packed.

> **Status: research prototype, synthetic data only.**
> Every sample hash, capability report, recovery record and evidence file in this repository is
> **synthetic** and was generated for testing. No malware was acquired, unpacked, decrypted or
> executed for this repository, and **no empirical results are reported here**. The numbers shown
> below demonstrate the arithmetic on fictional inputs. They say nothing about real malware.
> VisibilityLab is not production-ready.

---

## Contents

- [Motivation](#motivation)
- [Evidence stages: A, B, C and S](#evidence-stages-a-b-c-and-s)
- [Measures](#measures)
- [Architecture](#architecture)
- [Implemented features](#implemented-features)
- [Installation (Windows)](#installation-windows)
- [Running the app](#running-the-app)
- [Running the tests](#running-the-tests)
- [Synthetic demo mode](#synthetic-demo-mode)
- [Command-line pipeline](#command-line-pipeline)
- [Provenance, audit manifests and exports](#provenance-audit-manifests-and-exports)
- [What is not yet implemented or validated](#what-is-not-yet-implemented-or-validated)
- [Limitations](#limitations)
- [Safety precautions](#safety-precautions)
- [Roadmap](#roadmap)
- [Repository layout](#repository-layout)
- [Acknowledgements](#acknowledgements)

---

## Motivation

Packers compress or encrypt a Windows executable so that its real code only appears in memory at
run time. Static tools such as [capa](https://github.com/mandiant/capa) therefore report fewer, or
different, capabilities for a packed file than for its unpacked payload. Dynamic analysis in a
sandbox observes behaviour, but it is expensive, sees only one execution path, and needs isolated
infrastructure.

This project asks a narrow, measurable question:

> For a packed Windows executable, how does the set of ATT&CK techniques reported by capa change
> between the packed file, a validated unpacked payload, and a sandbox trace of the same file?
> And what recorded evidence explains the differences that remain?

| RQ | Question |
|----|----------|
| RQ1 | Which techniques does capa see in the packed file, and how much do they overlap with the payload and the dynamic reference? |
| RQ2 | Which techniques are gained, kept or lost after unpacking? Which dynamic-reference techniques appear only after unpacking? |
| RQ3 | Which dynamic-reference techniques stay absent after unpacking, and what recorded evidence explains each one? |

## Evidence stages: A, B, C and S

Every sample is identified by its SHA-256. All stages must refer to the same sample.

| Stage | Source | Role |
|-------|--------|------|
| **A** | capa (static) on the **packed** file | what an analyst sees without unpacking |
| **B** | capa (static) on the **recovered payload** | what unpacking reveals; used **only** if the recovery record passes the recovery gate |
| **C** | capa in dynamic mode on a **CAPE sandbox report** for the same SHA-256 | the dynamic *reference*. It is not ground truth. |
| **S** | the sandbox's own ATT&CK labels | secondary; reported beside the measures, never inside them |

### Recovery gate

VisibilityLab does not unpack anything. Unpacking and the checks below are done by the operator's
own validated tool, which writes a **recovery record**. The pipeline only decides whether that
record is acceptable, and Stage B is used only if it is. The record must:

- refer to the same packed sample (`sample_sha256`) and record the payload's SHA-256;
- come from an operator tool (`check_source: "operator_tool"`). Any other source, such as a sandbox
  trace, is refused;
- stay within its recovery budget (`budget_used <= budget_limit`);
- pass all five checks, each as a literal `true` **and** consistent with its recorded evidence:

| Check | Requirement (working definition) |
|-------|----------------------------------|
| V1 | the payload parses as a structurally valid PE file |
| V2 | the payload hash is recorded and matches the stored payload |
| V3 | the entry point lies inside a section of the payload |
| V4 | the import table resolves without errors |
| V5 | the payload differs from the packed input |

If any requirement fails, Stage B is `not_recovered`, and every reason is kept in the results. The
record format is documented in [`pipeline/recovery.py`](pipeline/recovery.py).

### `n/d`: not defined, never 0

A 0 would claim that a tool ran and found nothing. When a stage did not run or was not usable, the
measures that depend on it are reported as `n/d`, and the reason is recorded:

| Condition | Measures reported as `n/d` |
|-----------|----------------------------|
| B not recovered (gate rejected, no record, or B report failed) | QA, VB, DB, IB, G, L, M, O |
| B recovered but empty | QA only (zero denominator) |
| C empty or unavailable | VA, VB, DB, IB, M, O, S∩C |
| A failed or missing | QA, VA, DB, G, L |
| S failed or missing | S∩C |

## Measures

| Measure | Definition | Meaning |
|---------|-----------|---------|
| QA | \|A ∩ B\| / \|B\| | share of the payload's techniques already visible in the packed file |
| VA | \|A ∩ C\| / \|C\| | share of the dynamic reference visible in the packed file |
| VB | \|B ∩ C\| / \|C\| | share of the dynamic reference visible in the payload |
| DB | \|(B ∩ C) \ A\| / \|C\| | share of the dynamic reference found **only** after unpacking |
| IB | \|C \ B\| / \|C\| = 1 − VB | share of the dynamic reference still missing after unpacking |
| G, L | \|B \ A\|, \|A \ B\| | techniques gained / lost by unpacking |
| M, O | \|B ∩ C\|, \|B \ C\| | payload techniques matched / not matched by the dynamic reference |
| S∩C | \|S ∩ C\| | sandbox labels that also appear in the dynamic reference |

Ratios are rounded to 4 decimal places. Each numerator and denominator is stored in
`results.json` so that every value can be recomputed by hand.

Each technique in C \ B (still missing after unpacking) gets exactly one **residual class**, written
by the analyst in an evidence file. No class is inferred automatically:

| Class | Meaning |
|-------|---------|
| P | incomplete or incorrect payload recovery |
| K | behaviour of the packer or unpacking stub |
| O | other run-time obfuscation within the payload |
| E | behaviour outside the analysed file |
| T | rule scope or rule coverage |
| M | mapping difference |
| U | unresolved (the default) |

A class other than U is kept only if its evidence reference points to an existing field of one of
the sample's recorded inputs. Otherwise the technique falls back to U, with the reason recorded.

Before comparison, technique IDs are normalized against a versioned ATT&CK mapping table (rules
N1–N7). Full definitions are in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Architecture

VisibilityLab has two layers: a standard-library Python **pipeline** that does all of the
computation, and a local **web application** that manages samples and evidence and calls the
pipeline unchanged.

```
 Pipeline (pipeline/, Python standard library only)

 A  capa(packed) ─────────────────────────────┐
 B_recovery ─► RECOVERY GATE (V1–V5, budget,  │
               payload hash)                  │     ┌─────────────┐  ┌─────────┐  ┌──────────┐  ┌───────────┐
                  │ accepted                  ├───► │ Normalize   │─►│ Metrics │─►│ Classify │─►│ Manifest  │
 B  capa(payload) ┘ (used only if accepted)   │     │ N1–N7+audit │  │ n/d     │  │ evidence │  │ hash seal │
 C  capa(CAPE report, same SHA-256) ──────────┤     └─────────────┘  └─────────┘  └──────────┘  └───────────┘
 S  sandbox labels (kept separate) ───────────┘
      ▲ every input passes a SHA-256 hash gate first; pilot mode requires an approval reference
```

```
 Web application (webapp/)

 browser ─► Next.js frontend (127.0.0.1:3000)
               │
               ▼
            FastAPI backend (127.0.0.1:8000) ── SQLite + content-addressed evidence store
               │
               ▼
            Worker process ─► pipeline.run.run_batch(...)   (the unchanged pipeline)
               └─ optional: pinned capa subprocess (disabled by default)
```

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [webapp/README.md](webapp/README.md).

## Implemented features

**Pipeline (`pipeline/`)**
- SHA-256 hash gate on every input; a changed input aborts only that sample.
- Readers for capa JSON and sandbox label files.
- ATT&CK normalization (N1–N7) with a per-technique audit trail, against a versioned mapping table.
- Recovery gate (V1–V5, budget, payload hash) that decides whether Stage B may be used.
- All measures above, with stored numerators and denominators and explicit `n/d` handling.
- Evidence-based residual classification (RQ3) and gain attribution (RQ2).
- A hash-linked manifest that seals each result folder, plus a `verify` command that re-checks it.
- CSV, JSON and printable HTML outputs.
- A candidate register that records provenance only.

**Web application (`webapp/`)**
- Sample registration with provenance. Empirical samples require an approval reference, and
  obvious placeholder values are refused.
- Upload and validation of evidence files (schema checks, size limits, zip bundles without
  extraction to disk).
- Background worker that runs the pipeline and records statuses, hashes, tool and mapping versions.
- Result pages, seal verification, an audit view and exports.
- A synthetic **demo mode** that needs no samples or tools (see below).
- Optional local capa execution for Stages A, B and C. It is **off by default** and needs explicit
  configuration (see [Safety precautions](#safety-precautions)).

**Mapping data**
- `mappings/attack_enterprise_v20.0.csv` was generated from MITRE's ATT&CK Enterprise v20.0 STIX
  bundle by `tools/build_attack_map.py`. The source URL and hashes are recorded in
  `mappings/attack_enterprise_v20.0.provenance.json`.

## Installation (Windows)

Requirements:
- Python 3.10 or later (tested with Python 3.13 on Windows 11)
- Node.js 18.18 or later and npm (for the web frontend; tested with Node.js 22)
- Git

Open PowerShell in the repository root, then run:

```powershell
# optional: create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Python dependencies (web backend + tests; the pipeline itself needs no third-party packages)
python -m pip install -r requirements-webapp.txt

# frontend dependencies
cd webapp\frontend
npm install
cd ..\..
```

If you only want the command-line pipeline and its tests, `python -m pip install -r requirements-dev.txt`
is enough.

## Running the app

Run each of these from the repository root, in three separate terminals:

```powershell
# Terminal 1: API on http://127.0.0.1:8000 (interactive docs at /docs)
python -m webapp.backend

# Terminal 2: worker (required; runs the analyses)
python -m webapp.backend.worker

# Terminal 3: frontend on http://127.0.0.1:3000
cd webapp\frontend
npm run dev
```

Or start all three in separate windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
```

Then open http://127.0.0.1:3000.

Settings come from `VL_*` environment variables. See [webapp/.env.example](webapp/.env.example)
for the list and defaults. The app reads the process environment and does not load `.env` files
itself, so set a variable in the terminal before starting **both** the API and the worker, for
example:

```powershell
$env:VL_MAX_JSON_MB = "20"
```

By default, runtime data (the SQLite database, stored evidence and job results) is written to
`webapp/data/`, which is git-ignored.

## Running the tests

```powershell
python -m pytest -q
```

This runs the pipeline tests (`tests/`) and the web backend tests (`webapp/backend/tests/`). All
of them use synthetic inputs. External tools are replaced with a test double, so capa does not
need to be installed.

Frontend checks:

```powershell
cd webapp\frontend
npm run typecheck
npm run build
```

The tests show that the arithmetic is correct, that the gates refuse bad input, and that reruns are
reproducible. They do **not** show anything about real malware.

## Synthetic demo mode

Demo mode lets you explore the whole workflow without any sample, report, tool or approval.

1. Start the app and open http://127.0.0.1:3000.
2. Either click **Load synthetic demo** on the Overview page, or go to **New Analysis → Demo mode**
   and create a demo sample with the scenario *accepted* or *rejected*.
3. Attach the **demo evidence kit** (six synthetic inputs: `A`, `B_recovery`, `B`, `C`, `S`,
   `evidence`), then run the analysis.

How demo data is kept separate from real data:
- Demo samples get a generated, fictional SHA-256.
- Every demo file is marked `"synthetic": true`. Empirical samples refuse these files, and the demo
  kit is refused for empirical samples.
- Synthetic samples run against the fictional mapping table `fixtures/attack_map.csv`, not the
  official ATT&CK table.
- Every result page and printable report carries a **SYNTHETIC** banner.
- Synthetic files are never used to fill in a missing stage of an empirical sample.

The two scenarios are built to exercise the code paths:

| Scenario | What it exercises | Synthetic output |
|----------|-------------------|------------------|
| *accepted* (SYNTH-001) | recovery gate passes; all stages present | QA 0.75, VA 0.4, VB 0.4, DB 0.0, IB 0.6, G 1, L 0, M 2, O 2, S∩C 1; residual classes P=1, K=1, U=1 |
| *rejected* (SYNTH-002) | recovery gate fails (V4 not passed, budget exceeded) | B `not_recovered`; VA 0.4; every B-dependent measure `n/d` |

**These values are properties of hand-written synthetic inputs. They are not research findings.**

The same synthetic inputs are stored in [`fixtures/`](fixtures/), and the matching pipeline output
is in [`out_demo/`](out_demo/). Both are synthetic.

## Command-line pipeline

The pipeline can be used without the web app:

```powershell
python -m pipeline demo --out out_demo         # process both synthetic samples
python -m pipeline verify --dir out_demo       # re-check every manifest seal
python tools/show_failure_cases.py             # show each gate refusing bad input
python tools/build_fixtures.py                 # regenerate the synthetic fixtures

python -m pipeline run --specs fixtures/specs.json --mapping fixtures/attack_map.csv `
    --mapping-version "Synthetic mapping v1" --out out/
```

Exit codes: `0` success; `1` a sample aborted on the hash gate or a seal failed to verify;
`2` input refused (printed as `REFUSED: <reason>`).

## Provenance, audit manifests and exports

Every result is meant to be traceable to hashed inputs:

- **Hash gate.** Each input is checked against the SHA-256 recorded for it before processing. A
  changed input aborts that sample. In the web app, hashes are taken at upload time, so later
  changes to stored evidence are detected.
- **Audit trail.** `normalization_audit.csv` records, for every raw technique ID in every stage, the
  normalized ID, its status and the rules applied.
- **Manifest seal.** `manifest.json` records the input and output hashes, tool and mapping versions
  (including the mapping table's SHA-256), stage statuses and run mode, plus `manifest_sha256`, a
  hash over all of it. Identical inputs give an identical seal on a rerun.
  `python -m pipeline verify` (or **Verify seal** in the web app) re-checks it.

Each sample's output folder (named after the first 12 characters of its SHA-256) contains:

| File | Contents |
|------|----------|
| `results.json` | stage statuses, gate result, normalized sets, measures with numerators and denominators, RQ1–RQ3 sets |
| `normalization_audit.csv` | one row per raw technique ID per stage |
| `residual_classification.csv` | one row per technique in C \ B: class, evidence reference, reason |
| `gain_attribution.csv` | one row per technique in B \ A: `payload`, `dump_artifact` or `uncertain` |
| `raw/` | byte-identical copies of every input report |
| `manifest.json` | the hash-linked seal described above |
| `report.html` | printable per-sample report |

A batch also writes `summary_metrics.csv` (one row per sample) and an overview `report.html`. The
web app offers these files individually, as a `.zip` of the sealed result folder, and as a batch
summary CSV on the **Exports** page.

## What is not yet implemented or validated

The software path is built and tested on synthetic data. The empirical study has **not** been
carried out. Specifically:

- **No empirical experiments.** No real packed samples have been analysed, and the repository
  contains no empirical results.
- **No unpacking.** VisibilityLab does not unpack anything. Stage B depends on a recovery record
  from an external, operator-validated recovery process. That process and the V1–V5 checks have not
  been validated on real samples.
- **No dynamic analysis.** VisibilityLab never runs a sandbox. Stage C depends on CAPE reports
  produced elsewhere, in isolated infrastructure. No such reports have been imported.
- **No packer identification.** Identifying the packer happens outside the pipeline.
- **Unconfirmed tool formats.** The capa JSON shape, the capa command line and the CAPE report
  fields (`target.file.sha256`, `ttps`) are assumed. They must be checked against the pinned tool
  versions before any empirical use.
- **Working interpretations.** The normalization rules N1–N7, the recovery checks V1–V5 and the
  residual classes are working interpretations defined in this project, not an external standard.
- **No benign control yet.** A benign, self-built UPX-packed control to test the empirical path end
  to end is planned but has not been run. See [docs/EMPIRICAL_ONBOARDING.md](docs/EMPIRICAL_ONBOARDING.md).

## Limitations

- The fixtures are synthetic, so the current results demonstrate correctness of the code, not
  properties of malware.
- Stage C is a reference, not ground truth. A single sandbox run sees limited behaviour, and capa's
  rule coverage limits what any stage can report.
- Measures are only as good as the evidence files and recovery records supplied by the operator.
- The approval-reference check rejects obvious placeholders but cannot verify that a reference is
  genuine.
- The web app has no authentication and is designed for a single local user.

## Safety precautions

VisibilityLab is a **report processor**. By design it:

- never executes, unpacks, decrypts or downloads a sample, and never launches a sandbox;
- binds to `127.0.0.1` and refuses a non-loopback host unless `VL_ALLOW_REMOTE=true` is set.
  There is no authentication, so **do not expose it to a network**;
- stores uploaded PE files read-only under a non-executable name outside any served directory,
  and never returns them through the API;
- runs capa only from an explicitly configured absolute path at a pinned version, with no shell,
  a timeout and an output cap. Analysis of PE files also requires `VL_STATIC_ANALYSIS_ENABLED=true`
  and an explicit acknowledgement in `VL_ISOLATION_ACK` that the worker runs on an isolated
  analysis VM;
- validates every upload (size limits, schema checks, path-traversal and zip-bomb protection).

If you extend this work to real samples:

- Handle malware only on an isolated analysis VM with no route to production networks, and only
  with the approvals your institution requires.
- **Never commit samples, payloads, memory dumps or real sandbox reports to this repository.**
  `.gitignore` excludes common binary types, `samples/`, `payloads/` and the app's data directory,
  but it is not a substitute for care.
- Producing a CAPE report executes the sample. Do this only in an isolated sandbox.

## Roadmap

1. Confirm the capa and CAPE report formats against pinned tool versions.
2. Run the empirical path end to end on a documented benign UPX-packed control.
3. Validate the recovery process and the V1–V5 checks on that control.
4. After the required approvals, run a small pilot on a few approved samples in an isolated
   environment.
5. Review the working interpretations (N1–N7, V1–V5, residual classes) against the pilot.
6. Only then, scale up and report empirical results, with each result traceable to its sealed
   manifest.

## Repository layout

```
pipeline/          research pipeline (standard library only)
tests/             pipeline tests
webapp/backend/    FastAPI API, worker, storage, validation; tests in webapp/backend/tests/
webapp/frontend/   Next.js frontend
tools/             fixture builder, ATT&CK mapping builder, failure-case demo
scripts/dev.ps1    starts API, worker and frontend on Windows
mappings/          ATT&CK Enterprise v20.0 mapping table and its provenance
fixtures/          SYNTHETIC inputs (fictional samples SYNTH-001 and SYNTH-002)
out_demo/          SYNTHETIC pipeline output for the fixtures
docs/              architecture, methodology, test report, onboarding
```

## Acknowledgements

This project was developed as a university team research project.

- [capa](https://github.com/mandiant/capa) and [CAPE](https://github.com/kevoreilly/CAPEv2) are
  third-party tools. They are not included here and are referred to only as producers of input
  reports.
- MITRE ATT&CK® is a registered trademark of The MITRE Corporation. The mapping table in
  `mappings/` is derived from MITRE's public ATT&CK STIX data; see the provenance file for the
  source and its hash.

No license file is included yet. Until one is added, no permission to reuse the code is granted.
