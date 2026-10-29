# Test report

Everything below was produced by actually running the commands on 2026-10-27. The raw logs are in
[`docs/evidence/`](evidence/).

## Environment

* Windows 11 Home (10.0.26200), PowerShell in VS Code
* Python 3.13.7, pytest 9.1.1
* Also run: `py -3.10 -m pipeline demo` and `verify` on Python 3.10.11. Both succeeded with the
  same measures. The pytest suite was **not** run on 3.10, because pytest is not installed for that
  interpreter.

## Commands and outcomes

| Command | Outcome | Log |
|---------|---------|-----|
| `python -m pytest -v` | **64 passed, 0 failed** in 0.37 s | `evidence/pytest_verbose.txt` |
| `python tools/build_fixtures.py` | fixtures regenerated; `specs.json` byte-identical to the previous build (deterministic) | `evidence/build_fixtures_output.txt` |
| `python -m pipeline demo --out out_demo` | exit 0; both samples completed | `evidence/demo_output.txt` |
| `python -m pipeline verify --dir out_demo` | exit 0; `OK - seal holds` for both samples | `evidence/verify_output.txt` |
| `python tools/show_failure_cases.py` | all five failure cases behave as specified (see below) | `evidence/failure_cases.txt` |
| `python -m pipeline run --specs fixtures/specs.json --mapping fixtures/attack_map.csv --mapping-version "Synthetic mapping v1" --out out/` | exit 0; same measures as the demo | — |

## Test inventory (50 functions, 64 cases after parametrization)

| File | Cases | What they establish |
|------|------:|---------------------|
| `test_metrics.py` | 8 | worked example (QA 0.75, VA 0.4, VB 0.4, DB 0.0, IB 0.6, G 1, L 0, M 2, O 2, S∩C 1) with numerators and denominators; IB = 1 − VB over every pair of subsets of a 4-element universe; n/d when B is not recovered, B is empty (QA only), C is empty, A failed, S missing; 4-d.p. rounding; integer counts |
| `test_normalize.py` | 12 | N1 cleaning; N2 invalid kept and flagged; N3 keep/collapse; N4 revoked replaced and unknown flagged unmapped; N5 dedupe with `N5:merged`; N6 one row per raw ID with source rules; N7 provenance; 5 kinds of bad mapping rows rejected |
| `test_recovery.py` | 24 | accepted record; each single failed check V1–V5 rejects; valid PE alone rejected; truthy-not-`true` rejected; claimed pass contradicted by evidence (V1–V4) rejected; V5 identical payload; sandbox source; budget exceeded or missing; missing payload hash; wrong sample; every reason kept for SYNTH-002; synthetic record rejected in pilot mode; classification: evidence → class, missing → U, dangling reference → U, unknown class error, evidence outside C \ B error, P+K format, gain attribution default and validation |
| `test_pipeline.py` | 20 | capa parsing (multi-technique rules, skipped rules, missing `rules`, malformed entries, malformed JSON); label files; registry (lower-casing, status, 4 rule violations, duplicates); end-to-end SYNTH-001 values and all output files; SYNTH-002 gate rejection and n/d; manifest determinism across two runs, and tamper detection; Gate 3 refusal (exception, exit 2, `REFUSED:`, nothing written); B without a record refused; a changed input aborts only that sample; a malformed report is a failed stage; unmarked input refused in synthetic mode; bad evidence marks classification failed; CLI demo, HTML report and verify |

## Tests checked against deliberately broken code

To confirm that the tests detect real defects, two bugs were introduced temporarily, the suite was
run, and the code was restored:

| Deliberate bug | Result |
|----------------|--------|
| DB computed as \|B∩C\|/\|C\| (A not subtracted) | 3 tests failed |
| budget check weakened (`used > limit + 100`) | 4 tests failed |

After the originals were restored: 64 passed.

## Failure cases observed (from `evidence/failure_cases.txt`)

| Case | Exit | Observed |
|------|-----:|----------|
| pilot mode without approval_id | 2 | `REFUSED: spec SYNTH-001: Gate 3 - pilot mode requires an approval_id ...` |
| B supplied without B_recovery | 2 | `REFUSED: ... a payload report B was given without a recovery record (B_recovery)` |
| C changed after hashing | 1 | SYNTH-001 `aborted_integrity` (hash mismatch shown); SYNTH-002 still completed |
| recovery `check_source: "sandbox"` | 0 | SYNTH-001 B `not_recovered`: `check_source is 'sandbox', not 'operator_tool'; a sandbox trace ... cannot prove recovery`; seals verify |
| registry duplicate / bad date | 2 / 2 | `REFUSED: SHA-256 ... is already in the register` / `REFUSED: retrieval date must be YYYY-MM-DD` |

## What these tests do not show

The tests use synthetic, hand-written inputs. They show that the arithmetic is correct, that the
gates and n/d rules hold, and that outputs are reproducible and tamper-evident. They do **not**
show anything about real malware, real capa or CAPE output, or any detection rate.

---

## Update: VisibilityLab web application (2026-10-27)

All commands were run on Windows 11, Python 3.13.7 and Node 22.14.0. The logs are in `evidence/`.

| Command | Outcome | Log |
|---------|---------|-----|
| `python -m pytest -v` | **98 passed, 0 failed** (65 pipeline + 33 web backend) | `evidence/pytest_verbose.txt` |
| `npm run typecheck` (webapp/frontend) | exit 0, no type errors | `evidence/frontend_typecheck.txt` |
| `npm run build` (webapp/frontend, Next.js 15.5.28) | exit 0; 9 routes built | `evidence/frontend_build.txt` |
| `python -m pipeline demo` / `verify` | exit 0; unchanged synthetic values; seals hold | `evidence/demo_output.txt`, `evidence/verify_output.txt` |

The pipeline gained one test (`test_n4_deprecated_is_kept_and_flagged`), because N4 now handles
the `deprecated` rows of the official ATT&CK table. The original 64 cases are unchanged and still pass.

Backend tests (`webapp/backend/tests/`):

| File | Cases | Covers |
|------|------:|--------|
| `test_db.py` | 2 | migrations apply once and are idempotent; DB constraints for Gate 3, duplicate SHA-256 and status vocabularies |
| `test_uploads.py` | 19 | malformed JSON, wrong shapes, wrong-sample reports, CAPE report hash binding, synthetic/empirical mixing, size limits (413), duplicate submissions (409), supersession, PE storage switches and Gate 3, non-PE rejection, hash mismatch, quarantine naming, PE never served (403), payload V2/V5 checks, bundle path traversal / unknown names / zip bomb / all-or-nothing, storage traversal refusal, PE header parser, CAPE label extraction |
| `test_workflows.py` | 12 | synthetic demo through API and worker (guide values); existing-evidence workflow with the official v20.0 table (T1086 → T1059.001); failed recovery → not_recovered and n/d; missing B and absent CAPE report → awaiting_input with every measure n/d; accepted recovery without payload report; B without a recovery record → REFUSED; tampered stored evidence → hash-gate failure; duplicate job submission and interrupted-job recovery and resubmission; capa tool workflow (test double) for A, B, C and derived S; capa not configured / isolation not acknowledged / version mismatch / tool failure; export allow-list, zip and summary; settings and loopback guard |

The tool workflow uses `webapp/backend/tests/fake_capa.py`, a **test double** that prints
capa-shaped JSON. Real capa was **not** installed or run, so the real capa command line and output
shape are still assumptions to confirm.

Mutation check: with the isolation-acknowledgement requirement removed, and separately with the
"never serve PE files" guard removed, 2 backend tests failed. Both guards were then restored.

Live run of the real processes (API, worker and `next start`): the synthetic demo import, an
empirical test-double sample over real HTTP multipart uploads (malformed and duplicate uploads
rejected; B and S awaiting input; VA computed; official mapping applied), and headless-Edge
screenshots of the analysis and sample pages, which rendered the data, n/d values and badges
correctly. The runtime data directory was deleted afterwards, so no test-double "empirical"
record remains.

---

## Update: demo mode and empirical onboarding (2026-10-27)

| Command | Outcome |
|---------|---------|
| `python -m pytest -v` | **116 passed, 0 failed** (65 pipeline + 51 web backend, of which 18 are new in `test_demo_mode.py`) |
| `npm run typecheck`, `npm run build` | both exit 0 |
| `python -m pipeline demo` / `verify` | unchanged values; seals hold |

New tests cover the following:
* A demo sample is created with no SHA-256, source, date or approval. It is labelled synthetic and
  gets a fresh fictional hash each time.
* The *accepted* kit run reproduces the guide values. The *rejected* run gives not_recovered and n/d.
  A partial kit gives awaiting_input.
* Downloaded kit files work through the normal upload path.
* The kit is refused (403) for empirical and bundled-fixture samples. Demo files are refused by
  empirical samples.
* Empirical mode still requires SHA-256, source and date, refuses 8 placeholder or empty approval
  values, and refuses an approval reference on a synthetic sample.
* `pipeline/synthetic.py` reproduces the bundled fixtures byte for byte.
* Migration 2 upgrades a version-1 database and keeps its data.

Mutation check: disabling the placeholder-approval guard failed 5 tests, and disabling the demo-kit
restriction failed 1. Both guards were then restored.

A live check on a separate stack (ports 8001/3001, throwaway data directory) exercised the demo
workflow over HTTP. Screenshots of New Analysis (both modes) and a demo sample page rendered
correctly. The bundled fixtures are byte-identical after the refactor (same `specs.json` SHA-256).
