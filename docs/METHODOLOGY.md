# Methodology

## 1. Three-stage, same-sample comparison

For each packed sample (identified by its SHA-256), we compare four technique sets:

| Set | Source | Role |
|-----|--------|------|
| **A** | capa, static, on the packed file | what an analyst sees without unpacking |
| **B** | capa, static, on the recovered payload | what unpacking reveals (used **only** if the recovery gate accepts) |
| **C** | capa in dynamic mode on the CAPE report for the same SHA-256 | the dynamic **reference**, not ground truth |
| **S** | the sandbox's own ATT&CK labels | secondary; reported beside the measures, never inside them |

The ten method steps from Review 1 map to code as follows: 01 register → `registry.py`;
02 hash/provenance → `hashing.py`, `run.py`; 03 identify packing → operator tool (DIE), outside the
pipeline; 04 Stage A → `capa_io.py`; 05 unpack and validate → operator tool, gated in
`recovery.py`; 06 Stage B and 07 Stage C → `capa_io.py`; 08 normalize → `normalize.py`;
09 metrics and classes → `metrics.py`, `classify.py`; 10 repeat and report → `manifest.py`, outputs.

## 2. ATT&CK normalization (working interpretation of N1–N7)

| Rule | Implementation |
|------|----------------|
| N1 | trim whitespace and upper-case (`" t1055 "` → `T1055`) |
| N2 | format `^T\d{4}(\.\d{3})?$`; invalid IDs are flagged `invalid_format` and **kept** |
| N3 | sub-techniques kept; collapsed to the parent only with `--collapse-subtechniques` |
| N4 | mapping-table lookup: `current` kept; `revoked` replaced by its (current) replacement → `revoked_replaced`; `deprecated` (no replacement exists in ATT&CK) → kept, flagged `deprecated`; absent → kept, flagged `unmapped` |
| N5 | sets remove duplicates; an audit row whose ID was already produced is marked `N5:merged` |
| N6 | one audit row per raw ID per stage, with every rule applied and the source rule names |
| N7 | mapping table name, version and SHA-256 are recorded in every manifest |

These are **working interpretations**, not an official standard. Review 1 names N1–N7 without
defining them.

## 3. Measures

Let |X| be the number of techniques in X, ∩ intersection, and \ set difference.

| Measure | Formula | Reads as |
|---------|---------|----------|
| QA | $QA = \dfrac{\lvert A \cap B\rvert}{\lvert B\rvert}$ | share of the payload's techniques already visible in the packed file |
| VA | $VA = \dfrac{\lvert A \cap C\rvert}{\lvert C\rvert}$ | share of the dynamic reference visible in the packed file |
| VB | $VB = \dfrac{\lvert B \cap C\rvert}{\lvert C\rvert}$ | share of the dynamic reference visible in the payload |
| DB | $DB = \dfrac{\lvert (B \cap C) \setminus A\rvert}{\lvert C\rvert}$ | share of the dynamic reference found **only** after unpacking |
| IB | $IB = \dfrac{\lvert C \setminus B\rvert}{\lvert C\rvert} = 1 - VB$ | share of the dynamic reference still missing after unpacking |
| G | $\lvert B \setminus A\rvert$ | count gained by unpacking |
| L | $\lvert A \setminus B\rvert$ | count lost by unpacking |
| M | $\lvert B \cap C\rvert$ | dynamic-reference techniques matched by the payload |
| O | $\lvert B \setminus C\rvert$ | payload techniques not in the dynamic reference |
| S_overlap_C | $\lvert S \cap C\rvert$ | sandbox labels also in the dynamic reference (an addition to Review 1; secondary) |

Ratios are rounded to 4 decimals. Counts are integers. `results.json → measure_inputs` stores each
numerator and denominator so that every value can be recomputed by hand. The identity IB = 1 − VB
is tested over all pairs of subsets of a 4-element universe.

### When a value is `n/d` (not defined), never 0

| Condition | n/d measures |
|-----------|--------------|
| B not recovered (gate rejected, no record, or B report failed) | QA, VB, DB, IB, G, L, M, O |
| B recovered but empty | QA only (zero denominator); VB = 0, IB = 1, G = 0 and L = \|A\| are real values |
| C empty or unavailable | VA, VB, DB, IB, M, O, S_overlap_C |
| A failed or missing | QA, VA, DB, G, L |
| S failed or missing | S_overlap_C |

A zero would claim that the tool ran and found nothing. When a stage did not run or was not
usable, nothing is known, so the honest value is "not defined". Each n/d has its reason recorded
in `measure_inputs`.

## 4. Evidence-based residual classification (RQ3)

Each technique in C \ B gets exactly one class:

| Class | Meaning |
|-------|---------|
| P | incomplete or incorrect payload recovery |
| K | behaviour of the packer or unpacking stub |
| O | other run-time obfuscation within the payload |
| E | behaviour outside the analysed file |
| T | rule scope or rule coverage |
| M | mapping difference |
| U | unresolved: the default when there is no evidence |

Rules:
* No class is inferred automatically. The analyst writes an `evidence.json` entry
  `{technique, class, evidence_ref, reason}`.
* A class other than U is kept only if `evidence_ref` resolves to an existing field of one of the
  sample's recorded inputs, written `<input key>#<dotted.path>` (for example `B_recovery#checks.V3`
  or `C#rules.dyn-rule-4`). Missing or unresolvable evidence → **U**, and the reason says why.
* An unknown class letter, or evidence for a technique outside C \ B, is an **error**. The sample's
  classification is marked `failed` rather than silently ignored.
* P and K are always reported together: `P=1, K=1 (P+K=2)`.
* Gains (B \ A) are attributed to `payload`, `dump_artifact` or `uncertain`, with `uncertain` as
  the default. The same evidence rule applies.

## 5. Synthetic evaluation

There are two fictional samples, generated by `tools/build_fixtures.py`, with real hashes of the
fixture files.

**SYNTH-001 (gate accepts)**: the guide's worked example.

| Set | Raw IDs | Normalized |
|-----|---------|-----------|
| A | T1055, T1027, T1082 | same |
| B | T1055, T1027, T1082, T1497, T0001 | T1055, T1027, T1082, T1497 (T0001 is a fictional revoked ID → T1027) |
| C | T1055, T1027, T1112, T1620, T9998 | same; T9998 kept and flagged `unmapped` |
| S | T1055, T1486 | same |

Hand computation: A∩B = {T1055, T1027, T1082} → QA = 3/4 = 0.75; A∩C = B∩C = {T1055, T1027} →
VA = VB = 2/5 = 0.4; (B∩C)\A = ∅ → DB = 0/5 = 0.0; C\B = {T1112, T1620, T9998} → IB = 3/5 = 0.6;
G = |{T1497}| = 1; L = 0; M = 2; O = |{T1082, T1497}| = 2; S∩C = {T1055} → 1.
Residual: T1112 → P (`B_recovery#checks.V3`), T1620 → K (`C#rules.dyn-rule-4`), T9998 → U.
The pipeline output matches every value.

**SYNTH-002 (gate rejects)**: V1–V3 and V5 pass, V4 fails (3 import errors), and the budget is
25 > 20. B is `not_recovered`, and both reasons are listed. A B report is supplied but **not used**.
QA, VB, DB, IB, G, L, M and O are n/d. VA = |{T1055, T1027}| / 5 = 0.4. Residual classification is n/d.

What this evaluation does and does not show: it shows that the formulas, gates, n/d rules, audit and
seal behave as specified. It says nothing about real malware, capa's real output or any detection rate.

## Interpretations and deviations

| Topic | Guide | Implementation | Why |
|-------|-------|----------------|-----|
| B recovered but empty | "the same measures are n/d" | only QA (the zero-denominator ratio) is n/d; VB, IB, G, L, M, O are real values | an empty validated payload report is a real finding; turning real zeros into n/d would hide it. **Confirm with the guide.** |
| S_overlap_C when C is empty | not specified | n/d | consistent with M and O |
| Evidence reference format | file paths, e.g. `recovery/SYNTH-001_recovery.json#checks.V3` | input keys, e.g. `B_recovery#checks.V3`, which must resolve | lets the pipeline check that the evidence actually exists in a hashed input |
| V1–V5 | "all five True" | literal `true` **and** agreement with recorded evidence fields | prevents acceptance on five truthy values |
| Synthetic marker | not specified | synthetic mode accepts only inputs marked `"synthetic": true`; pilot mode rejects synthetic recovery records | keeps the two modes from mixing |
| Report/sample link | not specified | if a capa report states `meta.sample.sha256`, it must match (A, C: the sample; B: the payload) | provenance check |
| Integrity abort | "run aborts for that sample" | sample aborted, others continue, exit code 1 | follows the guide; exit 2 is reserved for refusals |
| Extras | — | `verify` command, `report.html`, `tools/show_failure_cases.py` | demonstration support |

## Assumptions to confirm before a pilot

1. V1–V5 definitions and the recovery-record field names (`recovery.py`).
2. N1–N7 definitions (`normalize.py`).
3. capa JSON shape `rules → meta → attack → id`, checked against the approved capa version
   (real capa may also need `meta.sample.sha256` read from a different path).
4. The official ATT&CK v20.0 mapping table is now generated from MITRE's STIX bundle (`mappings/attack_enterprise_v20.0.csv`, 706 current / 149 revoked / 12 deprecated, upstream SHA-256 in the provenance JSON). A second reviewer should check the revoked-chain resolution in `tools/build_attack_map.py`.
5. Recovery is external: the operator's validated tool produces the record.
6. S_overlap_C as an agreed addition.
7. The empty-B n/d rule (see the deviations table).
