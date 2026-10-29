# Review 2 — presentation notes

All numbers below come from `python -m pipeline demo` on the **synthetic** fixtures.

---

## 1. Two-minute explanation

Packers hide a program's real code behind a small stub. A static tool like capa then mostly sees the
stub, and a sandbox sees only one run. Our question is **how much ATT&CK-level visibility is lost**:
for the same sample, we compare what capa reports on (A) the packed file, (B) a validated unpacked
payload and (C) the CAPE sandbox trace, and we explain what still differs.

For Review 2 we built the measurement pipeline. It reads reports produced by other tools, checks
every input against its recorded SHA-256, and normalizes ATT&CK IDs with a full audit. It accepts a
payload only through a five-check recovery gate, computes nine visibility measures, and classifies
each remaining difference only from recorded evidence. Every output is sealed in a hash-linked
manifest. The pipeline never unpacks or runs anything. It runs today on synthetic fixtures, and 64
automated tests pass. The guide's worked example comes out exactly: QA 0.75, VA 0.4, VB 0.4, DB 0,
IB 0.6. The next step is confirming our working assumptions and getting written approval (Gate 3)
before any real sample is touched.

## 2. Five-minute technical explanation

1. **Inputs.** The inputs are described in a spec file, one entry per sample: SHA-256, mode
   (`synthetic` or `pilot`), approval_id, input paths, and each input's SHA-256.
2. **Gates before data.** The spec is validated first. Pilot mode without approval, or a payload
   report with no recovery record, refuses the whole run with exit code 2 before anything is
   written. Then each file is read once and hashed. Any mismatch aborts that sample.
3. **Independent stages.** A, C and S load independently. A malformed report is a *failed* stage,
   never an empty set.
4. **Recovery gate.** B is used only if the recovery record passes V1–V5 *and* each claimed pass
   agrees with its evidence fields. The source must be `operator_tool`, the budget must be within
   its limit, and the payload hash must be present. All reasons are listed.
5. **Normalization N1–N7.** IDs are cleaned, checked, mapped and deduplicated. Revoked IDs are
   replaced, and unknown or invalid IDs are kept and flagged. There is one audit row per raw ID.
6. **Metrics.** Nine measures are computed, with `n/d` wherever a stage is unavailable or a
   denominator is empty. S_overlap_C is reported beside them.
7. **Classification.** Each technique in C \ B gets P/K/O/E/T/M only if its evidence reference
   resolves to a real field of a hashed input. Otherwise it gets U. Gains B \ A get
   payload/dump_artifact/uncertain.
8. **Seal.** The manifest records input and output hashes, the mapping table hash and version, tool
   versions and stage statuses. Its hash is deterministic, so a rerun gives the same hash and
   `verify` detects any edit.

## 3. Architecture walkthrough (point at README diagram or `docs/ARCHITECTURE.md`)

Three paths feed one back end. **Packed → recovery gate → payload** is the static path. **CAPE
report → dynamic capa** is the reference path. **Sandbox labels S** are kept separate. The back end
is normalize → metrics → classify → manifest. A failed recovery leaves B as n/d, while A and C are
still measured.

## 4. A, B, C and S

* **A**: capa on the packed file. What you see without unpacking.
* **B**: capa on the payload recovered by the operator's validated tool. Used only if the gate accepts.
* **C**: capa in dynamic mode on the CAPE report for the same SHA-256. Our *reference*, not ground truth.
* **S**: the sandbox's own ATT&CK labels. Mappings differ between tools, so S never enters the
  measures. We report only |S ∩ C|.

## 5. The measures in one line each

* **QA = |A∩B|/|B|**: how much of the payload was already visible while packed (0.75: three of four).
* **VA = |A∩C|/|C|**: how much of the dynamic reference the packed file shows (0.4).
* **VB = |B∩C|/|C|**: how much of the dynamic reference the payload shows (0.4).
* **DB = |(B∩C)\A|/|C|**: what unpacking added that matches the reference (0.0: nothing new;
  this is a real zero).
* **IB = |C\B|/|C| = 1 − VB**: what is still invisible after unpacking (0.6). This is the RQ3 set.

## 6. The recovery gate

"A valid PE is not enough." A payload is used only if V1 (valid PE), V2 (hash matches the stored
payload), V3 (entry point inside a section), V4 (imports resolve) and V5 (differs from the packed
file) are **all** literally `true`, *and* each agrees with the recorded evidence. For example, V3's
entry-point RVA must actually fall inside one of the listed sections. The source must be the
operator's tool (a sandbox trace is refused), the budget must be within its limit, and the payload
hash must be present. If anything fails, every reason is listed and B becomes `not_recovered`.

## 7. Why `n/d` is not 0

Zero means "we looked and found nothing". `n/d` means "we could not look". If unpacking failed,
there is no B. Writing VB = 0 would falsely claim the payload matched none of the dynamic
reference, and averaging such zeros would understate visibility. In SYNTH-001, DB = 0.0 *is* a real
zero: B and C were both available, and nothing new appeared.

## 8. Walkthrough of the two synthetic samples

**SYNTH-001 (open `out_demo/f81dbb79c0e9/`)**
* `normalization_audit.csv`: B's `T0001` is `revoked_replaced` → T1027 (marked `N5:merged`, since
  T1027 was already present). C's `T9998` is `unmapped`, kept and flagged.
* Measures: QA 0.75 · VA 0.4 · VB 0.4 · DB 0.0 · IB 0.6 · G 1 · L 0 · M 2 · O 2 · S∩C 1.
* `residual_classification.csv`: T1112 → P (`B_recovery#checks.V3`), T1620 → K
  (`C#rules.dyn-rule-4`), T9998 → U (no evidence). This gives **P=1, K=1 (P+K=2), U=1**.
* `gain_attribution.csv`: T1497 → payload (`B#rules.payload-rule-3`).
* The evidence is fictional. It shows how the rule works, not a conclusion.

**SYNTH-002 (open `out_demo/9cbe176c1651/results.json`)**
* Gate: `budget exceeded (25 > 20)` and `V4 not passed (3 imports failed to resolve)`.
* B = `not_recovered`. A B report *was* supplied and is explicitly noted as not used.
* QA, VB, DB, IB, G, L, M, O = n/d. VA = 0.4. Residual classes are n/d.

**Live gate demo:** `python tools/show_failure_cases.py` shows pilot-without-approval (exit 2),
B-without-record (exit 2), a changed input (sample aborted, exit 1), a sandbox source (rejected) and
registry refusals.

## 9. Limitations and pilot requirements

* The results are synthetic. The tests prove the arithmetic, the gates and reproducibility, nothing
  about real malware.
* V1–V5 and N1–N7 are working interpretations, because Review 1 names but does not define them.
* The capa JSON shape is assumed. The mapping table is fictional, and the official ATT&CK v20.0
  export is needed.
* The CAPE trace is one run with a limited duration, so it is a reference, not ground truth. capa
  rule coverage also limits what can be seen.
* The planned pilot is small (2–3 samples), with no population or detection-rate claims.
* **Order of work for the pilot:** confirm the assumptions, then get written institutional approval
  (Gate 3), then obtain samples, then run in pilot mode with the `approval_id`.

## 10. Likely examiner questions

**Q: Does your code unpack or execute malware?**
No. It only reads JSON reports. Unpacking and V1–V5 run in the operator's validated tool. The
pipeline checks the resulting record. No binary is ever opened, and `.gitignore` blocks executables.

**Q: Are these real results?**
No. Every input is fictional and marked `"synthetic": true`. The sample hashes are hashes of label
strings, and every output carries a SYNTHETIC notice.

**Q: How do you stop someone from feeding real data through demo mode without approval?**
Synthetic mode accepts only inputs marked synthetic. Pilot mode requires an `approval_id`, and it
rejects synthetic recovery records. This is a guard against mistakes, not a substitute for the
written approval, which must come first.

**Q: Why trust the recovery record?**
We don't trust it blindly. Each pass must be a literal `true`, must agree with its evidence (for
example, the entry point is inside a listed section, and the stored hash equals the payload hash),
and must come from `operator_tool`, within budget. Its validity still rests on the operator's tool.
That limitation is stated.

**Q: Why is IB always 1 − VB?**
Every C technique is either in B (counted by VB) or not (counted by IB), and both share the
denominator |C|. This is tested over all subset pairs.

**Q: DB is 0 in your example. Is that a bug?**
No. Both techniques in B∩C (T1055, T1027) were already in A, so unpacking added nothing new from
the reference. It is a real count. Compare SYNTH-002, where DB is n/d because B does not exist.

**Q: What happens to an ATT&CK ID that is not in the table, or is malformed?**
It is kept and flagged (`unmapped` / `invalid_format`) in the audit. Nothing is silently dropped.
Revoked IDs are replaced, and the audit records the replacement.

**Q: Why not count sandbox labels S in the measures?**
Sandbox ATT&CK mappings differ from capa's (Fujii et al., 2022). Mixing them would measure mapping
differences, not packing. We report only |S ∩ C|, separately.

**Q: How do you know a result wasn't edited afterwards?**
The manifest seals the SHA-256 of every output and raw input copy. `python -m pipeline verify`
recomputes them, and a test shows that one edited byte is detected. Reruns give the identical
`manifest_sha256` (`created_utc` is excluded).

**Q: How is a residual technique classified?**
Only from recorded evidence. The analyst's reference must resolve to a field of a hashed input,
otherwise the technique gets U. Unknown class letters, or evidence for techniques not in C \ B, are
errors.

**Q: Your guide says 39 tests. You have 64?**
There are 50 test functions, and parametrization expands them to 64 cases (one per failed check,
bad mapping row, registry rule and so on). Each case checks a distinct behaviour.

**Q: What if capa's real JSON differs from your assumed shape?**
The reader rejects a report without `rules` as *failed*. It does not read it as empty. Checking the
shape against the approved capa version is listed as assumption 3 before the pilot.
