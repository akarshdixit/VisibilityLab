# Getting started: demo mode first, then a benign UPX control

You can learn and demonstrate VisibilityLab **today**, without a sample, a SHA-256, a source record,
reports or an approval reference: use **demo mode**. Empirical mode needs all of those. The app
refuses to proceed without them and never generates them for you.

## Demo mode (no prerequisites)

**New Analysis → Demo mode → Create demo sample** (scenario *accepted* or *rejected*). The app
generates a fictional SHA-256. On the sample page, the **demo evidence kit** lets you attach the six
synthetic inputs one by one, all at once, or download them and drag them into the normal upload
boxes. Then click **Run analysis**.

* *accepted* with everything attached reproduces the guide's worked example: QA 0.75, VA 0.4, VB 0.4,
  DB 0.0, IB 0.6, G 1, L 0, M 2, O 2, S∩C 1, with residual classes P=1, K=1 (P+K=2), U=1.
* *rejected* gives B = not recovered (V4 not passed; budget exceeded (25 > 20)), VA 0.4, and n/d for
  every B-dependent measure.
* Attaching only some items shows the missing stages as *awaiting input*, with their measures n/d.

Every demo file is marked `"synthetic": true`, so it cannot be attached to an empirical sample, and
every result page and report carries a SYNTHETIC banner. **Demo numbers are not research results.**

## Which stages need an isolated sandbox?

| Stage | You import | It is produced by | Isolation |
|-------|-----------|-------------------|-----------|
| A | capa JSON for the packed file | capa (static) | Importing an existing report needs no tools. capa does not run the file. Use the isolated VM for real malware (Gate 3). |
| B gate | recovery record (V1–V5, budget, payload hash) | your validated recovery tool | `upx -d` is static. Manual unpacking (x64dbg + Scylla) **executes the sample**, so isolated VM only. |
| B | capa JSON for the payload | capa (static) | No execution. Used only if the gate accepts. |
| C | genuine CAPE report, or capa dynamic JSON made from it | a CAPE sandbox run | **Producing it executes the sample: isolated sandbox with no network route only.** Importing an existing report needs nothing. |
| S | sandbox label list | the same CAPE report's `ttps` | Derived automatically from an imported report. |
| Analysis | — | VisibilityLab worker | Reads reports only. |

## Checklist: a documented benign UPX-packed control

The proposal's S1 is a UPX-packed pipeline control. A self-built benign program packed with UPX
contains no malware and gives you **genuine** capa output to test the empirical path end to end.

1. **Approval reference.** Ask your guide for the reference on the written institutional approval.
   VisibilityLab requires it for every empirical sample, including this control, and refuses empty
   or placeholder values ("n/a", "tbd", "demo", …). Do not invent one. Until you have it, stay in
   demo mode.
2. **Build the control.** Use a benign program whose origin you can document (for example, a small
   hello-world you compile yourself, or an open-source tool from its official release page). Record
   its name, version, origin and SHA-256. Get UPX from its official releases (github.com/upx/upx)
   and record the version. Then:
   ```powershell
   upx --best -o hello_upx.exe hello.exe
   upx -t hello_upx.exe
   ```
   Keep these files in your own analysis folder, never in this repository.
3. **SHA-256.** Run `Get-FileHash .\hello_upx.exe -Algorithm SHA256`, or use the calculator on the
   New Analysis page, which hashes in the browser and uploads nothing.
4. **Register.** In New Analysis → Empirical study, enter the approval reference, the source (for
   example "self-built benign control: hello.c, compiler and version, packed with UPX version"), the
   date, the packer label and the SHA-256.
5. **Stage A: genuine capa report.** Get standalone capa from its official releases
   (github.com/mandiant/capa) and record `capa --version`:
   ```powershell
   cmd /c "capa.exe -j hello_upx.exe > A.json"
   ```
   Running it through `cmd` keeps the output UTF-8; Windows PowerShell 5.1 redirection writes
   UTF-16. capa may warn that the file looks packed, which is the effect being measured. Attach
   `A.json` as Stage A.
6. **Stage B.** `upx -d hello_upx.exe -o hello_unpacked.exe` (static), then
   `cmd /c "capa.exe -j hello_unpacked.exe > B.json"`. Run your validated V1–V5 checks (for example a
   pefile script) and write the recovery record in the format documented in `pipeline/recovery.py`.
   Every value must come from an actual check. Attach the record, then `B.json`.
7. **Stage C and S (isolated sandbox only).** A CAPE report requires running the file. Do it only
   in an isolated CAPEv2 sandbox with no network route, or on the course-approved instance. Check
   that `target.file.sha256` equals your SHA-256, then import it as "CAPE report". S is derived from
   it. C needs a pinned capa (`capa -j -f cape report.json`), or you can import C yourself. Without
   a report, C and S stay *awaiting input*.
8. **Evidence and run.** For each technique in C \ B, record a class and an evidence reference
   (`<input key>#<field path>`). Without one, it is U. Run the analysis, verify the seal and export.

Note: a benign control tests the pipeline. It says nothing about malware behaviour, so report it as
a control.
