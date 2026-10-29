"use client";

import { useEffect, useState } from "react";

type Where = "none" | "host-ok" | "isolated";

const WHERE_LABEL: Record<Where, string> = {
  none: "existing report: no tools",
  "host-ok": "static, no execution",
  isolated: "isolated sandbox required",
};

/** Which stages need what. "Existing report" means VisibilityLab only reads a file produced elsewhere. */
export function StageMatrix() {
  const rows: { stage: string; importIt: string; produceIt: string; where: Where[]; note: string }[] = [
    { stage: "A", importIt: "capa JSON for the packed file", produceIt: "capa (static) on the packed file", where: ["none", "host-ok"],
      note: "capa reads the file without running it. For a benign self-built control any machine will do; for real malware use the isolated VM (Gate 3)." },
    { stage: "B gate", importIt: "recovery record (V1–V5, budget, payload hash)", produceIt: "your validated recovery tool", where: ["none", "host-ok", "isolated"],
      note: "\"upx -d\" decompresses statically without running the file. Manual unpacking (x64dbg + Scylla) executes the sample: isolated VM only." },
    { stage: "B", importIt: "capa JSON for the recovered payload", produceIt: "capa (static) on the payload", where: ["none", "host-ok"],
      note: "Used only if the recovery record passes the gate." },
    { stage: "C", importIt: "genuine CAPE report, or capa dynamic JSON made from it", produceIt: "a CAPE sandbox run of the sample", where: ["none", "isolated"],
      note: "Producing the report executes the sample, so only an isolated sandbox with no network route (local CAPEv2 or the course-approved instance). Importing an existing report needs nothing." },
    { stage: "S", importIt: "sandbox ATT&CK label list", produceIt: "the same CAPE report (its ttps section)", where: ["none"],
      note: "Derived automatically from an imported CAPE report. Never enters the measures." },
    { stage: "Analysis", importIt: "nothing more", produceIt: "VisibilityLab worker", where: ["none"],
      note: "Normalization, measures, classification and the manifest read reports only." },
  ];
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Stage</th><th>What you import</th><th>How it is produced</th><th>Where</th><th>Notes</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.stage}>
              <td><b>{r.stage}</b></td>
              <td>{r.importIt}</td>
              <td>{r.produceIt}</td>
              <td><div className="chips">{r.where.map((w) => <span key={w} className={`tag tag-${w}`}>{WHERE_LABEL[w]}</span>)}</div></td>
              <td className="sub">{r.note}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const STEPS: { id: string; title: string; body: React.ReactNode }[] = [
  {
    id: "approval",
    title: "Get the written approval reference",
    body: (
      <>
        Ask your guide for the reference on the written institutional approval for the pilot. VisibilityLab requires it
        for every empirical sample, <b>including a benign control</b>. Do not invent one. Until you have it, use{" "}
        <b>demo mode</b>.
      </>
    ),
  },
  {
    id: "control",
    title: "Build a documented benign UPX-packed control",
    body: (
      <>
        Use a benign program whose origin you can document: for example, compile a small hello-world yourself, or take an
        open-source tool from its official release page. Record its name, version, origin and SHA-256. Download UPX from its
        official release page (github.com/upx/upx) and record the version. Then pack and test it:
        <pre className="cmd">{"upx --best -o hello_upx.exe hello.exe\nupx -t hello_upx.exe"}</pre>
        Keep these files in your own analysis folder, never in this repository. The control contains no malware; it is the
        proposal&apos;s “S1” pipeline control.
      </>
    ),
  },
  {
    id: "hash",
    title: "Calculate its SHA-256",
    body: (
      <>
        In PowerShell (the app lower-cases the result), or use the local calculator on this page:
        <pre className="cmd">{"Get-FileHash .\\hello_upx.exe -Algorithm SHA256"}</pre>
      </>
    ),
  },
  {
    id: "register",
    title: "Register the sample with its provenance",
    body: (
      <>
        Fill in the form: <b>source</b> (for example “self-built benign control: hello.c compiled with &lt;compiler
        version&gt;, packed with UPX &lt;version&gt;”), the date you made or obtained it, and the packer label. Every report
        you import is checked against this SHA-256.
      </>
    ),
  },
  {
    id: "capaA",
    title: "Generate a genuine capa report for Stage A",
    body: (
      <>
        Download standalone capa from its official release page (github.com/mandiant/capa), record{" "}
        <code>capa --version</code>, then write the JSON through cmd so the bytes stay UTF-8:
        <pre className="cmd">{'cmd /c "capa.exe -j hello_upx.exe > A.json"'}</pre>
        capa may warn that the file looks packed; that is the effect being measured. Attach <code>A.json</code> as
        “Stage A”.
      </>
    ),
  },
  {
    id: "recovery",
    title: "Recover and validate the payload (Stage B)",
    body: (
      <>
        For standard UPX, decompress statically (this does not run the program):
        <pre className="cmd">{"upx -d hello_upx.exe -o hello_unpacked.exe\ncmd /c \"capa.exe -j hello_unpacked.exe > B.json\""}</pre>
        Run your validated checks V1–V5 (for example a pefile script) and write the recovery record in the documented format
        (<code>pipeline/recovery.py</code>): <code>check_source</code> = <code>operator_tool</code>, the payload SHA-256 and
        the budget used and allowed. Every value must come from an actual check, not from expectation. Attach the record
        first, then <code>B.json</code>.
      </>
    ),
  },
  {
    id: "cape",
    title: "Stage C and S: CAPE report (isolated sandbox only)",
    body: (
      <>
        Producing a CAPE report <b>runs the sample</b>. Do it only in an isolated CAPEv2 sandbox with no network route, or
        on the course-approved instance. Check that the report&apos;s <code>target.file.sha256</code> equals your SHA-256,
        then import it as “CAPE report”: S is derived from its own labels, and C needs a pinned capa (or run{" "}
        <code>capa -j -f cape report.json</code> yourself and import “C”). Without a report, C and S stay{" "}
        <i>awaiting input</i> and their measures are n/d.
      </>
    ),
  },
  {
    id: "evidence",
    title: "Record evidence and run the analysis",
    body: (
      <>
        For each technique in C \ B, record a class and an evidence reference such as <code>C#rules.&lt;rule&gt;</code> in
        an evidence file. Without evidence it stays U. Then run the analysis, verify the seal and export.
      </>
    ),
  },
];

const KEY = "visibilitylab.onboarding.v1";

export function OnboardingChecklist() {
  const [done, setDone] = useState<Record<string, boolean>>({});
  useEffect(() => {
    try {
      setDone(JSON.parse(localStorage.getItem(KEY) || "{}"));
    } catch {
      /* storage unavailable: the checklist still works for this visit */
    }
  }, []);
  function toggle(id: string) {
    const next = { ...done, [id]: !done[id] };
    setDone(next);
    try {
      localStorage.setItem(KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }
  const count = STEPS.filter((s) => done[s.id]).length;
  return (
    <div>
      <p className="sub" style={{ marginBottom: 10 }}>{count} of {STEPS.length} done · ticks are saved in this browser only</p>
      <ol className="checklist">
        {STEPS.map((s, i) => (
          <li key={s.id} className={done[s.id] ? "done" : ""}>
            <label className="check">
              <input type="checkbox" checked={!!done[s.id]} onChange={() => toggle(s.id)} />
              <span><b>{i + 1}. {s.title}</b></span>
            </label>
            <div className="step-body">{s.body}</div>
          </li>
        ))}
      </ol>
    </div>
  );
}
