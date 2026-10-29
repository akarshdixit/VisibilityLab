"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { get, post, type AppSettings, type DemoScenario, type Sample } from "@/lib/api";
import { ErrorText, Loading, useData } from "@/components/ui";
import { Uploader } from "@/components/Uploader";
import { HashCalculator } from "@/components/HashCalculator";
import { OnboardingChecklist, StageMatrix } from "@/components/Onboarding";

type Mode = "demo" | "empirical";
type Workflow = "evidence" | "static";

const today = () => new Date().toISOString().slice(0, 10);
const SHA_RE = /^[0-9a-fA-F]{64}$/;

export default function NewAnalysisPage() {
  const [mode, setMode] = useState<Mode>("demo");
  useEffect(() => {
    // /new?mode=empirical opens the empirical tab directly (useful for links from docs)
    if (new URLSearchParams(window.location.search).get("mode") === "empirical") setMode("empirical");
  }, []);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>New analysis</h1>
          <p className="sub">Choose a mode. The two never mix: demo data cannot be attached to an empirical sample.</p>
        </div>
      </div>
      <div className="modes" role="tablist">
        <button role="tab" aria-selected={mode === "demo"} className={`mode demo ${mode === "demo" ? "on" : ""}`} onClick={() => setMode("demo")}>
          <div className="mode-title">Demo mode <span className="badge b-synthetic">synthetic</span></div>
          <div className="mode-desc">
            No sample, SHA-256, source or approval needed. Runs the full workflow on fictional evidence so you can learn
            the app. Results are labelled synthetic everywhere.
          </div>
        </button>
        <button role="tab" aria-selected={mode === "empirical"} className={`mode emp ${mode === "empirical" ? "on" : ""}`} onClick={() => setMode("empirical")}>
          <div className="mode-title">Empirical study <span className="badge b-empirical">empirical</span></div>
          <div className="mode-desc">
            A real (approved) sample with documented provenance and genuine reports. Requires the SHA-256, source, retrieval
            date and the written approval reference (Gate 3).
          </div>
        </button>
      </div>
      {mode === "demo" ? <DemoPanel /> : <EmpiricalPanel />}
    </>
  );
}

function DemoPanel() {
  const router = useRouter();
  const scenarios = useData(() => get<DemoScenario[]>("/api/demo/scenarios"), []);
  const [scenario, setScenario] = useState<"accepted" | "rejected">("accepted");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);

  async function create() {
    setErr(null);
    setBusy("create");
    try {
      const s = await post<Sample>("/api/demo/samples", { scenario, label });
      router.push(`/samples/${s.id}`);
    } catch (e) {
      setErr(e);
      setBusy(null);
    }
  }

  async function bundled() {
    setErr(null);
    setBusy("bundled");
    try {
      await post("/api/demo/synthetic");
      router.push("/samples");
    } catch (e) {
      setErr(e);
      setBusy(null);
    }
  }

  return (
    <>
      <div className="banner">
        Demo mode uses FICTIONAL data. Its numbers demonstrate the method; they are not results about any real file and must
        not be reported as such.
      </div>
      <div className="grid g2">
        <div className="card">
          <h2>1 · Create a demo sample</h2>
          <p className="sub" style={{ marginBottom: 10 }}>
            A fresh fictional SHA-256 is generated for you. Next you attach demo evidence step by step, run the analysis and
            explore the results, audit and exports.
          </p>
          {!scenarios.data ? <Loading error={scenarios.error} what="scenarios" /> : scenarios.data.map((s) => (
            <label key={s.name} className={`radio ${scenario === s.name ? "on" : ""}`}>
              <input type="radio" name="scenario" checked={scenario === s.name} onChange={() => setScenario(s.name)} />
              <span><b>{s.name === "accepted" ? "Recovery accepted" : "Recovery rejected"}</b><br /><span className="sub">{s.description}</span></span>
            </label>
          ))}
          <div className="field">
            <label htmlFor="demolabel">Label (optional)</label>
            <input id="demolabel" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. My first demo" />
          </div>
          <button className="btn primary" onClick={create} disabled={busy !== null}>{busy === "create" ? "Creating…" : "Create demo sample"}</button>
          <ErrorText error={err} />
        </div>
        <div className="card">
          <h2>What happens next</h2>
          <ol className="sub" style={{ paddingLeft: 18, margin: 0 }}>
            <li>On the sample page, the <b>demo evidence kit</b> lists the six inputs (A, recovery record, B, C, S, evidence).</li>
            <li>Attach them one at a time, all at once, or download one and drop it on the matching upload box, which uses
              the same validation as real uploads.</li>
            <li>Click <b>Run analysis</b>. With everything attached, “accepted” reproduces the guide&apos;s worked example
              (QA 0.75, VA 0.4, VB 0.4, DB 0.0, IB 0.6). Leave items out to see <i>awaiting input</i> and n/d.</li>
            <li>Open the printable report, the evidence and audit view, and the exports.</li>
          </ol>
          <h3 style={{ marginTop: 16 }}>Bundled fixtures</h3>
          <p className="sub">Import the two original fixture samples (SYNTH-001 and SYNTH-002) and queue both analyses at once.</p>
          <button className="btn" onClick={bundled} disabled={busy !== null}>{busy === "bundled" ? "Importing…" : "Load bundled synthetic demo"}</button>
        </div>
      </div>
    </>
  );
}

function EmpiricalPanel() {
  const router = useRouter();
  const st = useData(() => get<AppSettings>("/api/settings"), []);
  const [wf, setWf] = useState<Workflow>("evidence");
  const [f, setF] = useState({ sha256: "", label: "", approval_id: "", source: "", retrieved: today(), packer_label: "", note: "" });
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });

  const missing: string[] = [];
  if (!f.approval_id.trim()) missing.push("approval reference");
  if (!f.source.trim()) missing.push("source");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(f.retrieved)) missing.push("retrieval date (YYYY-MM-DD)");
  const shaOk = SHA_RE.test(f.sha256.trim());

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const s = await post<Sample>("/api/samples", { ...f, sha256: f.sha256.trim(), mode: "empirical" });
      router.push(`/samples/${s.id}`);
    } catch (e2) {
      setErr(e2);
      setBusy(false);
    }
  }

  return (
    <>
      <div className="banner info">
        Gate 3: empirical samples need the reference on your written institutional approval. VisibilityLab cannot check that
        a reference is genuine; it refuses empty or placeholder values. If you do not have one yet, use <b>demo mode</b>.
        Never type an invented reference.
      </div>

      <div className="card">
        <h2>Which stages need an isolated sandbox?</h2>
        <StageMatrix />
      </div>

      <div className="grid g2">
        <div className="card">
          <h2>Onboarding checklist: a benign UPX-packed control</h2>
          <OnboardingChecklist />
        </div>

        <div>
          <div className="card">
            <h2>Register the sample</h2>
            <div className="tabs">
              <button className={wf === "evidence" ? "on" : ""} onClick={() => setWf("evidence")}>Existing evidence (by SHA-256)</button>
              <button className={wf === "static" ? "on" : ""} onClick={() => setWf("static")}>Local static analysis (PE upload)</button>
            </div>
            <div className="field">
              <label htmlFor="approval">Approval reference (Gate 3) *</label>
              <input id="approval" value={f.approval_id} onChange={set("approval_id")} placeholder="as written on your approval letter" />
              <div className="hint">Required. Empty or placeholder values such as “n/a” or “tbd” are refused.</div>
            </div>
            <div className="field">
              <label htmlFor="source">Source *</label>
              <input id="source" value={f.source} onChange={set("source")} placeholder="where the file came from, documented" />
              <div className="hint">For example: self-built benign control (hello.c, compiler and version), packed with UPX &lt;version&gt;.</div>
            </div>
            <div className="grid g2">
              <div className="field">
                <label htmlFor="retrieved">Obtained on (YYYY-MM-DD) *</label>
                <input id="retrieved" value={f.retrieved} onChange={set("retrieved")} />
              </div>
              <div className="field">
                <label htmlFor="packer">Packer label</label>
                <input id="packer" value={f.packer_label} onChange={set("packer_label")} placeholder="e.g. UPX 4.x (from DIE)" />
              </div>
            </div>
            <div className="field">
              <label htmlFor="label">Display label</label>
              <input id="label" value={f.label} onChange={set("label")} placeholder="e.g. S1 UPX control" />
            </div>
            <div className="field">
              <label htmlFor="note">Note</label>
              <textarea id="note" rows={2} value={f.note} onChange={set("note")} />
            </div>

            {wf === "evidence" ? (
              <form onSubmit={create}>
                <div className="field">
                  <label htmlFor="sha">Packed sample SHA-256 *</label>
                  <input id="sha" className="mono" value={f.sha256} onChange={set("sha256")} placeholder="64 hex characters" />
                  {f.sha256 && !shaOk && <div className="err">must be exactly 64 hexadecimal characters</div>}
                </div>
                {missing.length > 0 && <p className="hint">Still needed: {missing.join(", ")}.</p>}
                <button className="btn primary" disabled={busy || !shaOk || missing.length > 0}>{busy ? "Registering…" : "Register empirical sample"}</button>
                <ErrorText error={err} />
              </form>
            ) : !st.data ? (
              <Loading error={st.error} what="settings" />
            ) : !st.data.safety.allow_sample_upload ? (
              <p className="sub">
                PE upload is disabled on this installation (<code>VL_ALLOW_SAMPLE_UPLOAD=false</code>). Register by SHA-256
                and import reports instead. Enable uploads only on an isolated analysis host.
              </p>
            ) : missing.length > 0 ? (
              <p className="hint">Fill in: {missing.join(", ")}.</p>
            ) : (
              <Uploader
                title="Packed Windows PE"
                accept="pe"
                maxMb={st.data.limits_mb.pe}
                path="/api/samples/from-pe"
                fields={{ approval_id: f.approval_id, source: f.source, retrieved: f.retrieved, label: f.label, packer_label: f.packer_label, note: f.note }}
                onDone={(s) => router.push(`/samples/${(s as Sample).id}`)}
              />
            )}
          </div>
          <div className="card">
            <h2>SHA-256 calculator</h2>
            <HashCalculator onHash={(sha) => setF((prev) => ({ ...prev, sha256: sha }))} />
          </div>
        </div>
      </div>
    </>
  );
}
