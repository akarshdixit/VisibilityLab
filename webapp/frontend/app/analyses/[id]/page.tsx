"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { Fragment, useState } from "react";
import { API_BASE, fileUrl, get, post, type AppSettings, type Audit, type Job, type Results, type StageKey } from "@/lib/api";
import { Badge, Counts, ErrorText, Hash, Loading, SyntheticBanner, V, useData } from "@/components/ui";

const STAGES: { key: StageKey; name: string; desc: string }[] = [
  { key: "A", name: "Packed static", desc: "capa on the packed file" },
  { key: "B", name: "Payload static", desc: "capa on the validated recovered payload" },
  { key: "C", name: "Dynamic reference", desc: "capa dynamic mode on the CAPE report" },
  { key: "S", name: "Sandbox labels", desc: "secondary; excluded from the measures" },
];
const MEASURE_ORDER = ["QA", "VA", "VB", "DB", "IB", "G", "L", "M", "O"];
const READS_AS: Record<string, string> = {
  QA: "payload techniques already visible while packed",
  VA: "dynamic reference visible in the packed file",
  VB: "dynamic reference visible in the payload",
  DB: "dynamic reference found only after unpacking",
  IB: "dynamic reference still missing after unpacking",
  G: "gained by unpacking",
  L: "lost by unpacking",
  M: "dynamic reference matched by the payload",
  O: "payload techniques not in the dynamic reference",
};
const DOWNLOADS = ["results.json", "normalization_audit.csv", "residual_classification.csv", "gain_attribution.csv", "manifest.json", "summary_metrics.csv"];
const active = (j: Job) => j.status === "queued" || j.status === "running";

export default function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const job = useData(() => get<Job>(`/api/jobs/${id}`), [id], active);
  const done = job.data?.status === "complete";
  const res = useData(() => (done ? get<Results>(`/api/jobs/${id}/results`) : Promise.resolve(null)), [id, done]);
  const audit = useData(() => (done ? get<Audit>(`/api/jobs/${id}/audit`) : Promise.resolve(null)), [id, done]);
  const st = useData(() => get<AppSettings>("/api/settings"), []);
  const [verify, setVerify] = useState<{ ok: boolean; problems: string[] } | null>(null);
  const [verr, setVerr] = useState<unknown>(null);

  if (!job.data) return <Loading error={job.error} what="analysis" />;
  const j = job.data;
  const r = res.data;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Analysis #{j.id} <Badge status={j.status} /></h1>
          <p className="sub">
            <Link href={`/samples/${j.sample_id}`}>sample #{j.sample_id}</Link> · created {j.created_utc}
            {j.finished_utc && <> · finished {j.finished_utc}</>}
          </p>
        </div>
        {done && (
          <div className="row">
            <a className="btn" href={fileUrl(j.id, "report.html")} target="_blank" rel="noreferrer">Printable report</a>
            <a className="btn" href={`${API_BASE}/api/jobs/${j.id}/export.zip`}>Export .zip</a>
            <button className="btn" onClick={async () => {
              try { setVerr(null); setVerify(await post(`/api/jobs/${j.id}/verify`)); } catch (e) { setVerr(e); }
            }}>Verify seal</button>
          </div>
        )}
      </div>
      {verify && (
        <div className={`banner ${verify.ok ? "info" : "danger"}`}>
          {verify.ok ? "Manifest verified: every output matches its sealed SHA-256." : `Seal problems: ${verify.problems.join("; ")}`}
        </div>
      )}
      <ErrorText error={verr} />

      {active(j) && (
        <div className="card">
          <h2>{j.status === "queued" ? "Waiting for the worker" : "Running"}: {j.message}</h2>
          <div className="progress"><div style={{ width: `${j.progress}%` }} /></div>
          {j.status === "queued" && <p className="hint">Start it with <code>python -m webapp.backend.worker</code> if no worker is running.</p>}
        </div>
      )}
      {j.status === "failed" && <div className="banner danger">Analysis failed: {j.error}</div>}
      {j.status === "interrupted" && <div className="banner danger">{j.error}</div>}
      {r && <SyntheticBanner synthetic={r.synthetic} />}

      <div className="grid g4">
        {STAGES.map((s) => (
          <div className="stage" key={s.key}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <span className="stage-key">{s.key}</span>
              <Badge status={j.stages[s.key]?.status ?? "queued"} />
            </div>
            <div><b>{s.name}</b></div>
            <div className="sub" style={{ fontSize: 12 }}>{s.desc}</div>
            {r && Array.isArray(r.sets[s.key]) && <div className="sub" style={{ fontSize: 12 }}>{(r.sets[s.key] as string[]).length} techniques</div>}
            {j.stages[s.key]?.notes.length > 0 && (
              <ul className="notes">{j.stages[s.key].notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
            )}
          </div>
        ))}
      </div>

      {r && (
        <>
          <div className="card" style={{ marginTop: 16 }}>
            <h2>Recovery gate</h2>
            <p>
              {r.recovery_gate.accepted ? (
                <><Badge status="complete" /> accepted: V1–V5 passed, source operator_tool, within budget</>
              ) : j.stages.B?.status === "awaiting_input" ? (
                <><Badge status="awaiting_input" /> no recovery record yet (recovery runs in the separate, validated process)</>
              ) : (
                <><Badge status="not_recovered" /> rejected: Stage B is not used and B-dependent measures are n/d</>
              )}
            </p>
            {r.recovery_gate.reasons.length > 0 && <ul className="notes">{r.recovery_gate.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>}
          </div>

          <div className="grid g2">
            <div className="card">
              <h2>Measures</h2>
              <table>
                <thead><tr><th>Measure</th><th>Definition</th><th className="num">Value</th><th>Counts</th></tr></thead>
                <tbody>
                  {MEASURE_ORDER.map((k) => (
                    <tr key={k} title={READS_AS[k]}>
                      <td><b>{k}</b></td>
                      <td className="mono">{st.data?.measures[k] ?? ""}</td>
                      <td className="num"><V v={r.measures[k]} ratio={["QA", "VA", "VB", "DB", "IB"].includes(k)} /></td>
                      <td><Counts inp={r.measure_inputs[k]} /></td>
                    </tr>
                  ))}
                  <tr>
                    <td><b>S∩C</b></td>
                    <td className="sub">|S ∩ C|, secondary, not a measure</td>
                    <td className="num"><V v={r.secondary.S_overlap_C} /></td>
                    <td><Counts inp={r.secondary.S_inputs} /></td>
                  </tr>
                </tbody>
              </table>
              <p className="hint">n/d = not defined (a stage is unavailable or a denominator is empty). It is never shown as 0.</p>
            </div>
            <Overlap r={r} />
          </div>

          <div className="grid g2">
            <div className="card">
              <h2>RQ2 · gains and losses</h2>
              <SetRow label="Gained (B \ A)" v={r.research_questions.RQ2_gained_after_unpacking} cls="gain" />
              <SetRow label="Kept (A ∩ B)" v={r.research_questions.RQ2_kept} />
              <SetRow label="Lost (A \ B)" v={r.research_questions.RQ2_lost} cls="loss" />
              <SetRow label="Dynamic only after unpacking ((B∩C) \ A)" v={r.research_questions.RQ2_dynamic_only_after_unpacking} cls="gain" />
              {audit.data && audit.data.gain_attribution.length > 0 && (
                <table style={{ marginTop: 10 }}>
                  <thead><tr><th>Gain</th><th>Attribution</th><th>Evidence</th></tr></thead>
                  <tbody>{audit.data.gain_attribution.map((g) => (
                    <tr key={g.technique}><td className="mono">{g.technique}</td><td>{g.attribution}</td><td className="mono">{g.evidence_ref || <span className="sub">{g.reason}</span>}</td></tr>
                  ))}</tbody>
                </table>
              )}
            </div>
            <div className="card">
              <h2>RQ3 · residual differences (C \ B)</h2>
              {r.residual_classification.status !== "ok" ? (
                <p className="nd">{r.residual_classification.status}: {r.residual_classification.reason}</p>
              ) : (
                <>
                  <p><b>{r.residual_classification.pk_summary}</b>
                    {typeof r.residual_classification.class_counts === "object" && (
                      <span className="sub"> · O={r.residual_classification.class_counts.O} E={r.residual_classification.class_counts.E} T={r.residual_classification.class_counts.T} M={r.residual_classification.class_counts.M} U={r.residual_classification.class_counts.U}</span>
                    )}
                  </p>
                  <table>
                    <thead><tr><th>Technique</th><th>Class</th><th>Evidence reference</th><th>Reason</th></tr></thead>
                    <tbody>{audit.data?.residual_classification.map((x) => (
                      <tr key={x.technique}>
                        <td className="mono">{x.technique}</td>
                        <td title={x.class_meaning}><b>{x.class}</b>{x.class === "U" && <span className="sub"> unresolved</span>}</td>
                        <td className="mono">{x.evidence_ref || "—"}</td>
                        <td className="sub">{x.reason}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </>
              )}
            </div>
          </div>

          <div className="card">
            <h2>Downloads</h2>
            <div className="row">
              {DOWNLOADS.map((n) => <a key={n} className="btn sm" href={fileUrl(j.id, n)}>{n}</a>)}
              <Link className="btn sm" href={`/evidence?job=${j.id}`}>Normalization audit</Link>
            </div>
          </div>
        </>
      )}

      <div className="grid g2">
        <div className="card">
          <h2>Provenance</h2>
          <dl className="kv">
            <dt>ATT&amp;CK mapping</dt><dd>{j.mapping_name ?? "—"} · {j.mapping_version ?? "—"}<br /><Hash value={j.mapping_sha256} /></dd>
            <dt>Manifest SHA-256</dt><dd><Hash value={j.manifest_sha256} /></dd>
            {Object.entries(j.tools).map(([t, v]) => (<Fragment key={t}><dt>{t}</dt><dd className="mono">{v}</dd></Fragment>))}
          </dl>
          <h3 style={{ marginTop: 14 }}>Inputs (hash-verified)</h3>
          <table>
            <tbody>{j.inputs.map((i) => (
              <tr key={i.key}><td className="mono">{i.key}</td><td>{i.origin}{i.tool_name ? ` · ${i.tool_name} ${i.tool_version}` : ""}</td><td><Hash value={i.sha256} short /></td></tr>
            ))}</tbody>
          </table>
        </div>
        <div className="card">
          <h2>Event log</h2>
          <div className="table-wrap" style={{ maxHeight: 320, overflowY: "auto" }}>
            <table>
              <tbody>{j.events.map((e, i) => (
                <tr key={i}><td className="sub mono" style={{ whiteSpace: "nowrap" }}>{e.ts_utc.slice(11)}</td><td className={e.level === "error" ? "err" : ""}>{e.message}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}

function SetRow({ label, v, cls }: { label: string; v: string[] | "n/d" | undefined; cls?: string }) {
  return (
    <div className="field">
      <label>{label}</label>
      {v === undefined || v === "n/d" ? <span className="nd">n/d</span> : v.length === 0 ? <span className="sub">∅ (none)</span> : (
        <div className="chips">{v.map((t) => <span key={t} className={`chip ${cls ?? ""}`}>{t}</span>)}</div>
      )}
    </div>
  );
}

function Overlap({ r }: { r: Results }) {
  const keys: StageKey[] = ["A", "B", "C", "S"];
  const all = new Set<string>();
  keys.forEach((k) => Array.isArray(r.sets[k]) && (r.sets[k] as string[]).forEach((t) => all.add(t)));
  const rows = [...all].sort();
  return (
    <div className="card">
      <h2>Technique overlap</h2>
      {rows.length === 0 ? <p className="empty">No techniques in any available stage.</p> : (
        <div className="table-wrap">
          <table className="matrix">
            <thead><tr><th>Technique</th>{keys.map((k) => <th key={k} style={{ textAlign: "center" }}>{k}</th>)}</tr></thead>
            <tbody>{rows.map((t) => (
              <tr key={t}>
                <td className="mono">{t}</td>
                {keys.map((k) => {
                  const s = r.sets[k];
                  if (s === "n/d") return <td key={k} className="na">n/d</td>;
                  return s.includes(t) ? <td key={k} className="hit">●</td> : <td key={k} className="miss">·</td>;
                })}
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <p className="hint">S is shown for comparison only and never enters the measures.</p>
    </div>
  );
}
