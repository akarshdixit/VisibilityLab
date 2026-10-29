"use client";

import Link from "next/link";
import { useState } from "react";
import { get, post, type AppSettings, type Overview } from "@/lib/api";
import { Badge, ErrorText, Hash, Loading, useData } from "@/components/ui";

export default function OverviewPage() {
  const ov = useData(() => get<Overview>("/api/overview"), [], (d) => (d.jobs.queued ?? 0) + (d.jobs.running ?? 0) > 0);
  const st = useData(() => get<AppSettings>("/api/settings"), []);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  async function loadDemo() {
    setBusy(true);
    setErr(null);
    try {
      await post("/api/demo/synthetic");
      await ov.reload();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="sub">Same-sample comparison of packed-static (A), payload-static (B) and dynamic (C) capa outputs.</p>
        </div>
        <div className="row">
          <Link className="btn primary" href="/new">New analysis</Link>
          <button className="btn" onClick={loadDemo} disabled={busy} title="Imports the bundled fictional fixtures as synthetic samples">
            {busy ? "Importing…" : "Load synthetic demo"}
          </button>
        </div>
      </div>
      <ErrorText error={err} />

      {!ov.data ? (
        <Loading error={ov.error} what="overview (is the API running on 127.0.0.1:8000?)" />
      ) : (
        <>
          <div className="grid g4">
            <div className="card"><div className="stat">{ov.data.samples}</div><div className="stat-label">samples registered</div></div>
            <div className="card"><div className="stat">{ov.data.empirical_samples}</div><div className="stat-label">empirical (approved)</div></div>
            <div className="card"><div className="stat">{ov.data.synthetic_samples}</div><div className="stat-label">synthetic (demo only)</div></div>
            <div className="card">
              <div className="stat">{(ov.data.jobs.queued ?? 0) + (ov.data.jobs.running ?? 0)}</div>
              <div className="stat-label">analyses queued or running</div>
            </div>
          </div>

          <div className="card">
            <h2>Recent analyses</h2>
            {ov.data.recent_jobs.length === 0 ? (
              <p className="empty">No analyses yet. Create a sample, or load the synthetic demo.</p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Job</th><th>Sample</th><th>Type</th><th>Status</th><th>Progress</th><th>Finished</th></tr></thead>
                  <tbody>
                    {ov.data.recent_jobs.map((j) => (
                      <tr key={j.id}>
                        <td><Link href={`/analyses/${j.id}`}>#{j.id}</Link></td>
                        <td>{j.label || <Hash value={j.sha256} short />}</td>
                        <td><Badge status={j.mode} /></td>
                        <td><Badge status={j.status} /></td>
                        <td className="num">{j.progress}%</td>
                        <td className="sub">{j.finished_utc ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      <div className="grid g2">
        <div className="card">
          <h2>Research questions</h2>
          <p><b>RQ1</b> Which techniques does capa detect in the packed file, and how much of B and C do they overlap? <span className="sub">(QA, VA)</span></p>
          <p><b>RQ2</b> Which techniques are gained, retained or lost after unpacking, and which dynamic-reference techniques appear only then? <span className="sub">(G, L, DB)</span></p>
          <p><b>RQ3</b> Which dynamic-reference techniques remain absent after unpacking, and what recorded evidence explains them? <span className="sub">(IB, classes P K O E T M U)</span></p>
        </div>
        <div className="card">
          <h2>Safety status</h2>
          {st.data ? (
            <dl className="kv">
              <dt>Bind address</dt><dd className="mono">{st.data.bind}</dd>
              <dt>PE file storage</dt><dd>{st.data.safety.allow_sample_upload ? "enabled" : "disabled"}</dd>
              <dt>PE static analysis</dt><dd>{st.data.safety.pe_analysis_allowed ? "allowed (isolated VM acknowledged)" : "disabled"}</dd>
              <dt>capa</dt><dd>{st.data.capa.status}</dd>
              <dt>Dynamic execution</dt><dd>{st.data.safety.dynamic_execution}</dd>
              <dt>ATT&amp;CK mapping</dt><dd>{st.data.mapping.empirical.version}{st.data.mapping.empirical.exists ? "" : " (file missing!)"}</dd>
            </dl>
          ) : (
            <Loading error={st.error} what="settings" />
          )}
        </div>
      </div>
    </>
  );
}
