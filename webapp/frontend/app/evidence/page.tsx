"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { get, type Audit, type EvidenceRef, type JobSummary } from "@/lib/api";
import { Badge, Hash, Loading, useData } from "@/components/ui";

export default function EvidencePage() {
  return (
    <Suspense fallback={<p className="sub">Loading…</p>}>
      <EvidenceInner />
    </Suspense>
  );
}

function EvidenceInner() {
  const params = useSearchParams();
  const refs = useData(() => get<EvidenceRef[]>("/api/evidence"), []);
  const jobs = useData(() => get<JobSummary[]>("/api/jobs"), []);
  const [jobId, setJobId] = useState<string>(params.get("job") ?? "");
  const audit = useData(() => (jobId ? get<Audit>(`/api/jobs/${jobId}/audit`) : Promise.resolve(null)), [jobId]);
  const complete = (jobs.data ?? []).filter((j) => j.status === "complete");

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Evidence and audit</h1>
          <p className="sub">Every classification with its evidence reference, and every raw ATT&amp;CK ID with the normalization rules applied.</p>
        </div>
      </div>

      <div className="card">
        <h2>Classification evidence (all analyses)</h2>
        {!refs.data ? <Loading error={refs.error} what="evidence" /> : refs.data.length === 0 ? (
          <p className="empty">No classifications recorded yet.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Job</th><th>Sample</th><th>Type</th><th>Set</th><th>Technique</th><th>Class / attribution</th><th>Evidence reference</th><th>Reason</th></tr></thead>
              <tbody>{refs.data.map((e, i) => (
                <tr key={i}>
                  <td><Link href={`/analyses/${e.job_id}`}>#{e.job_id}</Link></td>
                  <td>{e.sample_label || <Hash value={e.sha256} short />}</td>
                  <td><Badge status={e.mode} /></td>
                  <td>{e.kind === "residual" ? "C \\ B" : "B \\ A"}</td>
                  <td className="mono">{e.technique}</td>
                  <td><b>{e.label}</b></td>
                  <td className="mono">{e.evidence_ref || "—"}</td>
                  <td className="sub">{e.reason}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        <p className="hint">Classes other than U are kept only when the reference resolves to a field of a hash-verified input; otherwise they become U.</p>
      </div>

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
          <h2 style={{ margin: 0 }}>Normalization audit (N1–N7)</h2>
          <select style={{ width: 280 }} value={jobId} onChange={(e) => setJobId(e.target.value)} aria-label="analysis">
            <option value="">Choose a completed analysis…</option>
            {complete.map((j) => <option key={j.id} value={j.id}>#{j.id} · {j.label || j.sha256.slice(0, 12)} ({j.mode})</option>)}
          </select>
        </div>
        {!jobId ? <p className="empty">Select an analysis to view its audit rows.</p> : !audit.data ? <Loading error={audit.error} what="audit" /> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Stage</th><th>Raw ID</th><th>Normalized</th><th>Status</th><th>Rules applied</th><th>Source rules</th></tr></thead>
              <tbody>{audit.data.normalization_audit.map((r, i) => (
                <tr key={i}>
                  <td>{r.stage}</td>
                  <td className="mono">{JSON.stringify(r.raw_id)}</td>
                  <td className="mono">{r.normalized_id}</td>
                  <td>{r.status === "current" ? r.status : <b className={r.status === "revoked_replaced" ? "" : "nd"}>{r.status}</b>}</td>
                  <td className="mono">{r.rules_applied}</td>
                  <td className="mono sub">{r.source_rules}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
