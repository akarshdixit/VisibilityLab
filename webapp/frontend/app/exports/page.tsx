"use client";

import Link from "next/link";
import { API_BASE, fileUrl, get, type JobSummary } from "@/lib/api";
import { Badge, Hash, Loading, useData } from "@/components/ui";

const FILES = ["results.json", "normalization_audit.csv", "residual_classification.csv", "gain_attribution.csv", "manifest.json"];

export default function ExportsPage() {
  const { data, error } = useData(() => get<JobSummary[]>("/api/jobs"), []);
  const complete = (data ?? []).filter((j) => j.status === "complete");
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Exports</h1>
          <p className="sub">Sealed per-sample research outputs and the batch summary.</p>
        </div>
        <a className="btn primary" href={`${API_BASE}/api/export/summary.csv`}>summary_metrics.csv (latest per sample)</a>
      </div>
      <div className="banner">
        Exports of synthetic analyses carry a SYNTHETIC notice in results.json and the report. Do not present them as results about real malware.
      </div>
      <div className="card">
        {!data ? <Loading error={error} what="analyses" /> : complete.length === 0 ? <p className="empty">No completed analyses.</p> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Job</th><th>Sample</th><th>Type</th><th>Mapping</th><th>Manifest</th><th>Files</th></tr></thead>
              <tbody>{complete.map((j) => (
                <tr key={j.id}>
                  <td><Link href={`/analyses/${j.id}`}>#{j.id}</Link></td>
                  <td>{j.label || <Hash value={j.sha256} short />}</td>
                  <td><Badge status={j.mode} /></td>
                  <td className="sub">{j.mapping_version}</td>
                  <td><Hash value={j.manifest_sha256} short /></td>
                  <td>
                    <div className="row">
                      {FILES.map((f) => <a key={f} className="btn sm" href={fileUrl(j.id, f)}>{f.replace(".csv", "").replace(".json", "")}</a>)}
                      <a className="btn sm" href={fileUrl(j.id, "report.html")} target="_blank" rel="noreferrer">report</a>
                      <a className="btn sm" href={`${API_BASE}/api/jobs/${j.id}/export.zip`}>.zip</a>
                    </div>
                  </td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
