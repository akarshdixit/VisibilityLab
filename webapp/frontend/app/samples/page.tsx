"use client";

import Link from "next/link";
import { get, type Sample } from "@/lib/api";
import { Badge, Hash, Loading, useData } from "@/components/ui";

export default function SamplesPage() {
  const { data, error } = useData(() => get<Sample[]>("/api/samples"), []);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Samples</h1>
          <p className="sub">Candidate register: provenance keyed by SHA-256.</p>
        </div>
        <Link className="btn primary" href="/new">Register sample</Link>
      </div>
      <div className="card">
        {!data ? (
          <Loading error={error} what="samples" />
        ) : data.length === 0 ? (
          <p className="empty">No samples registered.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Label</th><th>SHA-256</th><th>Type</th><th>Approval</th><th>Source</th><th>Retrieved</th><th>Evidence files</th><th>Last analysis</th></tr>
              </thead>
              <tbody>
                {data.map((s) => (
                  <tr key={s.id}>
                    <td><Link href={`/samples/${s.id}`}>{s.label || `#${s.id}`}</Link></td>
                    <td><Hash value={s.sha256} short /></td>
                    <td><Badge status={s.mode} /></td>
                    <td className="mono">{s.approval_id ?? "—"}</td>
                    <td>{s.source}</td>
                    <td>{s.retrieved}</td>
                    <td className="num">{s.artifact_count}</td>
                    <td>{s.last_job_id ? <Link href={`/analyses/${s.last_job_id}`}><Badge status={s.last_job_status ?? "queued"} /></Link> : <span className="sub">none</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
