"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { API_BASE, fmtBytes, get, post, type AppSettings, type Job, type SampleDetail } from "@/lib/api";
import { Badge, ErrorText, Hash, Loading, useData } from "@/components/ui";
import { Uploader, type UploadKind } from "@/components/Uploader";
import { DemoKit } from "@/components/DemoKit";

const SLOTS: { kind: string; stage: string; accept: UploadKind; title: string }[] = [
  { kind: "A", stage: "A", accept: "json", title: "Stage A · capa JSON (packed file)" },
  { kind: "B_recovery", stage: "B", accept: "json", title: "Stage B gate · recovery record (V1–V5)" },
  { kind: "B", stage: "B", accept: "json", title: "Stage B · capa JSON (recovered payload)" },
  { kind: "payload_pe", stage: "B", accept: "pe", title: "Stage B · recovered payload PE (for capa)" },
  { kind: "cape_report", stage: "C", accept: "json", title: "Stage C · genuine CAPE report" },
  { kind: "C", stage: "C", accept: "json", title: "Stage C · capa dynamic JSON" },
  { kind: "S", stage: "S", accept: "json", title: "S · sandbox ATT&CK labels" },
  { kind: "evidence", stage: "RQ3", accept: "json", title: "Evidence file (residual classes, gains)" },
];

export default function SampleDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const d = useData(() => get<SampleDetail>(`/api/samples/${id}`), [id]);
  const st = useData(() => get<AppSettings>("/api/settings"), []);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function start() {
    setErr(null);
    setBusy(true);
    try {
      const job = await post<Job>(`/api/samples/${id}/jobs`);
      router.push(`/analyses/${job.id}`);
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  }

  if (!d.data || !st.data) return <Loading error={d.error ?? st.error} what="sample" />;
  const { sample, artifacts, jobs, readiness } = d.data;
  const limits = st.data.limits_mb;
  const current = artifacts.filter((a) => !a.superseded);
  const slots = SLOTS.filter((s) => s.kind !== "payload_pe" || (sample.mode === "empirical" && st.data!.safety.allow_sample_upload));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{sample.label || `Sample #${sample.id}`} <Badge status={sample.mode} /></h1>
          <p className="sub mono">{sample.sha256}</p>
        </div>
        <button className="btn primary" onClick={start} disabled={busy}>{busy ? "Queuing…" : "Run analysis"}</button>
      </div>
      <ErrorText error={err} />
      {sample.mode === "synthetic" && (
        <div className="banner">
          SYNTHETIC {sample.demo_scenario ? "demo " : ""}sample: the hash and all evidence are fictional and accepted only for
          demonstration. Results are not about any real file.
        </div>
      )}
      {sample.demo_scenario && <DemoKit sampleId={sample.id} onChange={() => void d.reload()} />}

      <div className="grid g2">
        <div className="card">
          <h2>Provenance</h2>
          <dl className="kv">
            <dt>SHA-256</dt><dd className="mono">{sample.sha256}</dd>
            <dt>Approval reference</dt><dd className="mono">{sample.approval_id ?? "not required (synthetic)"}</dd>
            <dt>Source</dt><dd>{sample.source}</dd>
            <dt>Retrieved</dt><dd>{sample.retrieved}</dd>
            <dt>Packer label</dt><dd>{sample.packer_label || "—"}</dd>
            <dt>Registered</dt><dd>{sample.created_utc}</dd>
            <dt>Binary stored</dt><dd>{sample.file_stored ? `yes, quarantined (${fmtBytes(sample.file_size)})` : "no (evidence-only workflow)"}</dd>
            {sample.note && (<><dt>Note</dt><dd>{sample.note}</dd></>)}
          </dl>
          {sample.pe_meta && (
            <>
              <h3 style={{ marginTop: 14 }}>PE header</h3>
              <dl className="kv">
                <dt>Format / machine</dt><dd>{sample.pe_meta.format} · {sample.pe_meta.machine}{sample.pe_meta.is_dll ? " · DLL" : ""}</dd>
                <dt>Sections</dt><dd className="mono">{sample.pe_meta.sections.map((s) => s.name).join("  ")}</dd>
                <dt>Entry point RVA</dt><dd className="mono">0x{(sample.pe_meta.entry_point_rva ?? 0).toString(16)}</dd>
                <dt>.NET</dt><dd>{sample.pe_meta.is_dotnet ? "yes (out of scope: native PE only)" : "no"}</dd>
              </dl>
            </>
          )}
        </div>
        <div className="card">
          <h2>Stage readiness</h2>
          <table>
            <tbody>
              {(["A", "B", "C", "S"] as const).map((k) => (
                <tr key={k}><td style={{ width: 40 }}><span className="stage-key">{k}</span></td><td>{readiness[k]}</td></tr>
              ))}
            </tbody>
          </table>
          <p className="hint">
            Recovery (unpacking) and sandbox execution happen in separate, controlled processes. VisibilityLab only imports
            their outputs. Missing stages are reported as “awaiting input”; their measures are n/d.
          </p>
        </div>
      </div>

      <div className="card">
        <h2>Attach evidence</h2>
        <div className="grid g4">
          {slots.map((s) => (
            <Uploader
              key={s.kind}
              title={s.title}
              accept={s.accept}
              maxMb={s.kind === "cape_report" ? limits.cape_report : s.accept === "pe" ? limits.pe : limits.json}
              path={`/api/samples/${sample.id}/artifacts`}
              fields={{ kind: s.kind }}
              onDone={() => void d.reload()}
            />
          ))}
          <Uploader
            title="Analysis bundle (.zip)"
            hint="Flat zip with any of A.json, B_recovery.json, B.json, C.json, S.json, evidence.json, cape_report.json"
            accept="zip"
            maxMb={limits.bundle}
            path={`/api/samples/${sample.id}/bundle`}
            onDone={() => void d.reload()}
          />
        </div>
      </div>

      <div className="card">
        <h2>Evidence files</h2>
        {artifacts.length === 0 ? (
          <p className="empty">Nothing attached yet.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>#</th><th>Kind</th><th>Origin</th><th>SHA-256</th><th>Size</th><th>Original name</th><th>Tool</th><th>State</th><th></th></tr></thead>
              <tbody>
                {artifacts.map((a) => (
                  <tr key={a.id} style={a.superseded ? { opacity: 0.5 } : undefined}>
                    <td>{a.id}</td>
                    <td className="mono">{a.kind}</td>
                    <td>{a.origin}{a.derived_from ? ` (from #${a.derived_from})` : ""}</td>
                    <td><Hash value={a.sha256} short /></td>
                    <td className="num">{fmtBytes(a.size)}</td>
                    <td>{a.original_name}</td>
                    <td>{a.tool_name ? `${a.tool_name} ${a.tool_version}` : "—"}</td>
                    <td>{a.superseded ? "superseded" : current.includes(a) ? "current" : ""}</td>
                    <td>{a.kind.endsWith("_pe") ? <span className="sub">quarantined</span> : <a href={`${API_BASE}/api/artifacts/${a.id}/download`}>JSON</a>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2>Analyses</h2>
        {jobs.length === 0 ? (
          <p className="empty">No analysis has been run for this sample.</p>
        ) : (
          <table>
            <thead><tr><th>Job</th><th>Status</th><th>Message</th><th>Created</th><th>Manifest</th></tr></thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.id}>
                  <td><Link href={`/analyses/${j.id}`}>#{j.id}</Link></td>
                  <td><Badge status={j.status} /></td>
                  <td>{j.error ?? j.message}</td>
                  <td className="sub">{j.created_utc}</td>
                  <td><Hash value={j.manifest_sha256} short /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
