"use client";

import { Fragment } from "react";
import { get, type AppSettings } from "@/lib/api";
import { Loading, useData } from "@/components/ui";

export default function SettingsPage() {
  const { data, error } = useData(() => get<AppSettings>("/api/settings"), []);
  if (!data) return <Loading error={error} what="settings" />;
  const prov = data.mapping.empirical.provenance as Record<string, string> | null;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="sub">Read-only view of the backend configuration. Change it with environment variables (webapp/.env.example) and restart the API and worker.</p>
        </div>
      </div>

      <div className="grid g2">
        <div className="card">
          <h2>Safety switches</h2>
          <dl className="kv">
            <dt>Bind address</dt><dd className="mono">{data.bind}</dd>
            <dt>Store PE files</dt><dd>{String(data.safety.allow_sample_upload)} <span className="sub">VL_ALLOW_SAMPLE_UPLOAD</span></dd>
            <dt>Static analysis</dt><dd>{String(data.safety.static_analysis_enabled)} <span className="sub">VL_STATIC_ANALYSIS_ENABLED</span></dd>
            <dt>Isolated VM acknowledged</dt><dd>{String(data.safety.isolation_acknowledged)} <span className="sub">VL_ISOLATION_ACK</span></dd>
            <dt>PE analysis allowed</dt><dd><b>{String(data.safety.pe_analysis_allowed)}</b></dd>
            <dt>Dynamic execution</dt><dd>{data.safety.dynamic_execution}</dd>
            <dt>Data directory</dt><dd className="mono">{data.data_dir}</dd>
          </dl>
        </div>
        <div className="card">
          <h2>capa (pinned)</h2>
          <dl className="kv">
            <dt>Configured</dt><dd>{String(data.capa.configured)}</dd>
            <dt>Path</dt><dd className="mono">{data.capa.path || "—"}</dd>
            <dt>Pinned version</dt><dd className="mono">{data.capa.expected_version || "—"}</dd>
            <dt>Status</dt><dd>{data.capa.status}</dd>
          </dl>
          <h3 style={{ marginTop: 14 }}>Upload limits</h3>
          <dl className="kv">
            {Object.entries(data.limits_mb).map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v} MB</dd></Fragment>)}
          </dl>
        </div>
      </div>

      <div className="card">
        <h2>ATT&amp;CK mapping</h2>
        <dl className="kv">
          <dt>Empirical runs</dt><dd>{data.mapping.empirical.version} · <span className="mono">{data.mapping.empirical.path}</span> {data.mapping.empirical.exists ? "" : <b className="err">missing</b>}</dd>
          {prov && (<>
            <dt>Upstream source</dt><dd className="mono">{prov.source_url}</dd>
            <dt>Upstream SHA-256</dt><dd className="mono">{prov.source_sha256}</dd>
            <dt>Table SHA-256</dt><dd className="mono">{prov.csv_sha256}</dd>
            <dt>Rows</dt><dd>{JSON.stringify(prov.rows)}</dd>
          </>)}
          <dt>Synthetic runs</dt><dd>{data.mapping.synthetic.version} · <span className="mono">{data.mapping.synthetic.path}</span></dd>
        </dl>
      </div>

      <div className="grid g2">
        <div className="card">
          <h2>Measures</h2>
          <table><tbody>{Object.entries(data.measures).map(([k, v]) => <tr key={k}><td><b>{k}</b></td><td className="mono">{v}</td></tr>)}</tbody></table>
        </div>
        <div className="card">
          <h2>Residual classes</h2>
          <table><tbody>{Object.entries(data.classes).map(([k, v]) => <tr key={k}><td><b>{k}</b></td><td>{v}</td></tr>)}</tbody></table>
        </div>
      </div>

      <div className="card">
        <h2>Artifact kinds</h2>
        <table><tbody>{Object.entries(data.artifact_kinds).map(([k, v]) => <tr key={k}><td className="mono">{k}</td><td>{v}</td></tr>)}</tbody></table>
      </div>
    </>
  );
}
