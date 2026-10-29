"use client";

import { useState } from "react";
import { API_BASE, get, post, type DemoKit as Kit } from "@/lib/api";
import { ErrorText, Hash, Loading, useData } from "./ui";

const WHAT: Record<string, { label: string; real: string }> = {
  A: { label: "Stage A · capa JSON (packed file)", real: "capa -j on the packed file" },
  B_recovery: { label: "Recovery record (gate for B)", real: "your validated recovery tool (V1–V5)" },
  B: { label: "Stage B · capa JSON (payload)", real: "capa -j on the validated payload" },
  C: { label: "Stage C · capa dynamic JSON", real: "capa -f cape on a CAPE report (sandbox run)" },
  S: { label: "S · sandbox labels", real: "the CAPE report's own ATT&CK labels" },
  evidence: { label: "Evidence file", real: "the analyst, with references to recorded inputs" },
};

/** Synthetic evidence for a demo sample: attach items one by one, all at once, or download and drag them in. */
export function DemoKit({ sampleId, onChange }: { sampleId: number; onChange: () => void }) {
  const kit = useData(() => get<Kit>(`/api/samples/${sampleId}/demo-kit`), [sampleId]);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function attach(kind?: string) {
    setErr(null);
    setBusy(kind ?? "all");
    try {
      await post(`/api/samples/${sampleId}/demo-kit${kind ? `/${kind}` : ""}`);
      await kit.reload();
      onChange();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  }

  if (!kit.data) return <Loading error={kit.error} what="demo kit" />;
  return (
    <div className="card" style={{ borderColor: "#6b5222" }}>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <h2 style={{ margin: 0 }}>Demo evidence kit (synthetic)</h2>
        <button className="btn" disabled={busy !== null || kit.data.items.every((i) => i.attached)} onClick={() => attach()}>
          {busy === "all" ? "Attaching…" : "Attach all"}
        </button>
      </div>
      <p className="sub" style={{ marginBottom: 10 }}>
        Scenario <b>{kit.data.scenario}</b>: {kit.data.description} Every file is fictional and marked
        <code> &quot;synthetic&quot;: true</code>, so it can never be attached to an empirical sample. Try attaching only some
        items to see stages <i>awaiting input</i>, or download a file and drop it on the matching upload box.
      </p>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Item</th><th>In a real study this comes from</th><th>SHA-256</th><th>State</th><th></th></tr></thead>
          <tbody>
            {kit.data.items.map((i) => (
              <tr key={i.kind}>
                <td><b>{WHAT[i.kind]?.label ?? i.kind}</b><div className="hint mono">{i.file_name}</div></td>
                <td className="sub">{WHAT[i.kind]?.real}</td>
                <td><Hash value={i.sha256} short /></td>
                <td>{i.attached ? <span className="badge b-complete">attached</span> : <span className="badge b-queued">not attached</span>}</td>
                <td>
                  <div className="row">
                    <button className="btn sm" disabled={i.attached || busy !== null} onClick={() => attach(i.kind)}>
                      {busy === i.kind ? "…" : "Attach"}
                    </button>
                    <a className="btn sm" href={`${API_BASE}/api/samples/${sampleId}/demo-kit/${i.kind}/download`}>Download</a>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ErrorText error={err} />
    </div>
  );
}
