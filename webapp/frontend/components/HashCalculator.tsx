"use client";

import { useState } from "react";

/** Computes a file's SHA-256 in the browser with Web Crypto. The file is never uploaded. */
export function HashCalculator({ onHash }: { onHash?: (sha: string, name: string) => void }) {
  const [result, setResult] = useState<{ name: string; sha: string; size: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function hash(file: File) {
    setError(null);
    setResult(null);
    if (!globalThis.crypto?.subtle) {
      setError("Web Crypto is unavailable here (open the app via http://127.0.0.1 or localhost). Use Get-FileHash instead.");
      return;
    }
    if (file.size > 512 * 1024 * 1024) {
      setError("file is larger than 512 MB; use Get-FileHash instead");
      return;
    }
    setBusy(true);
    try {
      const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
      const sha = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
      setResult({ name: file.name, sha, size: file.size });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <label htmlFor="hashfile">Calculate a SHA-256 locally (the file stays in your browser, nothing is uploaded)</label>
      <input id="hashfile" type="file" onChange={(e) => { const f = e.target.files?.[0]; if (f) void hash(f); e.target.value = ""; }} />
      {busy && <p className="hint">Hashing…</p>}
      {error && <p className="err">{error}</p>}
      {result && (
        <div style={{ marginTop: 8 }}>
          <div className="hint">{result.name} · {result.size.toLocaleString()} bytes</div>
          <div className="mono" style={{ overflowWrap: "anywhere" }}>{result.sha}</div>
          {onHash && <button type="button" className="btn sm" style={{ marginTop: 6 }} onClick={() => onHash(result.sha, result.name)}>Use this SHA-256</button>}
        </div>
      )}
    </div>
  );
}
