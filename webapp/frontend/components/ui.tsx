"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, fmtCounts, fmtValue, type MeasureInput, type Value } from "@/lib/api";

const LABELS: Record<string, string> = {
  queued: "queued",
  running: "running",
  complete: "complete",
  failed: "failed",
  not_recovered: "not recovered",
  awaiting_input: "awaiting input",
  interrupted: "interrupted",
  synthetic: "synthetic",
  empirical: "empirical",
};

export function Badge({ status }: { status: string }) {
  return <span className={`badge b-${status}`}>{LABELS[status] ?? status}</span>;
}

export function Hash({ value, short = false }: { value: string | null | undefined; short?: boolean }) {
  if (!value) return <span className="sub">—</span>;
  return (
    <span className="mono" title={value}>
      {short ? `${value.slice(0, 12)}…` : value}
    </span>
  );
}

export function SyntheticBanner({ synthetic }: { synthetic: boolean }) {
  return synthetic ? (
    <div className="banner">
      SYNTHETIC DEMONSTRATION DATA: fictional fixtures. These numbers are not results about any real sample.
    </div>
  ) : (
    <div className="banner info">
      Empirical run on approved inputs. Results describe this sample only; Stage C is a tool-generated reference, not ground truth.
    </div>
  );
}

export function V({ v, ratio = false }: { v: Value | undefined; ratio?: boolean }) {
  return v === "n/d" ? <span className="nd" title="not defined: a required stage is unavailable or a denominator is empty">n/d</span> : <>{fmtValue(v, ratio)}</>;
}

export function Counts({ inp }: { inp: MeasureInput | undefined }) {
  if (inp && "reason" in inp) return <span className="nd">{inp.reason}</span>;
  return <span className="mono">{fmtCounts(inp)}</span>;
}

export function ErrorText({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error);
  return <p className="err">{msg}</p>;
}

/** Fetch on mount, with optional polling while `poll` returns true. */
export function useData<T>(loader: () => Promise<T>, deps: unknown[], poll?: (d: T) => boolean, intervalMs = 1500) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const reload = useCallback(async () => {
    try {
      setData(await loaderRef.current());
      setError(null);
    } catch (e) {
      setError(e);
    }
  }, []);
  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    if (!data || !poll || !poll(data)) return;
    const t = setTimeout(reload, intervalMs);
    return () => clearTimeout(t);
  }, [data, poll, reload, intervalMs]);
  return { data, error, reload };
}

export function Loading({ error, what }: { error: unknown; what: string }) {
  return error ? <ErrorText error={error} /> : <p className="sub">Loading {what}…</p>;
}
