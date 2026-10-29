// Typed client for the VisibilityLab API (webapp/backend/api.py).

export const API_BASE = (process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:8000").replace(/\/$/, "");

export type Mode = "synthetic" | "empirical";
export type StageKey = "A" | "B" | "C" | "S";
export type StageStatus =
  | "queued" | "running" | "complete" | "failed" | "not_recovered" | "awaiting_input";
export type JobStatus = "queued" | "running" | "complete" | "failed" | "interrupted";
export type Value = number | "n/d";

export interface PeMeta {
  machine: string;
  format: string;
  number_of_sections: number;
  timestamp: number;
  is_dll: boolean;
  is_dotnet: boolean;
  entry_point_rva?: number;
  sections: { name: string; virtual_address: number; virtual_size: number; raw_size: number }[];
  warnings: string[];
}

export interface Sample {
  id: number;
  sha256: string;
  label: string;
  mode: Mode;
  approval_id: string | null;
  source: string;
  retrieved: string;
  packer_label: string;
  note: string;
  file_stored: boolean;
  file_size: number | null;
  pe_meta: PeMeta | null;
  created_utc: string;
  last_job_id?: number | null;
  last_job_status?: JobStatus | null;
  artifact_count?: number | null;
  demo_scenario?: "accepted" | "rejected" | null;
}

export interface DemoScenario { name: "accepted" | "rejected"; description: string }
export interface DemoKit {
  scenario: "accepted" | "rejected";
  description: string;
  items: { kind: string; file_name: string; sha256: string; size: number; attached: boolean }[];
}

export interface Artifact {
  id: number;
  sample_id: number;
  kind: string;
  origin: string;
  sha256: string;
  size: number;
  original_name: string;
  tool_name: string | null;
  tool_version: string | null;
  derived_from: number | null;
  superseded: boolean;
  created_utc: string;
}

export interface JobSummary {
  id: number;
  sample_id: number;
  status: JobStatus;
  progress: number;
  message: string;
  error: string | null;
  created_utc: string;
  finished_utc: string | null;
  manifest_sha256: string | null;
  mapping_version: string | null;
  sha256: string;
  label: string;
  mode: Mode;
}

export interface Job extends Omit<JobSummary, "sha256" | "label" | "mode"> {
  started_utc: string | null;
  mapping_name: string | null;
  mapping_sha256: string | null;
  pipeline_version: string | null;
  python_version: string | null;
  stages: Record<StageKey, { status: StageStatus; notes: string[] }>;
  inputs: { key: string; sha256: string; artifact_id: number; origin: string; tool_name: string | null; tool_version: string | null; original_name: string }[];
  outputs: { name: string; sha256: string }[];
  tools: Record<string, string>;
  events: { ts_utc: string; level: "info" | "warning" | "error"; message: string }[];
}

export interface SampleDetail {
  sample: Sample;
  artifacts: Artifact[];
  jobs: JobSummary[];
  readiness: Record<StageKey, string>;
}

export type MeasureInput = { numerator: number; denominator: number } | { count: number } | { reason: string };

export interface Results {
  notice: string;
  synthetic: boolean;
  label: string;
  sample_sha256: string;
  mode: string;
  approval_id: string | null;
  stages: Record<StageKey, { status: string; notes: string[]; raw_ids?: number; techniques?: number }>;
  recovery_gate: { accepted: boolean; reasons: string[]; payload_sha256?: string | null; checks?: Record<string, boolean> };
  sets: Record<StageKey, string[] | "n/d">;
  measures: Record<string, Value>;
  measure_inputs: Record<string, MeasureInput>;
  secondary: { S_overlap_C: Value; S_inputs: MeasureInput; note: string };
  residual_classification: { status: string; reason: string; techniques: string[] | "n/d"; class_counts: Record<string, number> | "n/d"; pk_summary: string };
  gain_attribution: { status: string; reason: string; techniques: string[] | "n/d"; attribution_counts: Record<string, number> | "n/d" };
  research_questions: Record<string, string[] | "n/d">;
}

export interface AuditRow { stage: string; raw_id: string; normalized_id: string; status: string; rules_applied: string; source_rules: string }
export interface ResidualRow { technique: string; class: string; class_meaning: string; evidence_ref: string; reason: string }
export interface GainRow { technique: string; attribution: string; evidence_ref: string; reason: string }
export interface Audit { normalization_audit: AuditRow[]; residual_classification: ResidualRow[]; gain_attribution: GainRow[] }

export interface EvidenceRef { job_id: number; kind: "residual" | "gain"; technique: string; label: string; evidence_ref: string; reason: string; sha256: string; sample_label: string; mode: Mode }

export interface AppSettings {
  pipeline_version: string;
  data_dir: string;
  bind: string;
  limits_mb: { json: number; cape_report: number; pe: number; bundle: number };
  safety: { allow_sample_upload: boolean; static_analysis_enabled: boolean; isolation_acknowledged: boolean; pe_analysis_allowed: boolean; dynamic_execution: string };
  capa: { configured: boolean; path: string; expected_version: string; status: string };
  mapping: {
    empirical: { path: string; version: string; exists: boolean; provenance: Record<string, unknown> | null };
    synthetic: { path: string; version: string };
  };
  artifact_kinds: Record<string, string>;
  measures: Record<string, string>;
  classes: Record<string, string>;
}

export interface Overview {
  samples: number;
  synthetic_samples: number;
  empirical_samples: number;
  jobs: Record<string, number>;
  recent_jobs: JobSummary[];
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg?: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export async function get<T>(path: string): Promise<T> {
  return handle<T>(await fetch(`${API_BASE}${path}`, { cache: "no-store" }));
}

export async function post<T>(path: string, body?: unknown): Promise<T> {
  return handle<T>(
    await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}

/** multipart upload with progress (XMLHttpRequest exposes upload progress; fetch does not). */
export function uploadWithProgress<T>(path: string, form: FormData, onProgress: (pct: number) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}${path}`);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((e.loaded / e.total) * 100));
    xhr.onerror = () => reject(new ApiError(0, "network error: is the API running on " + API_BASE + "?"));
    xhr.onload = () => {
      let body: { detail?: unknown } = {};
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        /* ignore */
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as T);
      else {
        const d = body.detail;
        const msg = typeof d === "string" ? d : Array.isArray(d) ? d.map((x: { msg?: string }) => x.msg).join("; ") : `${xhr.status}`;
        reject(new ApiError(xhr.status, msg));
      }
    };
    xhr.send(form);
  });
}

export const fileUrl = (jobId: number, name: string) => `${API_BASE}/api/jobs/${jobId}/files/${name}`;

export function fmtValue(v: Value | undefined, ratio = false): string {
  if (v === undefined) return "—";
  if (v === "n/d") return "n/d";
  if (ratio) return v.toFixed(4).replace(/0+$/, "").replace(/\.$/, ".0");
  return Number.isInteger(v) ? String(v) : v.toFixed(4).replace(/0+$/, "").replace(/\.$/, "");
}

export function fmtCounts(inp: MeasureInput | undefined): string {
  if (!inp) return "";
  if ("numerator" in inp) return `${inp.numerator} / ${inp.denominator}`;
  if ("count" in inp) return String(inp.count);
  return inp.reason;
}

export const fmtBytes = (n: number | null | undefined) =>
  n == null ? "—" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
