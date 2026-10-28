// Result shapes shared by the API and the UI.

export type Severity = "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  title: string;
  /** Why it matters, in plain language. */
  detail: string;
  evidence?: string;
  recommendation?: string;
}

export interface SourceStatus {
  name: string;
  ok: boolean;
  count: number;
  error?: string;
  ms?: number;
}

export interface ModuleOutput<T = unknown> {
  /** One-line summary shown in lists and the full-scan overview. */
  summary: string;
  findings: Finding[];
  data: T;
  /** Status of each upstream source, when the module merges several. */
  sources?: SourceStatus[];
  /** Non-fatal problems: partial results, skipped steps, rate limits. */
  warnings?: string[];
}

export interface ScanMeta {
  module: string;
  target: string;
  kind: string;
  durationMs: number;
  scannedAt: string;
  requestId: string;
}

export type ScanResponse<T = unknown> =
  | { ok: true; result: ModuleOutput<T>; meta: ScanMeta }
  | { ok: false; error: string; code: string; requestId: string; skipped?: boolean };

export const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };
