// Shapes of saved and running scans. Shared by the API, the scan store and the UI.
import type { ModuleId, ScanMode } from "./modules-config.ts";
import type { Finding, SourceStatus } from "./types.ts";

export type ModuleEntry =
  | {
      id: ModuleId;
      title: string;
      tier: string;
      ok: true;
      summary: string;
      findings: Finding[];
      data: unknown;
      warnings: string[];
      sources: SourceStatus[];
      durationMs: number;
    }
  | { id: ModuleId; title: string; tier: string; ok: false; error?: string; code?: string; durationMs: number };

/** Modules run against one live subdomain found by the root scan (the "chain" step). */
export interface ChildScan {
  host: string;
  ips: string[];
  modules: ModuleEntry[];
}

export interface ScanCounts {
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanSummary {
  id: string;
  target: string;
  kind: string;
  mode: ScanMode;
  status: "running" | "done" | "failed";
  startedAt: string;
  finishedAt?: string;
  stage: string;
  done: number;
  total: number;
  counts?: ScanCounts;
  modulesRun?: number;
  modulesOk?: number;
  hosts?: number;
  scope?: string[];
  error?: string;
}

export interface ScanRecord extends ScanSummary {
  requestId: string;
  chainLimit: number;
  options?: Record<string, Record<string, unknown>>;
  modules: ModuleEntry[];
  children: ChildScan[];
  findings: (Finding & { module: string })[];
  warnings: string[];
}
