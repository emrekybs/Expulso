"use client";
import type { ModuleId } from "../modules-config.ts";
import type { ScanResponse } from "../types.ts";
import type { ChildScan, ModuleEntry, ScanCounts, ScanRecord, ScanSummary } from "../scan-types.ts";
import type { Finding } from "../types.ts";
import type { ScanMode } from "../modules-config.ts";
import { addLog } from "./logs.ts";

const CACHE_TTL = 10 * 60 * 1000;
const memory = new Map<string, { at: number; value: ScanResponse }>();

function key(module: string, target: string, options: unknown) {
  return `recon:${module}:${target.trim().toLowerCase()}:${JSON.stringify(options ?? {})}`;
}

function readCache(k: string): ScanResponse | null {
  const m = memory.get(k);
  if (m && Date.now() - m.at < CACHE_TTL) return m.value;
  try {
    const raw = sessionStorage.getItem(k);
    if (!raw) return null;
    const v = JSON.parse(raw) as { at: number; value: ScanResponse };
    if (Date.now() - v.at < CACHE_TTL) return v.value;
  } catch {
    /* ignore */
  }
  return null;
}
function writeCache(k: string, value: ScanResponse) {
  memory.set(k, { at: Date.now(), value });
  try {
    sessionStorage.setItem(k, JSON.stringify({ at: Date.now(), value }));
  } catch {
    /* ignore */
  }
}

export async function runScan<T = unknown>(module: ModuleId, target: string, options?: unknown, force = false): Promise<ScanResponse<T>> {
  const k = key(module, target, options);
  if (!force) {
    const c = readCache(k);
    if (c) return c as ScanResponse<T>;
  }
  const t0 = Date.now();
  let json: ScanResponse<T>;
  try {
    const res = await fetch(`/api/scan/${module}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target, options }) });
    try {
      json = (await res.json()) as ScanResponse<T>;
    } catch {
      json = { ok: false, error: res.status === 504 ? "The request timed out. Try a smaller scope." : `Server error (HTTP ${res.status}).`, code: "http_error", requestId: "-" };
    }
  } catch {
    json = { ok: false, error: "Could not reach the server. Check your connection.", code: "network", requestId: "-" };
  }
  if (json.ok) {
    writeCache(k, json);
    addLog({ level: "ok", module, target, message: json.result.summary, requestId: json.meta.requestId, durationMs: json.meta.durationMs });
    (json.result.warnings ?? []).forEach((w) => addLog({ level: "warn", module, target, message: w, requestId: json.ok ? json.meta.requestId : undefined }));
  } else if (!json.skipped) {
    addLog({ level: "error", module, target, message: json.error, detail: `code: ${json.code}`, requestId: json.requestId, durationMs: Date.now() - t0 });
  }
  return json;
}

/* ------------------------------ Scans ------------------------------ */

export type FullScanModule = ModuleEntry;

export interface FullScanResponse {
  ok: boolean;
  error?: string;
  id?: string;
  meta?: { target: string; kind: string; mode: string; scannedAt: string; requestId: string; moduleCount: number };
  findings?: (Finding & { module: string })[];
  counts?: ScanCounts;
  modules?: FullScanModule[];
  children?: ChildScan[];
}

export function toFullScanResponse(r: ScanRecord): FullScanResponse {
  return {
    ok: r.status === "done",
    error: r.status === "failed" ? r.error : undefined,
    id: r.id,
    meta: { target: r.target, kind: r.kind, mode: r.mode, scannedAt: r.startedAt, requestId: r.requestId, moduleCount: r.modulesRun ?? r.modules.length },
    findings: r.findings,
    counts: r.counts,
    modules: r.modules,
    children: r.children,
  };
}

export async function startScan(req: { target: string; mode: ScanMode; options?: Record<string, Record<string, unknown>>; scope?: string[]; chainLimit?: number }): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  try {
    const res = await fetch("/api/scans", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(req) });
    const json = (await res.json()) as { ok: boolean; id?: string; error?: string };
    if (json.ok && json.id) return { ok: true, id: json.id };
    addLog({ level: "error", module: "full-scan", target: req.target, message: json.error || "Scan could not start." });
    return { ok: false, error: json.error || "Scan could not start." };
  } catch {
    addLog({ level: "error", module: "full-scan", target: req.target, message: "Could not reach the server." });
    return { ok: false, error: "Could not reach the server." };
  }
}

export async function getScan(id: string): Promise<ScanRecord | null> {
  try {
    const res = await fetch(`/api/scans/${encodeURIComponent(id)}`, { cache: "no-store" });
    const json = (await res.json()) as { ok: boolean; scan?: ScanRecord };
    return json.ok && json.scan ? json.scan : null;
  } catch {
    return null;
  }
}

export async function listScans(): Promise<ScanSummary[]> {
  try {
    const res = await fetch("/api/scans", { cache: "no-store" });
    const json = (await res.json()) as { ok: boolean; scans?: ScanSummary[] };
    return json.ok ? json.scans ?? [] : [];
  } catch {
    return [];
  }
}

export async function deleteScan(id: string): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
  const json = (await res.json()) as { ok: boolean; error?: string };
  return json;
}

/** Polls a running scan until it finishes. onTick gets every new snapshot. */
export async function waitForScan(id: string, onTick?: (r: ScanRecord) => void, intervalMs = 1500, isAlive: () => boolean = () => true): Promise<ScanRecord | null> {
  for (;;) {
    if (!isAlive()) return null;
    const r = await getScan(id);
    if (!r) return null;
    onTick?.(r);
    if (r.status !== "running") return r;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** Starts a Full Scan and waits for its result. */
export async function runFullScan(target: string, mode: ScanMode, options?: Record<string, Record<string, unknown>>, scope?: string[]): Promise<FullScanResponse> {
  const started = await startScan({ target, mode, options, scope });
  if (!started.ok) return { ok: false, error: started.error };
  const rec = await waitForScan(started.id);
  if (!rec) return { ok: false, error: "The scan result could not be read." };
  return toFullScanResponse(rec);
}

/** Downloads the HTML report as a PDF rendered by the local Chromium. */
export async function downloadPdf(html: string, filename: string): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch("/api/report/pdf", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ html }) });
  if (!res.ok) {
    const json = (await res.json().catch(() => ({}))) as { error?: string };
    return { ok: false, error: json.error || `PDF failed (HTTP ${res.status}).` };
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return { ok: true };
}
