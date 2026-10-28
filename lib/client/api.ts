"use client";
import type { ModuleId } from "../modules-config.ts";
import type { ScanResponse } from "../types.ts";
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

export interface FullScanResponse {
  ok: boolean;
  error?: string;
  meta?: { target: string; kind: string; mode: string; scannedAt: string; requestId: string; moduleCount: number };
  findings?: (import("../types.ts").Finding & { module: string })[];
  counts?: { high: number; medium: number; low: number; info: number };
  modules?: FullScanModule[];
}
export type FullScanModule =
  | { id: ModuleId; title: string; tier: string; ok: true; summary: string; findings: import("../types.ts").Finding[]; data: unknown; warnings: string[]; sources: import("../types.ts").SourceStatus[]; durationMs: number }
  | { id: ModuleId; title: string; tier: string; ok: false; error?: string; code?: string; durationMs: number };

export async function runFullScan(target: string, mode: string, options?: Record<string, Record<string, unknown>>): Promise<FullScanResponse> {
  const t0 = Date.now();
  try {
    const res = await fetch("/api/full-scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target, mode, options }) });
    const json = (await res.json()) as FullScanResponse;
    if (json.ok && json.modules) {
      json.modules.forEach((m) =>
        m.ok
          ? addLog({ level: "ok", module: m.id, target, message: m.summary, requestId: json.meta?.requestId, durationMs: m.durationMs })
          : addLog({ level: "error", module: m.id, target, message: m.error || "failed", detail: `code: ${m.code}`, requestId: json.meta?.requestId }),
      );
    } else if (!json.ok) {
      addLog({ level: "error", module: "full-scan", target, message: json.error || "Full scan failed." });
    }
    return json;
  } catch {
    addLog({ level: "error", module: "full-scan", target, message: "Could not reach the server.", durationMs: Date.now() - t0 });
    return { ok: false, error: "Could not reach the server." };
  }
}

/* ------------------------------ History ------------------------------ */
const HKEY = "recon:history";
export interface HistoryItem {
  target: string;
  module: string;
  label: string;
  at: number;
  summary?: string;
}
export function getHistory(): HistoryItem[] {
  try {
    return JSON.parse(localStorage.getItem(HKEY) || "[]") as HistoryItem[];
  } catch {
    return [];
  }
}
export function pushHistory(item: Omit<HistoryItem, "at">) {
  try {
    const list = getHistory().filter((h) => !(h.target === item.target && h.module === item.module));
    list.unshift({ ...item, at: Date.now() });
    localStorage.setItem(HKEY, JSON.stringify(list.slice(0, 40)));
  } catch {
    /* ignore */
  }
}
