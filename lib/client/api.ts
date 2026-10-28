"use client";
import type { ModuleId } from "../modules-config.ts";

export interface ScanMeta {
  module: ModuleId;
  target: string;
  kind: string;
  durationMs: number;
  scannedAt: string;
}

export type ScanResponse<T> = { ok: true; data: T; meta: ScanMeta } | { ok: false; error: string };

const CACHE_TTL = 10 * 60 * 1000;
const memory = new Map<string, { at: number; value: ScanResponse<unknown> }>();

function cacheKey(module: string, target: string, options: unknown) {
  return `expulso:${module}:${target.trim().toLowerCase()}:${JSON.stringify(options ?? {})}`;
}

function readCache<T>(key: string): ScanResponse<T> | null {
  const m = memory.get(key);
  if (m && Date.now() - m.at < CACHE_TTL) return m.value as ScanResponse<T>;
  try {
    const raw = sessionStorage.getItem(key);
    if (!raw) return null;
    const v = JSON.parse(raw) as { at: number; value: ScanResponse<T> };
    if (Date.now() - v.at < CACHE_TTL) return v.value;
  } catch {
    /* depolama yok */
  }
  return null;
}

function writeCache(key: string, value: ScanResponse<unknown>) {
  const entry = { at: Date.now(), value };
  memory.set(key, entry);
  try {
    sessionStorage.setItem(key, JSON.stringify(entry));
  } catch {
    /* kota dolu veya depolama yok */
  }
}

export async function runScan<T>(module: ModuleId, target: string, options?: unknown, force = false): Promise<ScanResponse<T>> {
  const key = cacheKey(module, target, options);
  if (!force) {
    const c = readCache<T>(key);
    if (c) return c;
  }
  try {
    const res = await fetch(`/api/scan/${module}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target, options }),
    });
    let json: ScanResponse<T>;
    try {
      json = await res.json();
    } catch {
      json = { ok: false, error: res.status === 504 ? "İşlem zaman aşımına uğradı. Daha küçük bir kapsamla tekrar deneyin." : `Sunucu hatası (HTTP ${res.status}).` };
    }
    if (json.ok) writeCache(key, json);
    return json;
  } catch {
    return { ok: false, error: "Sunucuya ulaşılamadı. İnternet bağlantınızı kontrol edin." };
  }
}

/* ------------------------------ Son aramalar ------------------------------ */

const HISTORY_KEY = "expulso:history";
export interface HistoryItem {
  target: string;
  module: ModuleId | "overview";
  at: number;
}

export function getHistory(): HistoryItem[] {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]") as HistoryItem[];
  } catch {
    return [];
  }
}

export function pushHistory(item: Omit<HistoryItem, "at">) {
  try {
    const list = getHistory().filter((h) => !(h.target === item.target && h.module === item.module));
    list.unshift({ ...item, at: Date.now() });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, 30)));
  } catch {
    /* depolama yok */
  }
}

export function clearHistory() {
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch {
    /* depolama yok */
  }
}
