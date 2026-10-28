"use client";

export type LogLevel = "ok" | "error" | "warn";
export interface LogEntry {
  id: string;
  at: number;
  level: LogLevel;
  module: string;
  target: string;
  message: string;
  detail?: string;
  requestId?: string;
  durationMs?: number;
}

const KEY = "recon:logs";
const MAX = 500;
const listeners = new Set<() => void>();

// useSyncExternalStore requires getSnapshot to return the SAME reference until the store
// changes. Parsing storage on every call produced a new array each time and caused an
// infinite update loop. We keep one cached snapshot and replace it only on write.
const EMPTY: LogEntry[] = [];
let snapshot: LogEntry[] | null = null;

function load(): LogEntry[] {
  if (snapshot) return snapshot;
  try {
    snapshot = JSON.parse(sessionStorage.getItem(KEY) || "[]") as LogEntry[];
  } catch {
    snapshot = [];
  }
  return snapshot;
}

function write(list: LogEntry[]) {
  snapshot = list.slice(0, MAX);
  try {
    sessionStorage.setItem(KEY, JSON.stringify(snapshot));
  } catch {
    /* storage unavailable: keep in memory only */
  }
  listeners.forEach((l) => l());
}

export function addLog(e: Omit<LogEntry, "id" | "at">) {
  if (typeof window === "undefined") return;
  write([{ ...e, id: Math.random().toString(36).slice(2), at: Date.now() }, ...load()]);
}

/** Stable snapshot for useSyncExternalStore (same reference unless logs changed). */
export function getLogs(): LogEntry[] {
  if (typeof window === "undefined") return EMPTY;
  return load();
}

export function getServerLogs(): LogEntry[] {
  return EMPTY;
}

export function clearLogs() {
  write([]);
}

export function subscribeLogs(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

let installed = false;
/** Capture uncaught errors and rejected promises into the log once. */
export function installGlobalErrorCapture() {
  if (installed || typeof window === "undefined") return;
  installed = true;
  window.addEventListener("error", (ev) => addLog({ level: "error", module: "window", target: "-", message: ev.message || "Uncaught error", detail: ev.error?.stack?.slice(0, 500) }));
  window.addEventListener("unhandledrejection", (ev) => addLog({ level: "error", module: "window", target: "-", message: "Unhandled promise rejection", detail: String(ev.reason).slice(0, 500) }));
}
