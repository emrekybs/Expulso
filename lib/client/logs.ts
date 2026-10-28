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

function read(): LogEntry[] {
  try {
    return JSON.parse(sessionStorage.getItem(KEY) || "[]") as LogEntry[];
  } catch {
    return [];
  }
}
function write(list: LogEntry[]) {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(list.slice(0, MAX)));
  } catch {
    /* ignore */
  }
  listeners.forEach((l) => l());
}

export function addLog(e: Omit<LogEntry, "id" | "at">) {
  if (typeof window === "undefined") return;
  const list = read();
  list.unshift({ ...e, id: Math.random().toString(36).slice(2), at: Date.now() });
  write(list);
}

export function getLogs(): LogEntry[] {
  if (typeof window === "undefined") return [];
  return read();
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
