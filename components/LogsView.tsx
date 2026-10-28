"use client";
import { useEffect, useState, useSyncExternalStore } from "react";
import { getLogs, clearLogs, subscribeLogs, type LogEntry, type LogLevel } from "@/lib/client/logs";
import { download, stamp } from "@/lib/client/export";
import { Chips } from "./ui";

export default function LogsView() {
  const logs = useSyncExternalStore(subscribeLogs, getLogs, () => [] as LogEntry[]);
  const [filter, setFilter] = useState<LogLevel | "all">("all");
  const [open, setOpen] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const view = filter === "all" ? logs : logs.filter((l) => l.level === filter);
  const counts = {
    all: logs.length,
    ok: logs.filter((l) => l.level === "ok").length,
    warn: logs.filter((l) => l.level === "warn").length,
    error: logs.filter((l) => l.level === "error").length,
  };

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /><path d="M16 13H8" /><path d="M16 17H8" /></svg>
        </div>
        <div>
          <h1>Logs</h1>
          <p>Every module call in this session, with its status, duration, request id and any error. Uncaught errors in the panel are captured here too. Stored in your browser for this session only.</p>
        </div>
      </div>

      <div className="result-bar">
        <Chips
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All", count: counts.all },
            { value: "ok", label: "OK", count: counts.ok },
            { value: "warn", label: "Warnings", count: counts.warn },
            { value: "error", label: "Errors", count: counts.error },
          ]}
        />
        <div className="rb-actions">
          <button type="button" className="btn btn-sm" onClick={() => download(`recon_logs_${stamp()}.json`, JSON.stringify(logs, null, 2), "application/json")}>
            Export JSON
          </button>
          <button type="button" className="btn btn-sm" onClick={() => confirm("Clear all logs?") && clearLogs()}>
            Clear
          </button>
        </div>
      </div>

      <section className="card" style={{ padding: 0 }}>
        {!mounted ? null : view.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /></svg>
            </div>
            <h4>No logs yet</h4>
            <div className="muted">Run a module and its result or error will appear here.</div>
          </div>
        ) : (
          view.map((l) => (
            <div key={l.id}>
              <div className="log-row" style={{ cursor: l.detail ? "pointer" : "default" }} onClick={() => l.detail && setOpen((o) => (o === l.id ? null : l.id))}>
                <span className={`lvl ${l.level}`}>{l.level.toUpperCase()}</span>
                <time>{new Date(l.at).toLocaleTimeString()}</time>
                <span className="wrap-anywhere">
                  <b className="mono">{l.module}</b> <span className="muted">{l.target !== "-" ? l.target : ""}</span> — {l.message}
                </span>
                <span className="muted small">{l.durationMs != null ? `${Math.round(l.durationMs)}ms` : ""}</span>
                <span className="muted small mono">{l.requestId ?? ""}</span>
              </div>
              {open === l.id && l.detail && <div className="log-detail mono wrap-anywhere">{l.detail}</div>}
            </div>
          ))
        )}
      </section>
    </div>
  );
}
