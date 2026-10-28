"use client";
import { useState } from "react";
import type { ModuleDef } from "@/lib/modules-config";
import { parseTarget, splitTargets, KIND_LABEL } from "@/lib/target";
import type { ScanResponse } from "@/lib/types";
import { runScan } from "@/lib/client/api";
import { renderModule } from "./renderers";
import { Card, Findings, Alert, Badge } from "./ui";
import { Icon } from "./icons";

type Mode = "single" | "bulk";
interface BulkRow {
  target: string;
  state: "queued" | "running" | "done" | "failed";
  res?: ScanResponse;
}

export default function ModuleRunner({ def }: { def: ModuleDef }) {
  const [mode, setMode] = useState<Mode>("single");
  const [single, setSingle] = useState("");
  const [bulk, setBulk] = useState("");
  const [options, setOptions] = useState<Record<string, unknown>>(() => Object.fromEntries((def.options ?? []).map((o) => [o.key, o.default])));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [bulkRows, setBulkRows] = useState<BulkRow[]>([]);
  const [activeBulk, setActiveBulk] = useState(0);

  function setOpt(key: string, value: unknown) {
    setOptions((o) => ({ ...o, [key]: value }));
  }

  async function runSingle(targetRaw: string) {
    const parsed = parseTarget(targetRaw);
    if ("error" in parsed) {
      setError(parsed.error);
      return;
    }
    if (!def.accepts.includes(parsed.kind)) {
      setError(`${def.title} does not accept a ${KIND_LABEL[parsed.kind]} target. Accepts: ${def.accepts.map((k) => KIND_LABEL[k]).join(", ")}.`);
      return;
    }
    setError("");
    setBusy(true);
    setResult(null);
    const res = await runScan(def.id, targetRaw, options, true);
    setResult(res);
    setBusy(false);
  }

  async function runBulk() {
    const targets = splitTargets(bulk).slice(0, def.bulkLimit);
    if (!targets.length) {
      setError("Enter at least one target.");
      return;
    }
    setError("");
    setBusy(true);
    setResult(null);
    const rows: BulkRow[] = targets.map((t) => ({ target: t, state: "queued" }));
    setBulkRows([...rows]);
    for (let i = 0; i < rows.length; i++) {
      rows[i].state = "running";
      setBulkRows([...rows]);
      rows[i].res = await runScan(def.id, rows[i].target, options, true);
      rows[i].state = rows[i].res!.ok ? "done" : "failed";
      setBulkRows([...rows]);
    }
    setActiveBulk(rows.findIndex((r) => r.res?.ok) === -1 ? 0 : rows.findIndex((r) => r.res?.ok));
    setBusy(false);
  }

  const activeRow = bulkRows[activeBulk];

  return (
    <div className="stack">
      <section className="card search-card">
        <div className="seg" style={{ marginBottom: 12 }}>
          <button type="button" className={mode === "single" ? "on" : ""} onClick={() => setMode("single")}>Single</button>
          <button type="button" className={mode === "bulk" ? "on" : ""} onClick={() => setMode("bulk")}>Bulk list</button>
        </div>

        {mode === "single" ? (
          <form className="search-row" onSubmit={(e) => (e.preventDefault(), runSingle(single))}>
            <div className="search-input">
              <span className="si-icon">{Icon.search({ size: 18 })}</span>
              <input value={single} onChange={(e) => setSingle(e.target.value)} placeholder={placeholder(def)} aria-label="Target" autoFocus />
            </div>
            <button type="submit" className="btn-primary btn-run" disabled={busy}>
              {busy ? "Running…" : "Run"}
            </button>
          </form>
        ) : (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "flex-start" }}>
            <label className="field" style={{ flex: "1 1 380px" }}>
              One target per line (max {def.bulkLimit})
              <textarea className="bulk" value={bulk} onChange={(e) => setBulk(e.target.value)} rows={5} placeholder={`${placeholder(def)}\n…`} />
            </label>
            <button type="button" className="btn-primary" style={{ marginTop: 24 }} disabled={busy} onClick={runBulk}>
              {busy ? "Running…" : `Run ${splitTargets(bulk).length || ""} targets`}
            </button>
          </div>
        )}

        {def.options && def.options.length > 0 && (
          <div className="options">
            {def.options.map((o) => (
              <div key={o.key}>
                {o.type === "boolean" ? (
                  <label className="toggle">
                    <input type="checkbox" checked={!!options[o.key]} onChange={(e) => setOpt(o.key, e.target.checked)} />
                    <span className="track" />
                    {o.label}
                  </label>
                ) : o.type === "select" ? (
                  <label className="field">
                    {o.label}
                    <select value={String(options[o.key])} onChange={(e) => setOpt(o.key, e.target.value)} style={{ height: 36, padding: "0 10px", borderRadius: 8, border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)" }}>
                      {o.choices?.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                    </select>
                  </label>
                ) : (
                  <label className="field">
                    {o.label}
                    <input type={o.type === "number" ? "number" : "text"} value={String(options[o.key])} min={o.min} max={o.max} onChange={(e) => setOpt(o.key, o.type === "number" ? Number(e.target.value) : e.target.value)} style={{ width: o.type === "number" ? 110 : 240 }} />
                    {o.help && <small>{o.help}</small>}
                  </label>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {def.tier === "active" && <Alert kind="warn" title="Active module">This module sends requests to the target. Only run it against systems you are authorized to test.</Alert>}
      {error && <Alert kind="bad">{error}</Alert>}

      {busy && mode === "single" && (
        <div className="card loading-card">
          {Icon.search({ size: 20 })}
          <div style={{ flex: 1 }}>
            <div>Running {def.title}…</div>
            <div className="progress"><div /></div>
          </div>
        </div>
      )}

      {/* Bulk target chips */}
      {bulkRows.length > 0 && (
        <div className="result-bar">
          <span className="muted small">Targets:</span>
          {bulkRows.map((r, i) => (
            <button key={r.target} type="button" className={`target-pill ${r.state === "done" ? "done" : r.state === "failed" ? "failed" : ""} ${i === activeBulk ? "active" : ""}`} onClick={() => setActiveBulk(i)}>
              <span className="st" style={{ background: r.state === "done" ? "var(--ok)" : r.state === "failed" ? "var(--bad)" : r.state === "running" ? "var(--warn)" : "var(--muted)" }} />
              {r.target}
            </button>
          ))}
        </div>
      )}

      {/* Result (single or selected bulk row) */}
      {(() => {
        const res = mode === "bulk" ? activeRow?.res : result;
        if (!res) return null;
        if (!res.ok)
          return (
            <Alert kind={res.skipped ? "info" : "bad"} title={res.skipped ? "Skipped" : "Error"}>
              {res.error} <span className="muted small">(request {res.requestId})</span>
            </Alert>
          );
        return (
          <>
            <div className="result-bar">
              <span className="rb-title">
                <Badge kind="ok">done</Badge> {res.result.summary}
              </span>
              <span className="rb-meta">{res.meta.target} · {Math.round(res.meta.durationMs / 100) / 10}s · req {res.meta.requestId}</span>
            </div>
            {res.result.warnings && res.result.warnings.length > 0 && <Alert kind="warn" title="Notes">{res.result.warnings.join(" ")}</Alert>}
            {res.result.findings.length > 0 && <Findings items={res.result.findings} />}
            {res.result.sources && res.result.sources.length > 0 && (
              <Card title="Sources" count={`${res.result.sources.filter((s) => s.ok).length}/${res.result.sources.length}`} pad={false}>
                <div className="card-body" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8 }}>
                  {res.result.sources.map((s) => (
                    <div key={s.name} className="target-pill" style={{ justifyContent: "flex-start" }}>
                      <span className="st" style={{ background: s.ok ? "var(--ok)" : "var(--bad)" }} />
                      <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{s.name}</span>
                      <span className="muted small">{s.ok ? s.count : s.error ? "err" : 0}</span>
                    </div>
                  ))}
                </div>
              </Card>
            )}
            {renderModule(def.id, res.result)}
          </>
        );
      })()}
    </div>
  );
}

function placeholder(def: ModuleDef): string {
  if (def.accepts.includes("domain") && def.accepts.includes("ip")) return "example.com or 8.8.8.8";
  if (def.id === "osint" || def.id === "js" || def.id === "dirs" || def.id === "exposure" || def.id === "http" || def.id === "waf") return "https://example.com";
  return "example.com";
}
