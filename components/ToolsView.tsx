"use client";
import { useCallback, useEffect, useState } from "react";
import { Card, Badge, Alert, CopyBtn } from "./ui";

interface ToolStatus {
  name: string;
  status: "ok" | "missing" | "error";
  installed: boolean;
  path: string | null;
  version: string | null;
  error?: string;
  purpose: string;
  install: string;
  usedBy?: string;
  updatable: boolean;
  updateLabel?: string;
  updateNote?: string;
}
interface Status {
  tools: ToolStatus[];
  chromium: { path: string | null; ok: boolean; install: string; updatable: boolean };
}
interface UpdateOutcome {
  ok: boolean;
  output: string;
  error?: string;
  steps: { command: string; ok: boolean }[];
}

const BADGE: Record<ToolStatus["status"], { label: string; kind?: "ok" | "bad" | "warn" }> = {
  ok: { label: "installed", kind: "ok" },
  missing: { label: "not installed" },
  error: { label: "error", kind: "bad" },
};

export default function ToolsView() {
  const [s, setS] = useState<Status | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Record<string, UpdateOutcome>>({});
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/tools", { cache: "no-store" });
      setS((await res.json()) as Status);
      setErr("");
    } catch {
      setErr("Could not read tool status.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function update(name: string) {
    setBusy(name);
    setOpen(name);
    try {
      const res = await fetch("/api/tools/update", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) });
      const json = (await res.json()) as UpdateOutcome;
      setOutcome((o) => ({ ...o, [name]: json }));
    } catch {
      setOutcome((o) => ({ ...o, [name]: { ok: false, output: "", error: "Could not reach the server.", steps: [] } }));
    }
    setBusy(null);
    await load();
  }

  const tools = s?.tools ?? [];
  const installed = tools.filter((t) => t.status === "ok").length;
  const broken = tools.filter((t) => t.status === "error").length;

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" /></svg>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h1>Tools</h1>
          <p>
            Every external tool B24-engine can use. Each one is optional: when it is missing, the built-in engine runs instead. Update buttons run a fixed command, shown below each tool.
          </p>
        </div>
        <button type="button" className="btn btn-sm" onClick={() => void load()}>
          Refresh
        </button>
      </div>

      {err && <Alert kind="bad">{err}</Alert>}
      {s && (
        <div className="chips">
          <Badge kind="ok">{installed} installed</Badge>
          <Badge>{tools.length - installed - broken} not installed</Badge>
          {broken > 0 && <Badge kind="bad">{broken} with errors</Badge>}
        </div>
      )}

      {s && (
        <Card title="External tools" count={`${installed}/${tools.length}`} pad={false}>
          {tools.map((t) => {
            const b = BADGE[t.status];
            const result = outcome[t.name];
            return (
              <div key={t.name} className="list-item" style={{ alignItems: "flex-start", flexWrap: "wrap" }}>
                <Badge kind={b.kind}>{b.label}</Badge>
                <div className="li-main" style={{ minWidth: 0, flex: 1 }}>
                  <div className="value">
                    {t.name}
                    {t.version && <span className="muted small" style={{ marginLeft: 8 }}>{t.version}</span>}
                  </div>
                  <div className="muted small">{t.purpose}{t.usedBy ? ` · used by: ${t.usedBy}` : ""}</div>
                  {t.status === "error" && <div className="small" style={{ color: "var(--bad)", marginTop: 4 }}>{t.error}</div>}
                  {t.status === "missing" && <div className="hl" style={{ marginTop: 6 }}>{t.install}</div>}
                  {t.path && <div className="muted small mono" style={{ marginTop: 4 }}>{t.path}</div>}
                  {t.updateNote && !t.updatable && <div className="muted small" style={{ marginTop: 4 }}>{t.updateNote}</div>}
                  {result && open === t.name && (
                    <div style={{ marginTop: 8 }}>
                      <div className="small" style={{ color: result.ok ? "var(--ok)" : "var(--bad)", marginBottom: 4 }}>
                        {result.ok ? "Update finished." : result.error ?? "Update failed."}
                      </div>
                      {result.steps.map((st) => (
                        <div key={st.command} className="muted small mono wrap-anywhere">
                          {st.ok ? "✓" : "✗"} {st.command}
                        </div>
                      ))}
                      {result.output && <pre className="mono small" style={{ maxHeight: 220, overflow: "auto", whiteSpace: "pre-wrap", marginTop: 6 }}>{result.output}</pre>}
                    </div>
                  )}
                </div>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  {t.updatable && (
                    <button type="button" className="btn btn-sm" disabled={busy !== null || !t.installed} onClick={() => update(t.name)} title={t.updateLabel}>
                      {busy === t.name ? "Updating…" : "Update"}
                    </button>
                  )}
                  {result && (
                    <button type="button" className="btn btn-sm" onClick={() => setOpen(open === t.name ? null : t.name)}>
                      {open === t.name ? "Hide output" : "Output"}
                    </button>
                  )}
                  {!t.installed && <CopyBtn text={t.install} label="Copy install" />}
                </div>
              </div>
            );
          })}
        </Card>
      )}

      {s && (
        <Card
          title="Chromium (screenshots and PDF reports)"
          actions={
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <Badge kind={s.chromium.ok ? "ok" : undefined}>{s.chromium.ok ? "installed" : "not installed"}</Badge>
              <button type="button" className="btn btn-sm" disabled={busy !== null} onClick={() => update("chromium")}>
                {busy === "chromium" ? "Installing…" : s.chromium.ok ? "Update" : "Install"}
              </button>
            </div>
          }
        >
          {s.chromium.ok ? (
            <div className="muted small">Using {s.chromium.path}</div>
          ) : (
            <div className="muted small" style={{ marginBottom: 8 }}>Needed for screenshots and the PDF report. The button runs the command below.</div>
          )}
          <div className="hl" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginTop: 8 }}>
            {s.chromium.install}
            <CopyBtn text={s.chromium.install} label="Copy" />
          </div>
          {outcome.chromium && open === "chromium" && (
            <pre className="mono small" style={{ maxHeight: 220, overflow: "auto", whiteSpace: "pre-wrap", marginTop: 8 }}>{outcome.chromium.output || outcome.chromium.error}</pre>
          )}
          {outcome.chromium && (
            <div style={{ marginTop: 6 }}>
              <button type="button" className="btn btn-sm" onClick={() => setOpen(open === "chromium" ? null : "chromium")}>
                {open === "chromium" ? "Hide output" : "Output"}
              </button>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
