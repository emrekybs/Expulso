"use client";
import { useEffect, useState } from "react";
import { Card, Badge, Alert, CopyBtn } from "./ui";

interface ToolStatus { name: string; installed: boolean; path: string | null; purpose: string; install: string }
interface Status { tools: ToolStatus[]; chromium: { path: string | null; ok: boolean; install: string } }

export default function ToolsView() {
  const [s, setS] = useState<Status | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    fetch("/api/tools").then((r) => r.json()).then(setS).catch(() => setErr("Could not read tool status."));
  }, []);
  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" /></svg>
        </div>
        <div>
          <h1>Tools</h1>
          <p>B24-engine uses the command-line tools below when they are installed on this machine. Missing tools are skipped and reported in the scan. Nothing here is required for the built-in modules.</p>
        </div>
      </div>
      {err && <Alert kind="bad">{err}</Alert>}
      {s && (
        <Card title="External tools" count={`${s.tools.filter((t) => t.installed).length}/${s.tools.length} installed`} pad={false}>
          {s.tools.map((t) => (
            <div key={t.name} className="list-item" style={{ alignItems: "flex-start" }}>
              <Badge kind={t.installed ? "ok" : undefined}>{t.installed ? "installed" : "missing"}</Badge>
              <div className="li-main">
                <div className="value">{t.name}</div>
                <div className="muted small">{t.purpose}</div>
                {!t.installed && <div className="hl" style={{ marginTop: 6 }}>{t.install}</div>}
                {t.path && <div className="muted small mono" style={{ marginTop: 4 }}>{t.path}</div>}
              </div>
              {!t.installed && <CopyBtn text={t.install} label="Copy command" />}
            </div>
          ))}
        </Card>
      )}
      {s && (
        <Card title="Screenshots (Chromium)" actions={<Badge kind={s.chromium.ok ? "ok" : undefined}>{s.chromium.ok ? "ready" : "not installed"}</Badge>}>
          {s.chromium.ok ? (
            <div className="muted small">Using {s.chromium.path}</div>
          ) : (
            <>
              <div className="muted small" style={{ marginBottom: 8 }}>Screenshots need the Chromium browser that Playwright installs. Run this once in the project folder:</div>
              <div className="hl" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                {s.chromium.install}
                <CopyBtn text={s.chromium.install} label="Copy" />
              </div>
            </>
          )}
        </Card>
      )}
    </div>
  );
}
