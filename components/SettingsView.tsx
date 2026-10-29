"use client";
import { useEffect, useState } from "react";
import { Alert, Badge, Card } from "./ui";
import type { BurpSettings, SessionSettings } from "@/lib/settings-core";

export default function SettingsView() {
  const [s, setS] = useState<BurpSettings | null>(null);
  const [sess, setSess] = useState<SessionSettings | null>(null);
  const [sessMsg, setSessMsg] = useState("");
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const [test, setTest] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    fetch("/api/settings", { cache: "no-store" })
      .then((r) => r.json())
      .then((j: { settings: { burp: BurpSettings; session: SessionSettings } }) => {
        setS(j.settings.burp);
        setSess(j.settings.session);
      })
      .catch(() => setError("Could not read the settings."));
  }, []);

  async function save(next: BurpSettings) {
    setError("");
    setSaved(false);
    const res = await fetch("/api/settings", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ burp: next, session: sess }) });
    const json = (await res.json()) as { ok: boolean; error?: string; settings?: { burp: BurpSettings; session: SessionSettings } };
    if (!json.ok) setError(json.error ?? "Could not save.");
    else {
      setS(json.settings!.burp);
      setSaved(true);
    }
  }

  async function saveSession() {
    setSessMsg("");
    const res = await fetch("/api/settings", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ burp: s, session: sess }) });
    const json = (await res.json()) as { ok: boolean; error?: string };
    setSessMsg(json.ok ? "Saved. New scans use this login." : json.error ?? "Could not save.");
  }

  async function runTest() {
    setTest(null);
    const res = await fetch("/api/settings/test", { method: "POST" });
    const json = (await res.json()) as { ok: boolean; message?: string; error?: string };
    setTest({ ok: json.ok, message: json.message ?? json.error ?? "" });
  }

  if (!s || !sess) return <div className="card loading-card"><div>Loading settings…</div></div>;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>Connect B24-engine to Burp Suite (or any HTTP proxy). When the proxy is on, every target-facing request from every module and tool goes through it, so you can see and replay the traffic in Burp.</p>
        </div>
      </div>

      {error && <Alert kind="bad">{error}</Alert>}
      {saved && <Alert kind="info">Saved. New scans use this setting.</Alert>}

      <Card title="Burp Suite proxy" actions={<Badge kind={s.enabled ? "ok" : undefined}>{s.enabled ? "on" : "off"}</Badge>}>
        <div className="stack" style={{ gap: 14 }}>
          <label className="toggle">
            <input type="checkbox" checked={s.enabled} onChange={(e) => save({ ...s, enabled: e.target.checked })} />
            <span className="track" />
            Send scan traffic through the proxy
          </label>

          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Proxy address</span>
            <div style={{ display: "flex", gap: 8 }}>
              <input value={s.url} onChange={(e) => setS({ ...s, url: e.target.value })} aria-label="Proxy address" />
              <button type="button" className="btn btn-sm" onClick={() => save(s)}>Save</button>
            </div>
          </label>

          <label className="toggle">
            <input type="checkbox" checked={s.ignoreTls} onChange={(e) => save({ ...s, ignoreTls: e.target.checked })} />
            <span className="track" />
            Accept Burp's certificate for proxied HTTPS (recommended unless you installed Burp's CA)
          </label>

          <div>
            <button type="button" className="btn btn-sm" disabled={!s.enabled} onClick={runTest}>Test connection</button>
            {test && <div style={{ marginTop: 8 }}><Alert kind={test.ok ? "info" : "bad"}>{test.message}</Alert></div>}
          </div>
        </div>
      </Card>

      <Card title="Login session" actions={<Badge kind={sess.enabled ? "ok" : undefined}>{sess.enabled ? "on" : "off"}</Badge>}>
        <div className="stack" style={{ gap: 12 }}>
          <label className="toggle">
            <input type="checkbox" checked={sess.enabled} onChange={(e) => setSess({ ...sess, enabled: e.target.checked })} />
            <span className="track" />
            Send this login with every target-facing request, from the modules, the tools and the crawler
          </label>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Cookie (copy the Cookie header from your browser's developer tools)</span>
            <textarea rows={2} value={sess.cookie} onChange={(e) => setSess({ ...sess, cookie: e.target.value })} aria-label="Cookie" />
          </label>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Authorization header (for example Bearer token)</span>
            <input type="password" value={sess.authorization} onChange={(e) => setSess({ ...sess, authorization: e.target.value })} aria-label="Authorization" />
          </label>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Other headers, one per line (for example X-Api-Key: value)</span>
            <textarea rows={2} value={sess.headers} onChange={(e) => setSess({ ...sess, headers: e.target.value })} aria-label="Other headers" />
          </label>
          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button type="button" className="btn btn-sm" onClick={saveSession}>Save login</button>
            {sessMsg && <span className="muted small">{sessMsg}</span>}
          </div>
          <div className="muted small">Stored in data/settings.json on this computer, in plain text. Turn the switch off when you test without a login. Only use credentials you are authorised to use.</div>
        </div>
      </Card>

      <Card title="How to connect">
        <ol className="stack" style={{ gap: 6, paddingLeft: 18 }}>
          <li>In Burp: Proxy → Proxy settings → the listener on 127.0.0.1:8080 must be running.</li>
          <li>Turn Burp's <b>Intercept</b> off during scans. With intercept on, each request waits for your click and the scan stalls.</li>
          <li>Turn the switch above on, then press Test connection. The request appears in Burp's HTTP history.</li>
          <li>Scan traffic includes test payloads. Keep Burp's history for your report and clear it when the job is done.</li>
        </ol>
      </Card>
    </div>
  );
}
