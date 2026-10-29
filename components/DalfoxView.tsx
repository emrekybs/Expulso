"use client";
import { useState } from "react";
import { Alert, Badge, Card, CopyBtn, Findings } from "./ui";
import { Icon } from "./icons";
import type { Finding } from "@/lib/types";

interface Candidate {
  url: string;
  params: string[];
}
interface Outcome {
  ok: boolean;
  error?: string;
  engine?: "dalfox" | "built-in";
  discovered?: number;
  candidates?: Candidate[];
  findings?: Finding[];
  warnings?: string[];
  command?: string;
}

export default function DalfoxView() {
  const [targets, setTargets] = useState("");
  const [discover, setDiscover] = useState(true);
  const [limit, setLimit] = useState(50);
  const [concurrency, setConcurrency] = useState(5);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  async function run() {
    setBusy(true);
    setOutcome(null);
    try {
      const res = await fetch("/api/dalfox", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ targets, discover, limit, concurrency, authorized }),
      });
      setOutcome((await res.json()) as Outcome);
    } catch {
      setOutcome({ ok: false, error: "Could not reach the server." });
    }
    setBusy(false);
  }

  const canRun = authorized && !busy && targets.trim().length > 0;

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.search({ size: 22 })}</div>
        <div>
          <h1>Dalfox (XSS)</h1>
          <p>
            Enter URLs with parameters, or domains. For a domain, B24-engine collects its known URLs, keeps the ones with parameters that usually reach the page, and tests each one for XSS.
          </p>
        </div>
      </div>

      <Alert kind="warn" title="Authorised targets only">
        Each candidate parameter receives test input. Run this only on systems you own or have written permission to test.
      </Alert>

      <Card title="Targets">
        <div className="stack" style={{ gap: 12 }}>
          <textarea className="bulk" rows={4} value={targets} onChange={(e) => setTargets(e.target.value)} placeholder={"https://app.example.com/search?q=test\nexample.com"} aria-label="Targets" />
          <label className="toggle">
            <input type="checkbox" checked={discover} onChange={(e) => setDiscover(e.target.checked)} />
            <span className="track" />
            For domains: discover URLs (gau, or the built-in archives when gau is not installed)
          </label>
        </div>
      </Card>

      <Card title="Limits">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Maximum candidate URLs</span>
            <input type="number" min={1} max={500} value={limit} onChange={(e) => setLimit(Number(e.target.value) || 1)} />
          </label>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Parallel workers</span>
            <input type="number" min={1} max={20} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value) || 1)} />
          </label>
        </div>
      </Card>

      <section className="card" style={{ padding: 16 }}>
        <label className="toggle" style={{ marginBottom: 12 }}>
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span className="track" />
          I am authorised to test these targets.
        </label>
        <button type="button" className="btn-primary" disabled={!canRun} onClick={run}>
          {busy ? "Testing…" : "Run XSS test"}
        </button>
        {busy && <div className="muted small" style={{ marginTop: 8 }}>Discovery and testing can take several minutes. Keep this page open until it finishes.</div>}
      </section>

      {outcome && !outcome.ok && <Alert kind="bad" title="XSS test did not run">{outcome.error}</Alert>}

      {outcome?.ok && (
        <>
          <div className="chips">
            <Badge kind={outcome.engine === "dalfox" ? "ok" : "info"}>engine: {outcome.engine}</Badge>
            <Badge>{outcome.discovered ?? 0} URLs discovered</Badge>
            <Badge>{outcome.candidates?.length ?? 0} candidate URLs</Badge>
            <Badge kind={(outcome.findings?.length ?? 0) > 0 ? "bad" : undefined}>{outcome.findings?.length ?? 0} finding(s)</Badge>
          </div>
          {outcome.warnings && outcome.warnings.length > 0 && <Alert kind="info">{outcome.warnings.join(" ")}</Alert>}
          {outcome.command && (
            <Card title="Command" actions={<CopyBtn text={outcome.command} label="Copy" />}>
              <pre className="mono small wrap-anywhere" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{outcome.command}</pre>
            </Card>
          )}
          {(outcome.candidates?.length ?? 0) > 0 && (
            <Card title="Candidate URLs" count={outcome.candidates?.length} pad={false}>
              {outcome.candidates?.map((c) => (
                <div key={c.url} className="list-item">
                  <span className="value wrap-anywhere" style={{ flex: 1 }}>{c.url}</span>
                  <span className="muted small">{c.params.join(", ")}</span>
                </div>
              ))}
            </Card>
          )}
          <Findings items={outcome.findings ?? []} />
        </>
      )}
    </div>
  );
}
