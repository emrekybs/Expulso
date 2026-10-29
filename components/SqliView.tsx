"use client";
import { useState } from "react";
import { Alert, Badge, Card, CopyBtn, Findings } from "./ui";
import NucleiTagPicker from "./NucleiTagPicker";
import { Icon } from "./icons";
import { SQLMAP_TECHNIQUES } from "@/lib/sqli-core";
import type { Finding } from "@/lib/types";

interface Candidate {
  url: string;
  params: string[];
}
interface Outcome {
  ok: boolean;
  error?: string;
  engine?: "sqlmap" | "built-in";
  discovered?: number;
  candidates?: Candidate[];
  findings?: Finding[];
  warnings?: string[];
  command?: string;
}

const TECHNIQUE_LABEL: Record<string, string> = { B: "boolean-blind", E: "error-based", U: "union", T: "time-blind", S: "stacked" };

export default function SqliView() {
  const [targets, setTargets] = useState("");
  const [discover, setDiscover] = useState(true);
  const [level, setLevel] = useState(1);
  const [risk, setRisk] = useState(1);
  const [techniques, setTechniques] = useState<string[]>(["B", "E", "T"]);
  const [threads, setThreads] = useState(1);
  const [limit, setLimit] = useState(20);
  const [nucleiTags, setNucleiTags] = useState<string[]>(["sqli"]);
  const [withNuclei, setWithNuclei] = useState(true);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  async function run() {
    setBusy(true);
    setOutcome(null);
    try {
      const res = await fetch("/api/sqli", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ nucleiTags: withNuclei ? nucleiTags : [], targets, discover, level, risk, techniques, threads, limit, authorized }),
      });
      setOutcome((await res.json()) as Outcome);
    } catch {
      setOutcome({ ok: false, error: "Could not reach the server." });
    }
    setBusy(false);
  }

  const canRun = authorized && !busy && targets.trim().length > 0 && techniques.length > 0;
  const toggleTech = (t: string) => setTechniques(techniques.includes(t) ? techniques.filter((x) => x !== t) : [...techniques, t]);

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.search({ size: 22 })}</div>
        <div>
          <h1>SQL Injection</h1>
          <p>
            Detects SQL injection in URL parameters that usually reach a database. sqlmap does the detection when it is installed. Only detection runs: no data is read from the database, and no shell or file access is attempted.
          </p>
        </div>
      </div>

      <Alert kind="warn" title="Authorised targets only">
        sqlmap sends many crafted requests to each parameter, and time-based techniques slow the target down. Run it only on systems you own or have written permission to test.
      </Alert>

      <Card title="Targets">
        <div className="stack" style={{ gap: 12 }}>
          <textarea className="bulk" rows={4} value={targets} onChange={(e) => setTargets(e.target.value)} placeholder={"https://shop.example.com/item?id=5\nexample.com"} aria-label="Targets" />
          <label className="toggle">
            <input type="checkbox" checked={discover} onChange={(e) => setDiscover(e.target.checked)} />
            <span className="track" />
            For domains: discover URLs (gau, or the built-in archives when gau is not installed)
          </label>
        </div>
      </Card>

      <Card title="Depth (sqlmap)">
        <div className="stack" style={{ gap: 12 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
            <label className="stack" style={{ gap: 6 }}>
              <span className="muted small">Level (1 = fewest tests, 5 = most)</span>
              <input type="number" min={1} max={5} value={level} onChange={(e) => setLevel(Number(e.target.value) || 1)} />
            </label>
            <label className="stack" style={{ gap: 6 }}>
              <span className="muted small">Risk (1 = safe, 3 = may modify data)</span>
              <input type="number" min={1} max={3} value={risk} onChange={(e) => setRisk(Number(e.target.value) || 1)} />
            </label>
            <label className="stack" style={{ gap: 6 }}>
              <span className="muted small">Threads</span>
              <input type="number" min={1} max={4} value={threads} onChange={(e) => setThreads(Number(e.target.value) || 1)} />
            </label>
            <label className="stack" style={{ gap: 6 }}>
              <span className="muted small">Maximum candidate URLs</span>
              <input type="number" min={1} max={200} value={limit} onChange={(e) => setLimit(Number(e.target.value) || 1)} />
            </label>
          </div>
          <div>
            <div className="muted small" style={{ marginBottom: 6 }}>Techniques</div>
            <div className="chips">
              {SQLMAP_TECHNIQUES.map((t) => (
                <button key={t} type="button" className={`chip${techniques.includes(t) ? " on" : ""}`} onClick={() => toggleTech(t)}>
                  {TECHNIQUE_LABEL[t]}
                </button>
              ))}
            </div>
          </div>
          {risk >= 2 || level >= 4 ? <Alert kind="warn">Higher level and risk send more payloads. Risk 3 can change data on the target.</Alert> : null}
        </div>
      </Card>

      <Card title="Nuclei templates on the same URLs">
        <div className="stack" style={{ gap: 12 }}>
          <label className="toggle">
            <input type="checkbox" checked={withNuclei} onChange={(e) => setWithNuclei(e.target.checked)} />
            <span className="track" />
            Also run nuclei with these tags on the candidate URLs
          </label>
          {withNuclei && <NucleiTagPicker selected={nucleiTags} onChange={setNucleiTags} />}
          <div className="muted small">Uses the installed nuclei. Tags are the same as on the Nuclei page.</div>
        </div>
      </Card>

      <section className="card" style={{ padding: 16 }}>
        <label className="toggle" style={{ marginBottom: 12 }}>
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span className="track" />
          I am authorised to test these targets.
        </label>
        <button type="button" className="btn-primary" disabled={!canRun} onClick={run}>
          {busy ? "Testing…" : "Run SQL injection test"}
        </button>
        {busy && <div className="muted small" style={{ marginTop: 8 }}>sqlmap can take a long time on slow targets. Keep this page open until it finishes.</div>}
      </section>

      {outcome && !outcome.ok && <Alert kind="bad" title="SQL test did not run">{outcome.error}</Alert>}

      {outcome?.ok && (
        <>
          <div className="chips">
            <Badge kind={outcome.engine === "sqlmap" ? "ok" : "info"}>engine: {outcome.engine}</Badge>
            <Badge>{outcome.discovered ?? 0} URLs discovered</Badge>
            <Badge>{outcome.candidates?.length ?? 0} candidate URLs</Badge>
            <Badge kind={(outcome.findings?.length ?? 0) > 0 ? "bad" : undefined}>{outcome.findings?.length ?? 0} finding(s)</Badge>
          </div>
          {outcome.warnings && outcome.warnings.length > 0 && <Alert kind="info">{outcome.warnings.join(" ")}</Alert>}
          {outcome.command && (
            <Card title="Command (first runs)" actions={<CopyBtn text={outcome.command} label="Copy" />}>
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
