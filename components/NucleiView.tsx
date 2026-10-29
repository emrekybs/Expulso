"use client";
import { useState } from "react";
import Link from "next/link";
import { NUCLEI_SEVERITIES, NUCLEI_TEMPLATES, nucleiCommandPreview, type NucleiRequest } from "@/lib/nuclei-core";
import type { Finding } from "@/lib/types";
import { Alert, Card, CopyBtn, Findings } from "./ui";
import { Icon } from "./icons";

const TAG_SUGGESTIONS = ["cve", "kev", "rce", "sqli", "xss", "lfi", "ssrf", "exposure", "misconfig", "takeover", "default-login", "panel", "tech", "wordpress", "jenkins", "grafana"];

interface RunOutcome {
  ok: boolean;
  command?: string;
  rawCount?: number;
  findings?: Finding[];
  error?: string;
  targets?: number;
}

function toggle<T>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
}

export default function NucleiView() {
  const [targets, setTargets] = useState("");
  const [severities, setSeverities] = useState<string[]>(["medium", "high", "critical"]);
  const [templates, setTemplates] = useState<string[]>(["cves"]);
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState("");
  const [automatic, setAutomatic] = useState(false);
  const [rateLimit, setRateLimit] = useState(50);
  const [concurrency, setConcurrency] = useState(10);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<RunOutcome | null>(null);
  const [installing, setInstalling] = useState(false);
  const [installLog, setInstallLog] = useState("");

  const request: NucleiRequest = {
    targets: targets.split(/[\s,]+/).filter(Boolean),
    severities,
    tags,
    templates,
    automatic,
    rateLimit,
    concurrency,
  };
  const preview = nucleiCommandPreview(request);

  function addTag(raw: string) {
    const t = raw.trim().toLowerCase();
    if (t && !tags.includes(t)) setTags([...tags, t]);
    setTagInput("");
  }

  async function run() {
    setBusy(true);
    setOutcome(null);
    try {
      const res = await fetch("/api/nuclei", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ targets, severities, tags, templates, automatic, rateLimit, concurrency, authorized }),
      });
      setOutcome((await res.json()) as RunOutcome);
    } catch {
      setOutcome({ ok: false, error: "Could not reach the server." });
    }
    setBusy(false);
  }

  async function install() {
    setInstalling(true);
    setInstallLog("");
    try {
      const res = await fetch("/api/tools/update", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "nuclei" }) });
      const json = (await res.json()) as { ok: boolean; output?: string; error?: string };
      setInstallLog(json.output || json.error || "");
    } catch {
      setInstallLog("Could not reach the server.");
    }
    setInstalling(false);
  }

  const canRun = authorized && !busy && request.targets.length > 0 && (automatic || tags.length > 0 || templates.length > 0);

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.search({ size: 22 })}</div>
        <div>
          <h1>Nuclei</h1>
          <p>Template-based scanning for known CVEs, exposures and misconfigurations. Choose templates, tags and severities, or let automatic detection pick templates from the technologies it finds.</p>
        </div>
      </div>

      <Alert kind="warn" title="Authorised targets only">
        nuclei sends test requests to every target. Run it only on systems you own or have written permission to test.
      </Alert>

      <Card title="Targets">
        <div className="stack" style={{ gap: 12 }}>
          <textarea className="bulk" rows={4} value={targets} onChange={(e) => setTargets(e.target.value)} placeholder={"example.com\nhttps://app.example.com\n203.0.113.10"} aria-label="Targets" />
          <div className="muted small">One per line, or separated by spaces. Up to 200 targets. Ranges and private addresses are refused.</div>
        </div>
      </Card>

      <Card title="Templates">
        <div className="stack" style={{ gap: 12 }}>
          <div>
            <div className="muted small" style={{ marginBottom: 6 }}>Categories</div>
            <div className="chips">
              {NUCLEI_TEMPLATES.map((t) => (
                <button key={t} type="button" className={`chip${templates.includes(t) ? " on" : ""}`} onClick={() => setTemplates(toggle(templates, t))}>{t}</button>
              ))}
            </div>
          </div>
          <div>
            <div className="muted small" style={{ marginBottom: 6 }}>Tags (press Enter to add)</div>
            <div className="chips" style={{ marginBottom: 8 }}>
              {tags.map((t) => (
                <button key={t} type="button" className="chip on" onClick={() => setTags(tags.filter((x) => x !== t))}>{t} ×</button>
              ))}
            </div>
            <input
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addTag(tagInput);
                }
              }}
              placeholder="cve, kev, wordpress…"
              aria-label="Add tag"
            />
            <div className="chips" style={{ marginTop: 8 }}>
              {TAG_SUGGESTIONS.filter((t) => !tags.includes(t)).map((t) => (
                <button key={t} type="button" className="chip" onClick={() => addTag(t)}>+ {t}</button>
              ))}
            </div>
          </div>
          <div>
            <div className="muted small" style={{ marginBottom: 6 }}>Severity</div>
            <div className="chips">
              {NUCLEI_SEVERITIES.map((s) => (
                <button key={s} type="button" className={`chip${severities.includes(s) ? " on" : ""}`} onClick={() => setSeverities(toggle(severities, s))}>{s}</button>
              ))}
            </div>
          </div>
          <label className="toggle">
            <input type="checkbox" checked={automatic} onChange={(e) => setAutomatic(e.target.checked)} />
            <span className="track" />
            Automatic detection (-as): detect technologies and run the matching templates
          </label>
        </div>
      </Card>

      <Card title="Speed">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Requests per second</span>
            <input type="number" min={1} max={500} value={rateLimit} onChange={(e) => setRateLimit(Number(e.target.value) || 1)} />
          </label>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Concurrent templates</span>
            <input type="number" min={1} max={100} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value) || 1)} />
          </label>
        </div>
      </Card>

      <Card title="Command" actions={<CopyBtn text={preview} label="Copy" />}>
        <pre className="mono small wrap-anywhere" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{preview}</pre>
      </Card>

      <section className="card" style={{ padding: 16 }}>
        <label className="toggle" style={{ marginBottom: 12 }}>
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span className="track" />
          I am authorised to test these targets.
        </label>
        <button type="button" className="btn-primary" disabled={!canRun} onClick={run}>
          {busy ? "Running nuclei…" : "Run nuclei"}
        </button>
        {busy && <div className="muted small" style={{ marginTop: 8 }}>This can take several minutes. Keep this page open until it finishes.</div>}
      </section>

      {outcome && !outcome.ok && (
        <Alert kind="bad" title="Nuclei did not run">
          {outcome.error}
          {outcome.error?.includes("not installed") && (
            <div style={{ marginTop: 10 }}>
              <button type="button" className="btn btn-sm" disabled={installing} onClick={install}>
                {installing ? "Installing…" : "Install nuclei now"}
              </button>
              <span className="muted small" style={{ marginLeft: 10 }}>or see <Link className="value-link" href="/tools">Tools</Link></span>
            </div>
          )}
        </Alert>
      )}
      {installLog && <pre className="mono small" style={{ whiteSpace: "pre-wrap", maxHeight: 220, overflow: "auto" }}>{installLog}</pre>}

      {outcome?.ok && (
        <>
          <Alert kind="info" title="Run finished">
            {outcome.targets} target(s), {outcome.rawCount} raw result(s), {outcome.findings?.length ?? 0} finding(s).
          </Alert>
          <Findings items={outcome.findings ?? []} />
        </>
      )}
    </div>
  );
}
