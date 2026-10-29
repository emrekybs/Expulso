"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Alert, Badge, Card, Chips } from "./ui";
import NucleiTagPicker from "./NucleiTagPicker";
import { Icon } from "./icons";
import { STAGES, ALL_STAGES_ON, type StageId, type StatusFilter } from "@/lib/autopipe-core";
import type { PipelineRecord } from "@/lib/autopipe";

interface PlanStep {
  stage: string;
  on: boolean;
  engine: string;
  note: string;
}

export default function AutopipeView() {
  const [targets, setTargets] = useState("");
  const [stages, setStages] = useState<Record<StageId, boolean>>(ALL_STAGES_ON);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("2xx");
  const [hostLimit, setHostLimit] = useState(30);
  const [urlLimit, setUrlLimit] = useState(30);
  const [nucleiTags, setNucleiTags] = useState<string[]>([]);
  const [authorized, setAuthorized] = useState(false);
  const [proxyMode, setProxyMode] = useState<"global" | "on" | "off">("global");
  const [plan, setPlan] = useState<PlanStep[] | null>(null);
  const [error, setError] = useState("");
  const [runs, setRuns] = useState<PipelineRecord[]>([]);
  const [busy, setBusy] = useState(false);

  const body = () => JSON.stringify({ targets, stages, statusFilter, hostLimit, urlLimit, nucleiTags, authorized });

  useEffect(() => {
    let alive = true;
    const load = () => fetch("/api/autopipe", { cache: "no-store" }).then((r) => r.json()).then((j: { runs: PipelineRecord[] }) => alive && setRuns(j.runs ?? [])).catch(() => undefined);
    void load();
    const t = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  async function previewPlan() {
    setError("");
    const res = await fetch("/api/autopipe/plan", { method: "POST", headers: { "content-type": "application/json" }, body: body() });
    const json = (await res.json()) as { ok: boolean; steps?: PlanStep[]; error?: string };
    if (!json.ok) {
      setPlan(null);
      setError(json.error ?? "Could not build the plan.");
    } else setPlan(json.steps ?? []);
  }

  async function start() {
    setError("");
    setBusy(true);
    const res = await fetch("/api/autopipe", { method: "POST", headers: { "content-type": "application/json" }, body: body() });
    const json = (await res.json()) as { ok: boolean; error?: string };
    setBusy(false);
    if (!json.ok) setError(json.error ?? "Could not start.");
  }

  const toggle = (id: StageId) => {
    setStages({ ...stages, [id]: !stages[id] });
    setPlan(null);
  };

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.fullscan({ size: 22 })}</div>
        <div>
          <h1>Autopipeline</h1>
          <p>One run from a domain to tested findings: subdomains, live hosts, nuclei, URLs with parameters, XSS and SQL tests. Every stage can be switched off, and each stage shows its result as it finishes.</p>
        </div>
      </div>

      <Alert kind="warn" title="Authorised targets only">
        This run sends test requests to every live host it finds, within the limits below. Run it only on systems you own or have written permission to test.
      </Alert>

      <Card title="Domains">
        <div className="stack" style={{ gap: 12 }}>
          <textarea className="bulk" rows={3} value={targets} onChange={(e) => { setTargets(e.target.value); setPlan(null); }} placeholder={"example.com\nexample.org"} aria-label="Domains" />
          <div className="muted small">One domain per line, up to 5. Each domain is a separate run.</div>
        </div>
      </Card>

      <Card title="Stages">
        <div className="stack" style={{ gap: 10 }}>
          {STAGES.map((s) => (
            <label key={s.id} className="toggle" style={{ alignItems: "flex-start" }}>
              <input type="checkbox" checked={stages[s.id]} onChange={() => toggle(s.id)} />
              <span className="track" />
              <span>
                <b>{s.title}</b>
                <span className="muted small" style={{ display: "block" }}>{s.detail}</span>
              </span>
            </label>
          ))}
        </div>
      </Card>

      <Card title="Limits and filters">
        <div className="stack" style={{ gap: 12 }}>
          <div>
            <div className="muted small" style={{ marginBottom: 6 }}>Which hosts continue to the tests</div>
            <Chips
              value={statusFilter}
              onChange={(v) => {
                setStatusFilter(v);
                setPlan(null);
              }}
              options={[
                { value: "2xx", label: "200 only" },
                { value: "2xx-3xx", label: "200 and redirects" },
                { value: "all", label: "Every live host" },
              ]}
            />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
            <label className="stack" style={{ gap: 6 }}>
              <span className="muted small">Maximum hosts per run</span>
              <input type="number" min={1} max={200} value={hostLimit} onChange={(e) => setHostLimit(Number(e.target.value) || 1)} />
            </label>
            <label className="stack" style={{ gap: 6 }}>
              <span className="muted small">Maximum candidate URLs per test</span>
              <input type="number" min={1} max={200} value={urlLimit} onChange={(e) => setUrlLimit(Number(e.target.value) || 1)} />
            </label>
          </div>
        </div>
      </Card>

      <Card title="nuclei tags (added to the automatic run)">
        <NucleiTagPicker selected={nucleiTags} onChange={setNucleiTags} />
      </Card>

      <Card title="Burp proxy for this run">
        <Chips
          value={proxyMode}
          onChange={(v) => {
            setProxyMode(v);
            setPlan(null);
          }}
          options={[
            { value: "global", label: "Follow Settings" },
            { value: "on", label: "Send through Burp" },
            { value: "off", label: "Direct" },
          ]}
        />
        <div className="muted small" style={{ marginTop: 8 }}>Overrides the Settings switch for this run only. Burp must be listening at the address set in Settings.</div>
      </Card>

      <section className="card" style={{ padding: 16 }}>
        <label className="toggle" style={{ marginBottom: 12 }}>
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span className="track" />
          I am authorised to test these targets.
        </label>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button type="button" className="btn btn-sm" onClick={previewPlan}>Preview plan</button>
          <button type="button" className="btn-primary" disabled={!authorized || busy || !targets.trim()} onClick={start}>
            {busy ? "Starting…" : "Start autopipeline"}
          </button>
        </div>
      </section>

      {error && <Alert kind="bad">{error}</Alert>}

      {plan && (
        <Card title="Plan" pad={false}>
          {plan.map((p) => (
            <div key={p.stage} className="list-item">
              <Badge kind={p.on ? "ok" : undefined}>{p.on ? "on" : "off"}</Badge>
              <span className="value">{p.stage}</span>
              <span className="muted small" style={{ marginLeft: "auto" }}>{p.engine}{p.note ? ` · ${p.note}` : ""}</span>
            </div>
          ))}
        </Card>
      )}

      <Card title="Runs" count={runs.length} pad={false}>
        {runs.length === 0 ? (
          <div className="card-body muted">No runs yet.</div>
        ) : (
          runs.map((r) => (
            <div key={r.id} className="list-item">
              <Badge kind={r.status === "done" ? "ok" : r.status === "failed" ? "bad" : r.status === "stopped" ? undefined : "warn"}>{r.status}</Badge>
              <Link className="value-link" href={`/autopipe/${r.id}`}>{r.target}</Link>
              <span className="muted small" style={{ marginLeft: "auto" }}>
                {r.hosts.length} host(s) · {r.selected.length} selected · {r.stages.reduce((n, s) => n + s.findings.length, 0)} finding(s)
              </span>
            </div>
          ))
        )}
      </Card>
    </div>
  );
}
