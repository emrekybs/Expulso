"use client";
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { MODE_LABEL, modulesForMode, type ScanMode } from "@/lib/modules-config";
import { parseTarget, splitTargets } from "@/lib/target";
import { runFullScan, pushHistory, type FullScanResponse, type FullScanModule } from "@/lib/client/api";
import { buildHtmlReport } from "@/lib/client/report";
import { download, stamp, slug } from "@/lib/client/export";
import { renderModule } from "./renderers";
import AssessmentCard from "./AssessmentCard";
import { computeAssessment } from "@/lib/assessment";
import { Card, Stat, Findings, Alert, Badge } from "./ui";
import { Icon } from "./icons";

interface TargetRun {
  target: string;
  state: "queued" | "running" | "done" | "failed";
  res?: FullScanResponse;
}

export default function FullScanView() {
  const params = useSearchParams();
  const [mode, setMode] = useState<ScanMode>("passive");
  const [input, setInput] = useState("");
  const [bulk, setBulk] = useState(false);
  const [runs, setRuns] = useState<TargetRun[]>([]);
  const [active, setActive] = useState(0);
  const [busy, setBusy] = useState(false);
  const [openMod, setOpenMod] = useState<string | null>(null);
  const [error, setError] = useState("");
  const started = useRef(false);
  const [pendingRun, setPendingRun] = useState(false);

  useEffect(() => {
    const t = params.get("target");
    if (t && !started.current) {
      started.current = true;
      setInput(t);
      setPendingRun(true);
    }
  }, [params]);

  useEffect(() => {
    if (pendingRun && input) {
      setPendingRun(false);
      void run();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingRun, input]);

  const expectedModules = modulesForMode(mode);

  async function run() {
    const targets = (bulk ? splitTargets(input) : [input.trim()]).filter(Boolean).slice(0, 20);
    if (!targets.length) {
      setError("Enter at least one target.");
      return;
    }
    for (const t of targets) {
      const p = parseTarget(t);
      if ("error" in p) {
        setError(`${t}: ${p.error}`);
        return;
      }
    }
    setError("");
    setBusy(true);
    setOpenMod(null);
    const list: TargetRun[] = targets.map((t) => ({ target: t, state: "queued" }));
    setRuns([...list]);
    setActive(0);
    for (let i = 0; i < list.length; i++) {
      list[i].state = "running";
      setRuns([...list]);
      setActive(i);
      list[i].res = await runFullScan(list[i].target, mode);
      list[i].state = list[i].res?.ok ? "done" : "failed";
      setRuns([...list]);
      if (list[i].res?.ok) pushHistory({ target: parseTarget(list[i].target) && "host" in (parseTarget(list[i].target) as object) ? (parseTarget(list[i].target) as { host: string }).host : list[i].target, module: "overview", label: `Full Scan (${mode})`, summary: `${list[i].res!.counts?.high ?? 0} high · ${list[i].res!.counts?.medium ?? 0} medium` });
    }
    setBusy(false);
  }

  const cur = runs[active];

  function exportAll(kind: "html" | "json" | "csv") {
    const done = runs.filter((r) => r.res?.ok).map((r) => ({ target: r.target, res: r.res! }));
    if (!done.length) return;
    const base = `full_scan_${slug(runs[0]?.target ?? "report")}_${stamp()}`;
    if (kind === "html") download(`${base}.html`, buildHtmlReport(done, mode), "text/html");
    else if (kind === "json") download(`${base}.json`, JSON.stringify(done, null, 2), "application/json");
    else {
      const rows = done.flatMap((d) => (d.res.findings ?? []).map((f) => ({ target: d.target, severity: f.severity, module: f.module, title: f.title, detail: f.detail, recommendation: f.recommendation ?? "" })));
      download(`${base}_findings.csv`, toCsvLocal(rows), "text/csv");
    }
  }

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.fullscan({ size: 22 })}</div>
        <div>
          <h1>Full Scan</h1>
          <p>Runs many modules against each target and merges the results into one report. Choose passive only, active only, or both. In bulk mode, enter several targets — domains, IPs, ranges or URLs.</p>
        </div>
      </div>

      <section className="card search-card">
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center", marginBottom: 12 }}>
          <div className="seg">
            {(["passive", "active", "full"] as ScanMode[]).map((m) => (
              <button key={m} type="button" className={mode === m ? "on" : ""} onClick={() => setMode(m)}>
                {MODE_LABEL[m]}
              </button>
            ))}
          </div>
          <label className="toggle" style={{ marginLeft: "auto" }}>
            <input type="checkbox" checked={bulk} onChange={(e) => setBulk(e.target.checked)} />
            <span className="track" />
            Bulk list
          </label>
        </div>

        {bulk ? (
          <textarea className="bulk" value={input} onChange={(e) => setInput(e.target.value)} rows={5} placeholder={"example.com\n8.8.8.8\n203.0.113.0/24\nhttps://example.org"} />
        ) : (
          <form className="search-row" onSubmit={(e) => (e.preventDefault(), run())}>
            <div className="search-input">
              <span className="si-icon">{Icon.search({ size: 18 })}</span>
              <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="example.com" aria-label="Target" />
            </div>
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? "Scanning…" : "Run Full Scan"}
            </button>
          </form>
        )}
        {bulk && (
          <div style={{ marginTop: 10 }}>
            <button type="button" className="btn-primary" disabled={busy} onClick={run}>
              {busy ? "Scanning…" : `Scan ${splitTargets(input).length || ""} targets`}
            </button>
          </div>
        )}
        <div className="recent" style={{ marginTop: 10 }}>
          {mode === "full" ? "Active modules send requests to the target. Use only on systems you are authorized to test." : mode === "active" ? "Active modules send requests to the target. Use only on systems you are authorized to test." : "Passive mode sends nothing to the target."} Modules this mode runs: {expectedModules.length}.
        </div>
      </section>

      {error && <Alert kind="bad">{error}</Alert>}
      {(mode === "active" || mode === "full") && <Alert kind="warn" title="Active scan">This includes modules that send requests to the target (HTTP fingerprint, JS crawler, directory finder, exposure checks). Only run against systems you are authorized to test.</Alert>}

      {runs.length > 0 && (
        <>
          <div className="result-bar">
            <span className="muted small">Targets:</span>
            {runs.map((r, i) => (
              <button key={r.target} type="button" className={`target-pill ${r.state === "done" ? "done" : r.state === "failed" ? "failed" : ""} ${i === active ? "active" : ""}`} onClick={() => setActive(i)}>
                <span className="st" style={{ background: r.state === "done" ? "var(--ok)" : r.state === "failed" ? "var(--bad)" : r.state === "running" ? "var(--warn)" : "var(--muted)" }} />
                {r.target}
                {r.state === "running" && " …"}
              </button>
            ))}
            <div className="rb-actions">
              <button type="button" className="btn btn-sm" disabled={!runs.some((r) => r.res?.ok)} onClick={() => exportAll("html")}>HTML report</button>
              <button type="button" className="btn btn-sm" disabled={!runs.some((r) => r.res?.ok)} onClick={() => exportAll("json")}>JSON</button>
              <button type="button" className="btn btn-sm" disabled={!runs.some((r) => r.res?.ok)} onClick={() => exportAll("csv")}>CSV</button>
            </div>
          </div>

          {cur && <TargetResult run={cur} mode={mode} expected={expectedModules.length} openMod={openMod} setOpenMod={setOpenMod} />}
        </>
      )}
    </div>
  );
}

function TargetResult({ run, mode, expected, openMod, setOpenMod }: { run: TargetRun; mode: ScanMode; expected: number; openMod: string | null; setOpenMod: (v: string | null) => void }) {
  if (run.state === "running" && !run.res)
    return (
      <div className="card loading-card">
        {Icon.fullscan({ size: 20 })}
        <div style={{ flex: 1 }}>
          <div>Scanning {run.target} — running {expected} modules…</div>
          <div className="progress"><div /></div>
        </div>
      </div>
    );
  const res = run.res;
  if (!res) return null;
  if (!res.ok) return <Alert kind="bad" title="Scan failed">{res.error}</Alert>;

  const c = res.counts ?? { high: 0, medium: 0, low: 0, info: 0 };
  const okMods = (res.modules ?? []).filter((m): m is Extract<FullScanModule, { ok: true }> => m.ok);
  const findings = res.findings ?? [];

  return (
    <div className="stack">
      <AssessmentCard a={computeAssessment(res.modules ?? [])} />

      {/* progress grid */}
      <Card title={run.target} count={`${okMods.length}/${res.modules?.length ?? 0} ok`} pad={false}>
        <div className="card-body" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: 8 }}>
          {(res.modules ?? []).map((m) => (
            <div key={m.id} className="target-pill" style={{ justifyContent: "flex-start" }}>
              <span className="st" style={{ background: m.ok ? "var(--ok)" : "var(--bad)" }} />
              <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{m.title}</span>
              <span className="muted small">{m.ok ? `${Math.round(m.durationMs)}ms` : (m.code ?? "err")}</span>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid grid-4">
        <Stat label="Findings" value={findings.length} sub={`${c.high} high · ${c.medium} medium`} accent={c.high ? "orange" : "blue"} />
        <Stat label="Modules run" value={res.modules?.length ?? 0} sub={MODE_LABEL[mode]} accent="silver" />
        <Stat label="Succeeded" value={okMods.length} accent="green" />
        <Stat label="Mode" value={mode} accent="silver" />
      </div>

      {findings.length > 0 && <FindingsWithModule items={findings} />}

      {/* Per-module accordion */}
      <Card title="Results by module" pad={false}>
        {okMods.map((m) => (
          <div key={m.id}>
            <button type="button" className="acc-head" aria-expanded={openMod === m.id} onClick={() => setOpenMod(openMod === m.id ? null : m.id)}>
              <span className="muted" style={{ width: 14 }}>{openMod === m.id ? "▾" : "▸"}</span>
              <b style={{ width: 220, flexShrink: 0 }}>{m.title}</b>
              <span className="muted small" style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.summary}</span>
              <span className={`tier ${m.tier}`}>{m.tier}</span>
            </button>
            {openMod === m.id && <div className="acc-body">{renderModule(m.id, { summary: m.summary, findings: m.findings, data: m.data })}</div>}
          </div>
        ))}
        {(res.modules ?? []).filter((m) => !m.ok).map((m) => (
          <div key={m.id} className="acc-head" style={{ cursor: "default" }}>
            <span style={{ width: 14 }} />
            <b style={{ width: 220, flexShrink: 0 }}>{m.title}</b>
            <span className="muted small" style={{ flex: 1 }}>{!m.ok ? m.error : ""}</span>
            <Badge kind="bad">failed</Badge>
          </div>
        ))}
      </Card>
    </div>
  );
}

function FindingsWithModule({ items }: { items: (import("@/lib/types").Finding & { module: string })[] }) {
  // Reuse the Findings card but show the source module.
  return (
    <>
      <Findings items={items} />
      <div className="muted small" style={{ marginTop: -8, paddingLeft: 2 }}>
        Findings are aggregated from: {[...new Set(items.map((f) => f.module))].join(", ")}
      </div>
    </>
  );
}

function toCsvLocal(rows: Record<string, unknown>[]): string {
  if (!rows.length) return "";
  const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  const esc = (v: unknown) => {
    const s = v == null ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
}
