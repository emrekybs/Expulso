"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { MODE_LABEL, modulesForMode, type ScanMode } from "@/lib/modules-config";
import { parseTarget, splitTargets } from "@/lib/target";
import { listScans, startScan } from "@/lib/client/api";
import type { ScanSummary } from "@/lib/scan-types";
import { Alert, Badge } from "./ui";
import { Icon } from "./icons";

interface Started {
  target: string;
  id?: string;
  error?: string;
}

const STATUS: Record<ScanSummary["status"], { label: string; kind?: "ok" | "warn" | "bad" | "info" }> = {
  running: { label: "running", kind: "warn" },
  done: { label: "done", kind: "ok" },
  failed: { label: "failed", kind: "bad" },
};

export default function FullScanView() {
  const params = useSearchParams();
  const router = useRouter();
  const [mode, setMode] = useState<ScanMode>("passive");
  const [input, setInput] = useState("");
  const [bulk, setBulk] = useState(false);
  const [scopeText, setScopeText] = useState("");
  const [chainLimit, setChainLimit] = useState(15);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [batch, setBatch] = useState<Started[]>([]);
  const [summaries, setSummaries] = useState<Record<string, ScanSummary>>({});
  const auto = useRef(false);

  const expectedModules = modulesForMode(mode);

  async function run(override?: string) {
    const raw = override ?? input;
    const targets = (bulk ? splitTargets(raw) : [raw.trim()]).filter(Boolean).slice(0, 20);
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
    const scope = scopeText.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    const started: Started[] = [];
    for (const t of targets) {
      const r = await startScan({ target: t, mode, scope, chainLimit });
      started.push(r.ok ? { target: t, id: r.id } : { target: t, error: r.error });
    }
    setBusy(false);
    if (!bulk && started[0]?.id) {
      router.push(`/scans/${started[0].id}`);
      return;
    }
    setBatch(started);
  }

  useEffect(() => {
    const t = params.get("target");
    if (t && !auto.current) {
      auto.current = true;
      setInput(t);
      void run(t);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  // Follows the batch until every scan has finished.
  useEffect(() => {
    if (!batch.length) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      const list = await listScans();
      if (stopped) return;
      const map: Record<string, ScanSummary> = {};
      list.forEach((s) => (map[s.id] = s));
      setSummaries(map);
      const pending = batch.some((b) => b.id && (!map[b.id] || map[b.id].status === "running"));
      if (pending) timer = setTimeout(tick, 2000);
    };
    void tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [batch]);

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.fullscan({ size: 22 })}</div>
        <div>
          <h1>Full Scan</h1>
          <p>
            Runs the target modules, then scans every live subdomain it finds (the chain), and port-scans each address once. The scan runs on the server: you can open other pages, and it stays in{" "}
            <Link className="value-link" href="/history">History</Link>.
          </p>
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
              {busy ? "Starting…" : "Run Full Scan"}
            </button>
          </form>
        )}
        {bulk && (
          <div style={{ marginTop: 10 }}>
            <button type="button" className="btn-primary" disabled={busy} onClick={() => run()}>
              {busy ? "Starting…" : `Scan ${splitTargets(input).length || ""} targets`}
            </button>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, marginTop: 14 }}>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Scope (optional): only these domains and their subdomains are scanned</span>
            <input value={scopeText} onChange={(e) => setScopeText(e.target.value)} placeholder="example.com, example.org" aria-label="Scope" />
          </label>
          <label className="stack" style={{ gap: 6 }}>
            <span className="muted small">Live subdomains to chain (0 turns the chain off)</span>
            <input type="number" min={0} max={50} value={chainLimit} onChange={(e) => setChainLimit(Math.max(0, Math.min(50, Number(e.target.value) || 0)))} aria-label="Chain limit" />
          </label>
        </div>

        <div className="recent" style={{ marginTop: 10 }}>
          {mode === "passive" ? "Passive mode sends nothing to the target." : "Active modules send requests to the target. Use only on systems you are authorized to test."} Modules this mode runs on the target: {expectedModules.length}.
        </div>
      </section>

      {error && <Alert kind="bad">{error}</Alert>}
      {(mode === "active" || mode === "full") && <Alert kind="warn" title="Active scan">This includes modules that send requests to the target (port scan, HTTP fingerprint, directory finder, admin panels, exposure checks). Only run against systems you are authorized to test.</Alert>}

      {batch.length > 0 && (
        <section className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-head">
            <h3>Started scans</h3>
            <span className="count">{batch.length}</span>
          </div>
          <div className="table-wrap">
            <table className="dt">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Findings</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {batch.map((b) => {
                  const s = b.id ? summaries[b.id] : undefined;
                  const st = s ? STATUS[s.status] : undefined;
                  return (
                    <tr key={b.target}>
                      <td className="value">{b.target}</td>
                      <td>{b.error ? <Badge kind="bad">{b.error}</Badge> : st ? <Badge kind={st.kind}>{st.label}</Badge> : <Badge>starting</Badge>}</td>
                      <td className="muted small">{s ? `${s.stage} · ${s.done}/${s.total}` : "—"}</td>
                      <td className="muted small">{s?.counts ? `${s.counts.high} high · ${s.counts.medium} medium` : "—"}</td>
                      <td>{b.id && <Link className="value-link" href={`/scans/${b.id}`}>Open</Link>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
