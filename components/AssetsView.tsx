"use client";
import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { MODE_LABEL, type ScanMode } from "@/lib/modules-config";
import { parseTarget } from "@/lib/target";
import { runFullScan, pushHistory, type FullScanResponse } from "@/lib/client/api";
import { buildInventory } from "@/lib/inventory";
import { Alert, Card, Stat } from "./ui";
import InventoryCard from "./InventoryCard";
import AssessmentCard from "./AssessmentCard";
import { computeAssessment } from "@/lib/assessment";
import { Icon } from "./icons";

function AssetsInner() {
  const params = useSearchParams();
  const [target, setTarget] = useState(params.get("target") ?? "");
  const [mode, setMode] = useState<ScanMode>("full");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [res, setRes] = useState<FullScanResponse | null>(null);

  async function run(e?: React.FormEvent) {
    e?.preventDefault();
    const p = parseTarget(target);
    if ("error" in p) return setError(p.error);
    setError("");
    setBusy(true);
    setRes(null);
    const r = await runFullScan(target.trim(), mode);
    setRes(r);
    setBusy(false);
    if (r.ok) pushHistory({ target: p.host, module: "overview", label: `Asset inventory (${mode})`, summary: r.counts ? `${r.counts.high} high findings` : undefined });
    if (!r.ok) setError(r.error || "Scan failed.");
  }

  const inv = res?.ok && res.modules ? buildInventory(res.modules) : null;
  const assessment = res?.ok && res.modules ? computeAssessment(res.modules) : null;

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.search({ size: 22 })}</div>
        <div>
          <h1>Asset Inventory</h1>
          <p>Every asset the modules find for a domain, grouped into 11 categories: subdomains, IP addresses, open ports, web apps, directories, admin panels, API endpoints, exposed services, cloud assets, sensitive files and certificates. Reconnaissance only: no vulnerability tests (no XSS, SQLi or similar) are run.</p>
        </div>
      </div>

      <section className="card search-card">
        <form className="search-row" onSubmit={run}>
          <div className="search-input">
            <span className="si-icon">{Icon.search({ size: 18 })}</span>
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" aria-label="Target" />
          </div>
          <button type="submit" className="btn-primary" disabled={busy}>{busy ? "Discovering…" : "Discover assets"}</button>
        </form>
        <div className="result-bar" style={{ marginTop: 12, marginBottom: 0 }}>
          <div className="seg">
            {(["passive", "active", "full"] as ScanMode[]).map((m) => (
              <button key={m} type="button" className={mode === m ? "on" : ""} onClick={() => setMode(m)}>{MODE_LABEL[m]}</button>
            ))}
          </div>
          <span className="rb-meta">Passive: no packets to the target · Active: adds light and active discovery</span>
        </div>
      </section>

      {error && <Alert kind="bad">{error}</Alert>}
      {busy && <div className="card loading-card">{Icon.search({ size: 20 })}<div style={{ flex: 1 }}><div>Discovering assets for {target}…</div><div className="progress"><div /></div></div></div>}

      {res?.ok && inv && assessment && (
        <>
          <div className="grid grid-4">
            <Stat label="Assets" value={Object.values(inv).reduce((a, b) => a + b.length, 0)} accent="blue" />
            <Stat label="Subdomains" value={inv.subdomain.length} accent="silver" />
            <Stat label="IP addresses" value={inv.ip.length} accent="silver" />
            <Stat label="Admin panels" value={inv.admin.length} accent={inv.admin.length ? "orange" : "green"} />
          </div>
          <InventoryCard inv={inv} target={res.meta?.target} />
          <AssessmentCard a={assessment} />
        </>
      )}
    </div>
  );
}

export default function AssetsView() {
  return (
    <Suspense fallback={null}>
      <AssetsInner />
    </Suspense>
  );
}
