"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { MODE_LABEL } from "@/lib/modules-config";
import type { ScanRecord } from "@/lib/scan-types";
import { buildHtmlReport } from "@/lib/client/report";
import { download, stamp, slug } from "@/lib/client/export";
import { deleteScan, downloadPdf, toFullScanResponse, waitForScan } from "@/lib/client/api";
import { Alert, Badge, Card } from "./ui";
import ScanResult from "./ScanResult";
import { Icon } from "./icons";

const STATUS_KIND: Record<ScanRecord["status"], "ok" | "warn" | "bad"> = { running: "warn", done: "ok", failed: "bad" };

export default function ScanDetailView({ id }: { id: string }) {
  const router = useRouter();
  const [rec, setRec] = useState<ScanRecord | null>(null);
  const [missing, setMissing] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let alive = true;
    void (async () => {
      const r = await waitForScan(id, (x) => alive && setRec(x), 1500, () => alive);
      if (!alive) return;
      if (!r) setMissing(true);
      else setRec(r);
    })();
    return () => {
      alive = false;
    };
  }, [id]);

  if (missing) {
    return (
      <Alert kind="bad" title="Scan not found">
        It may have been deleted. <Link className="value-link" href="/history">Back to history</Link>
      </Alert>
    );
  }
  if (!rec) {
    return (
      <div className="card loading-card">
        {Icon.fullscan({ size: 20 })}
        <div style={{ flex: 1 }}>Loading scan…</div>
      </div>
    );
  }

  const pct = rec.total ? Math.min(100, Math.round((rec.done / rec.total) * 100)) : 0;
  const report = () => buildHtmlReport([{ target: rec.target, res: toFullScanResponse(rec) }], rec.mode);
  const base = `full_scan_${slug(rec.target)}_${stamp()}`;

  async function exportPdf() {
    setMessage("");
    const r = await downloadPdf(report(), `${base}.pdf`);
    if (!r.ok) setMessage(r.error ?? "PDF failed.");
  }
  function exportCsv() {
    const rows = rec!.findings.map((f) => ({ target: rec!.target, severity: f.severity, module: f.module, title: f.title, detail: f.detail, recommendation: f.recommendation ?? "" }));
    const cols = Object.keys(rows[0] ?? { target: "", severity: "", module: "", title: "", detail: "", recommendation: "" });
    const esc = (v: unknown) => {
      const s = v == null ? "" : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    download(`${base}_findings.csv`, [cols.join(","), ...rows.map((r) => cols.map((c) => esc((r as Record<string, unknown>)[c])).join(","))].join("\n"), "text/csv");
  }
  async function remove() {
    if (!window.confirm(`Delete the saved scan of ${rec!.target}? This cannot be undone.`)) return;
    const r = await deleteScan(rec!.id);
    if (r.ok) router.push("/history");
    else setMessage(r.error ?? "Delete failed.");
  }

  const finished = rec.status !== "running";

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.fullscan({ size: 22 })}</div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <h1 className="wrap-anywhere">{rec.target}</h1>
          <div className="chips">
            <Badge kind={STATUS_KIND[rec.status]}>{rec.status}</Badge>
            <span className="chip">{MODE_LABEL[rec.mode]}</span>
            <span className="chip">{rec.kind}</span>
            <span className="chip">Started {new Date(rec.startedAt).toLocaleString()}</span>
            {rec.finishedAt && <span className="chip">Took {Math.max(1, Math.round((new Date(rec.finishedAt).getTime() - new Date(rec.startedAt).getTime()) / 1000))} s</span>}
            {rec.scope?.length ? <span className="chip">Scope: {rec.scope.join(", ")}</span> : null}
          </div>
        </div>
        {finished && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button type="button" className="btn btn-sm" onClick={exportPdf}>PDF report</button>
            <button type="button" className="btn btn-sm" onClick={() => download(`${base}.html`, report(), "text/html")}>HTML report</button>
            <button type="button" className="btn btn-sm" onClick={() => download(`${base}.json`, JSON.stringify(rec, null, 2), "application/json")}>JSON</button>
            <button type="button" className="btn btn-sm" onClick={exportCsv}>CSV</button>
            <button type="button" className="btn btn-sm" onClick={remove}>Delete</button>
          </div>
        )}
      </div>

      {message && <Alert kind="bad">{message}</Alert>}

      {!finished && (
        <Card title="Scanning" count={`${rec.done}/${rec.total}`}>
          <div className="stack" style={{ gap: 10 }}>
            <div className="muted">{rec.stage}</div>
            <div className="progress"><div style={{ width: `${pct}%` }} /></div>
            <div className="muted small">
              You can leave this page: the scan keeps running on the server and stays in History.
            </div>
          </div>
        </Card>
      )}
      {!finished && rec.modules.length > 0 && (
        <Card title="Finished so far" count={rec.modules.length} pad={false}>
          {rec.modules.map((m) => (
            <div key={m.id} className="list-item">
              <Badge kind={m.ok ? "ok" : "bad"}>{m.ok ? "ok" : "failed"}</Badge>
              <span className="value">{m.title}</span>
              <span className="muted small" style={{ marginLeft: "auto" }}>{m.ok ? m.summary : m.error}</span>
            </div>
          ))}
        </Card>
      )}

      {rec.status === "failed" && <Alert kind="bad" title="Scan stopped">{rec.error}</Alert>}
      {rec.warnings.length > 0 && <Alert kind="warn">{rec.warnings.join(" ")}</Alert>}

      {finished && <ScanResult rec={rec} />}
    </div>
  );
}
