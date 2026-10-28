"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { MODE_LABEL } from "@/lib/modules-config";
import type { ScanSummary } from "@/lib/scan-types";
import { deleteScan, listScans } from "@/lib/client/api";
import { Card, Chips, DataTable, Alert, Badge, type Column } from "./ui";
import { Icon } from "./icons";

type StatusFilter = "all" | "running" | "done" | "failed";

export default function HistoryView() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [status, setStatus] = useState<StatusFilter>("all");
  const [message, setMessage] = useState("");

  async function load() {
    setScans(await listScans());
  }

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let alive = true;
    const tick = async () => {
      const list = await listScans();
      if (!alive) return;
      setScans(list);
      if (list.some((s) => s.status === "running")) timer = setTimeout(tick, 3000);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, []);

  async function remove(s: ScanSummary) {
    if (!window.confirm(`Delete the saved scan of ${s.target}?`)) return;
    const r = await deleteScan(s.id);
    if (!r.ok) setMessage(r.error ?? "Delete failed.");
    await load();
  }

  if (!scans) return <div className="card loading-card">{Icon.logs({ size: 20 })}<div>Loading history…</div></div>;

  const counts = {
    all: scans.length,
    running: scans.filter((s) => s.status === "running").length,
    done: scans.filter((s) => s.status === "done").length,
    failed: scans.filter((s) => s.status === "failed").length,
  };
  const rows = scans.filter((s) => status === "all" || s.status === status);

  const cols: Column<ScanSummary>[] = [
    {
      key: "target",
      header: "Target",
      render: (r) => (
        <Link className="value-link wrap-anywhere" href={`/scans/${r.id}`}>
          {r.target}
        </Link>
      ),
      value: (r) => r.target,
      sortable: true,
    },
    { key: "mode", header: "Mode", render: (r) => <span className="muted small">{MODE_LABEL[r.mode]}</span> },
    {
      key: "status",
      header: "Status",
      render: (r) => (r.status === "running" ? <Badge kind="warn">{r.stage} · {r.done}/{r.total}</Badge> : r.status === "done" ? <Badge kind="ok">done</Badge> : <Badge kind="bad" >failed</Badge>),
    },
    {
      key: "findings",
      header: "Findings",
      render: (r) => (r.counts ? <span className="small">{r.counts.high} high · {r.counts.medium} medium · {r.counts.low} low</span> : <span className="muted">—</span>),
    },
    { key: "modules", header: "Modules", num: true, render: (r) => <span className="muted small">{r.modulesOk ?? "—"}/{r.modulesRun ?? "—"}</span> },
    { key: "hosts", header: "Chained hosts", num: true, render: (r) => <span className="muted small">{r.hosts ?? "—"}</span> },
    { key: "startedAt", header: "Started", render: (r) => <span className="muted small">{new Date(r.startedAt).toLocaleString()}</span>, value: (r) => r.startedAt, sortable: true },
    {
      key: "actions",
      header: "",
      render: (r) =>
        r.status === "running" ? null : (
          <button type="button" className="btn btn-sm" onClick={() => remove(r)}>
            Delete
          </button>
        ),
    },
  ];

  return (
    <div className="stack">
      <div className="page-head">
        <div className="page-icon">{Icon.logs({ size: 22 })}</div>
        <div>
          <h1>History</h1>
          <p>Every Full Scan, newest first. Open one to see its full result, export it or delete it. Running scans show live progress.</p>
        </div>
      </div>
      {message && <Alert kind="bad">{message}</Alert>}
      <Card title="Scans" count={rows.length} pad={false}>
        <div className="card-body" style={{ paddingBottom: 0 }}>
          <Chips
            value={status}
            onChange={setStatus}
            options={[
              { value: "all", label: "All", count: counts.all },
              { value: "running", label: "Running", count: counts.running },
              { value: "done", label: "Done", count: counts.done },
              { value: "failed", label: "Failed", count: counts.failed, warn: true },
            ]}
          />
        </div>
        <DataTable rows={rows} columns={cols} filterKeys={(r) => `${r.target} ${r.mode} ${r.status}`} empty="No scans yet. Run a Full Scan to see it here." />
      </Card>
    </div>
  );
}
