"use client";
import { useEffect, useState } from "react";
import { Alert, Badge, Card, Findings } from "./ui";
import type { PipelineRecord } from "@/lib/autopipe";
import type { Finding } from "@/lib/types";

const STATUS_KIND: Record<string, "ok" | "warn" | "bad" | undefined> = { done: "ok", running: "warn", failed: "bad", skipped: undefined, pending: undefined };

export default function AutopipeRunView({ id }: { id: string }) {
  const [run, setRun] = useState<PipelineRecord | null>(null);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      const res = await fetch(`/api/autopipe/${encodeURIComponent(id)}`, { cache: "no-store" });
      const json = (await res.json()) as { ok: boolean; run?: PipelineRecord };
      if (!alive) return;
      if (!json.ok || !json.run) {
        setMissing(true);
        return;
      }
      setRun(json.run);
      if (json.run.status === "queued" || json.run.status === "running") timer = setTimeout(tick, 2000);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [id]);

  if (missing) return <Alert kind="bad" title="Run not found">It may have been deleted.</Alert>;
  if (!run) return <div className="card loading-card"><div>Loading run…</div></div>;

  const findings: Finding[] = run.stages.flatMap((s) => s.findings.map((f) => ({ ...f, title: `${f.title}`, detail: f.detail })));

  return (
    <div className="stack">
      <div className="page-head">
        <div style={{ flex: 1, minWidth: 0 }}>
          <h1 className="wrap-anywhere">{run.target}</h1>
          <div className="chips">
            <Badge kind={run.status === "done" ? "ok" : run.status === "failed" ? "bad" : "warn"}>{run.status}</Badge>
            <span className="chip">Started {new Date(run.createdAt).toLocaleString()}</span>
            <span className="chip">Filter: {run.request.statusFilter}</span>
            <span className="chip">{run.hosts.length} host(s)</span>
            <span className="chip">{run.selected.length} selected</span>
          </div>
        </div>
      </div>

      {run.error && <Alert kind="bad" title="Run stopped">{run.error}</Alert>}

      <Card title="Stages" pad={false}>
        {run.stages.map((s) => (
          <div key={s.id} className="list-item" style={{ alignItems: "flex-start", flexWrap: "wrap" }}>
            <Badge kind={STATUS_KIND[s.status]}>{s.status}</Badge>
            <div className="li-main" style={{ minWidth: 0, flex: 1 }}>
              <div className="value">{s.title}</div>
              <div className="muted small">{s.engine ? `engine: ${s.engine}` : ""}{s.summary ? ` · ${s.summary}` : ""}</div>
              {s.warnings.length > 0 && <div className="muted small" style={{ marginTop: 4 }}>{s.warnings.join(" ")}</div>}
            </div>
            <Badge>{s.findings.length} finding(s)</Badge>
          </div>
        ))}
      </Card>

      {run.hosts.length > 0 && (
        <Card title="Hosts" count={run.hosts.length} pad={false}>
          <div className="table-wrap">
            <table className="dt">
              <thead>
                <tr><th>Host</th><th>Status</th><th>Title</th><th>Technologies</th><th>Tested</th></tr>
              </thead>
              <tbody>
                {run.hosts.map((h) => (
                  <tr key={h.host}>
                    <td className="value">{h.host}</td>
                    <td>{h.status ?? "—"}</td>
                    <td className="muted small">{h.title || "—"}</td>
                    <td className="muted small">{h.tech.slice(0, 5).join(", ") || "—"}</td>
                    <td>{run.selected.includes(h.host) ? <Badge kind="ok">yes</Badge> : <span className="muted">no</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <Findings items={findings} />
    </div>
  );
}
