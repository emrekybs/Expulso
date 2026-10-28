"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { MODULES, GROUPS, MODE_LABEL } from "@/lib/modules-config";
import { parseTarget, KIND_LABEL } from "@/lib/target";
import { listScans } from "@/lib/client/api";
import type { ScanSummary } from "@/lib/scan-types";
import { moduleIcon } from "./icons";
import { Card, Badge, Stat } from "./ui";

interface ToolLite {
  name: string;
  status: "ok" | "missing" | "error";
}

export default function Overview() {
  const router = useRouter();
  const [target, setTarget] = useState("example.com");
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [tools, setTools] = useState<ToolLite[] | null>(null);

  useEffect(() => {
    void listScans().then(setScans);
    fetch("/api/tools", { cache: "no-store" })
      .then((r) => r.json())
      .then((j: { tools?: ToolLite[] }) => setTools(j.tools ?? []))
      .catch(() => setTools([]));
  }, []);

  const parsed = parseTarget(target);
  const kind = "error" in parsed ? null : parsed.kind;

  function go(e: React.FormEvent) {
    e.preventDefault();
    router.push(`/full-scan?target=${encodeURIComponent(target)}`);
  }

  const done = scans?.filter((s) => s.status === "done") ?? [];
  const highTotal = done.reduce((n, s) => n + (s.counts?.high ?? 0), 0);
  const running = scans?.filter((s) => s.status === "running").length ?? 0;
  const installed = tools?.filter((t) => t.status === "ok").length ?? 0;
  const broken = tools?.filter((t) => t.status === "error").length ?? 0;

  return (
    <div className="stack">
      <section className="card hero">
        <h1>
          Domain recon, <span className="accent">in one place</span>
        </h1>
        <p>Enter a domain, IP, range or URL. A Full Scan finds subdomains, scans the live ones, checks ports and exports a PDF or HTML report. Everything runs on this computer.</p>
        <form className="search-row" onSubmit={go}>
          <div className="search-input">
            <span className="si-icon">{moduleIcon("subdomains", 18)}</span>
            <input value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Target" placeholder="example.com" />
            {kind && <span style={{ position: "absolute", right: 12, top: 13, fontSize: 11.5, padding: "2px 9px", borderRadius: 6, background: "var(--info-bg)", color: "var(--info)", fontWeight: 600 }}>{KIND_LABEL[kind]}</span>}
          </div>
          <button type="submit" className="btn-primary">Full Scan</button>
        </form>
        <div className="recent">
          Or go straight to one module:
          <Link className="chip" href="/m/subdomains">Subdomains</Link>
          <Link className="chip" href="/m/ports-scan">Port Scan</Link>
          <Link className="chip" href="/m/url-archive">Archived URLs</Link>
          <Link className="chip" href="/m/cloud-buckets">Cloud Buckets</Link>
          <Link className="chip" href="/m/dirs">Directories</Link>
        </div>
      </section>

      <div className="grid grid-4">
        <Stat label="Scans saved" value={scans?.length ?? "—"} sub={running ? `${running} running now` : "history on the History page"} accent="silver" />
        <Stat label="High findings (all scans)" value={highTotal} accent={highTotal ? "orange" : "green"} />
        <Stat label="Tools installed" value={tools ? `${installed}/${tools.length}` : "—"} sub={broken ? `${broken} with errors` : "see the Tools page"} accent="blue" />
        <Stat label="Modules" value={MODULES.length} sub="passive, light and active" accent="silver" />
      </div>

      <Card
        title="Recent scans"
        count={scans?.length ?? 0}
        actions={
          <Link className="value-link" href="/history">
            View all
          </Link>
        }
        pad={false}
      >
        {!scans ? (
          <div className="card-body muted">Loading…</div>
        ) : scans.length === 0 ? (
          <div className="card-body muted">No scans yet. Enter a domain above to start your first Full Scan.</div>
        ) : (
          <div className="table-wrap">
            <table className="dt">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 8).map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Link className="value-link wrap-anywhere" href={`/scans/${s.id}`}>
                        {s.target}
                      </Link>
                    </td>
                    <td className="muted small">{MODE_LABEL[s.mode]}</td>
                    <td>{s.status === "running" ? <Badge kind="warn">{s.done}/{s.total}</Badge> : s.status === "done" ? <Badge kind="ok">done</Badge> : <Badge kind="bad">failed</Badge>}</td>
                    <td className="small">{s.counts ? `${s.counts.high} high · ${s.counts.medium} medium` : "—"}</td>
                    <td className="muted small">{new Date(s.startedAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {GROUPS.map((g) => (
        <div key={g}>
          <div className="section-title">
            {g}
            {g === "Active" && <span className="muted" style={{ textTransform: "none", letterSpacing: 0, fontWeight: 400 }}>— these send requests to the target</span>}
          </div>
          <div className="grid grid-3">
            {MODULES.filter((m) => m.group === g).map((m) => (
              <Link key={m.id} href={`/m/${m.id}`} className="card module-card">
                <span className="page-icon" style={{ width: 38, height: 38, borderRadius: 10 }}>{moduleIcon(m.id, 18)}</span>
                <div style={{ minWidth: 0 }}>
                  <h4>
                    {m.title} <span className={`tier ${m.tier}`}>{m.tier === "passive" ? "Passive" : m.tier === "light" ? "Light" : "Active"}</span>
                  </h4>
                  <p>{m.description}</p>
                </div>
              </Link>
            ))}
          </div>
        </div>
      ))}

      <p className="disclaimer">Built for authorized security research and threat intelligence work. Missing external tools are listed on the Tools page with install commands.</p>
    </div>
  );
}
