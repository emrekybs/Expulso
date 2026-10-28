"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { MODULES, GROUPS } from "@/lib/modules-config";
import { parseTarget, KIND_LABEL } from "@/lib/target";
import { getHistory, type HistoryItem } from "@/lib/client/api";
import { moduleIcon } from "./icons";

export default function Overview() {
  const router = useRouter();
  const [target, setTarget] = useState("example.com");
  const [history, setHistory] = useState<HistoryItem[]>([]);

  useEffect(() => setHistory(getHistory()), []);

  const parsed = parseTarget(target);
  const kind = "error" in parsed ? null : parsed.kind;

  function go(e: React.FormEvent) {
    e.preventDefault();
    sessionStorage.setItem("recon:lastTarget", target);
    router.push(`/full-scan?target=${encodeURIComponent(target)}`);
  }

  return (
    <div className="stack">
      <section className="card hero">
        <h1>
          Domain recon, <span className="accent">in one place</span>
        </h1>
        <p>Enter a domain, IP, range or URL and run a full scan or a single module. All sources are keyless; results stay in this workspace and export as JSON or CSV.</p>
        <form className="search-row" onSubmit={go}>
          <div className="search-input">
            <span className="si-icon">{moduleIcon("subdomains", 18)}</span>
            <input value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Target" placeholder="example.com" />
            {kind && <span style={{ position: "absolute", right: 12, top: 13, fontSize: 11.5, padding: "2px 9px", borderRadius: 6, background: "var(--info-bg)", color: "var(--info)", fontWeight: 600 }}>{KIND_LABEL[kind]}</span>}
          </div>
          <button type="submit" className="btn-primary">Full Scan</button>
        </form>
        <div className="recent">
          Jump to a module:
          <Link className="chip" href="/m/subdomains">Subdomains</Link>
          <Link className="chip" href="/m/dns">DNS</Link>
          <Link className="chip" href="/m/whois">WHOIS</Link>
          <Link className="chip" href="/m/geoip">GeoIP &amp; ASN</Link>
          <Link className="chip" href="/m/osint">OSINT</Link>
          <Link className="chip" href="/m/waf">WAF / CDN</Link>
        </div>
      </section>

      {history.length > 0 && (
        <section className="card" >
          <div className="card-head">
            <h3>Recent</h3>
            <span className="count">{history.length}</span>
          </div>
          <div className="table-wrap">
            <table className="dt">
              <thead><tr><th>Target</th><th>Module</th><th>Summary</th><th>When</th></tr></thead>
              <tbody>
                {history.slice(0, 10).map((h, i) => (
                  <tr key={i}>
                    <td className="value">{h.target}</td>
                    <td><Link className="value-link" href={h.module === "overview" ? "/full-scan" : `/m/${h.module}`}>{h.label}</Link></td>
                    <td className="muted">{h.summary || "—"}</td>
                    <td className="muted">{new Date(h.at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

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

      <p className="disclaimer">Built for authorized security research and threat intelligence work.</p>
    </div>
  );
}
