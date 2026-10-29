"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { MODULES, GROUPS, type Group } from "@/lib/modules-config";
import { listScans } from "@/lib/client/api";
import type { ScanSummary } from "@/lib/scan-types";
import { Icon, moduleIcon } from "./icons";

const DOT: Record<ScanSummary["status"], string> = { running: "var(--warn)", done: "var(--ok)", failed: "var(--bad)" };

export default function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [recent, setRecent] = useState<ScanSummary[]>([]);

  useEffect(() => {
    try {
      setCollapsed(localStorage.getItem("sidebar") === "collapsed");
    } catch {
      /* ignore */
    }
  }, []);

  // Refreshed on every page change, so a scan started elsewhere shows up without a reload.
  useEffect(() => {
    let alive = true;
    void listScans().then((list) => alive && setRecent(list.slice(0, 5)));
    return () => {
      alive = false;
    };
  }, [pathname]);

  function toggleCollapse() {
    setCollapsed((c) => {
      const n = !c;
      try {
        localStorage.setItem("sidebar", n ? "collapsed" : "open");
      } catch {
        /* ignore */
      }
      return n;
    });
  }

  const active = (href: string) => pathname === href || (href !== "/" && pathname.startsWith(`${href}/`));
  const show = !collapsed;

  const Item = ({ href, icon, label, tier }: { href: string; icon: React.ReactNode; label: string; tier?: string }) => (
    <Link href={href} className={`nav-link${active(href) ? " active" : ""}`} title={label} onClick={onClose} style={collapsed ? { justifyContent: "center", padding: 0, width: 44, minHeight: 44, margin: "0 auto" } : undefined}>
      <span className="nav-icon">{icon}</span>
      {show && <span>{label}</span>}
      {show && tier === "active" && <span className="tier active" style={{ marginLeft: "auto" }}>Active</span>}
    </Link>
  );

  return (
    <>
      <div className={`backdrop${open ? " open" : ""}`} onClick={onClose} />
      <aside className={`sidebar${open ? " open" : ""}`} style={{ width: collapsed ? 72 : 268 }}>
        <div className="sidebar-head" style={collapsed ? { display: "flex", flexDirection: "column", alignItems: "center", gap: 10 } : { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
          {/* eslint-disable @next/next/no-img-element */}
          <img src="/logo-dark.png" alt="Logo" className="brand-logo logo-dark" style={{ width: collapsed ? 46 : 128 }} />
          <img src="/logo.png" alt="Logo" className="brand-logo logo-light" style={{ width: collapsed ? 46 : 128 }} />
          {/* eslint-enable @next/next/no-img-element */}
          <button type="button" className="icon-btn" style={{ width: 34, height: 34 }} onClick={toggleCollapse} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} title={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            {collapsed ? Icon.menu({ size: 17 }) : <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden><rect width="18" height="18" x="3" y="3" rx="2" /><path d="M9 3v18" /><path d="m16 15-3-3 3-3" /></svg>}
          </button>
        </div>
        {show && <div className="brand-bar" style={{ margin: "0 18px" }} />}

        <nav className="nav">
          <Item href="/" icon={Icon.overview({ size: 18 })} label="Overview" />
          <Item href="/full-scan" icon={Icon.fullscan({ size: 18 })} label="Full Scan" />
          <Item href="/history" icon={Icon.history({ size: 18 })} label="History" />
          {show &&
            recent.map((s) => (
              <Link key={s.id} href={`/scans/${s.id}`} onClick={onClose} className={`nav-link${pathname === `/scans/${s.id}` ? " active" : ""}`} title={s.target} style={{ paddingLeft: 40, minHeight: 32, fontSize: 12.5 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: DOT[s.status], flexShrink: 0 }} />
                <span className="wrap-anywhere" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.target}</span>
              </Link>
            ))}
          <Item href="/assets" icon={Icon.search({ size: 18 })} label="Asset Inventory" />
          {GROUPS.map((g: Group) => (
            <div className="nav-group" key={g}>
              {show ? (
                <div className="nav-group-title">
                  {g === "Active" ? (
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                      {g} <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--brand-orange)" }} />
                    </span>
                  ) : (
                    g
                  )}
                </div>
              ) : (
                <div style={{ height: 1, background: "var(--border)", margin: "10px 8px" }} />
              )}
              {MODULES.filter((m) => m.group === g).map((m) => (
                <Item key={m.id} href={`/m/${m.id}`} icon={moduleIcon(m.id, 18)} label={m.title} tier={m.tier} />
              ))}
              {g === "Vulnerability" && (
                <>
                  <Item href="/dalfox" icon={Icon.search({ size: 18 })} label="Dalfox (XSS)" />
                  <Item href="/sqli" icon={Icon.search({ size: 18 })} label="SQL Injection" />
                  <Item href="/nuclei" icon={Icon.search({ size: 18 })} label="Nuclei" />
                </>
              )}
            </div>
          ))}
          <div className="nav-group">
            <Item href="/tools" icon={Icon.tools({ size: 18 })} label="Tools" />
            <Item href="/settings" icon={Icon.overview({ size: 18 })} label="Settings" />
            <Item href="/logs" icon={Icon.logs({ size: 18 })} label="Logs" />
          </div>
        </nav>

        <div className="sidebar-foot" style={collapsed ? { display: "flex", justifyContent: "center" } : { display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 30, height: 30, borderRadius: "50%", background: "var(--surface-3)", color: "var(--brand-blue-2)", display: "grid", placeItems: "center", fontSize: 12, fontWeight: 700, flexShrink: 0 }}>B</span>
          {show && (
            <>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>Local workspace</div>
                <div style={{ fontSize: 11, color: "var(--muted)" }}>No API keys needed</div>
              </div>
            </>
          )}
        </div>
      </aside>
    </>
  );
}
