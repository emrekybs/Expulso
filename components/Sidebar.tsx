"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { MODULES, GROUPS, type Group } from "@/lib/modules-config";
import { Icon, moduleIcon } from "./icons";

export default function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const pathname = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    try {
      setCollapsed(localStorage.getItem("sidebar") === "collapsed");
    } catch {
      /* ignore */
    }
  }, []);
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

  const active = (href: string) => pathname === href;
  const show = !collapsed;

  async function logout() {
    await fetch("/api/logout", { method: "POST" });
    router.replace("/login");
    router.refresh();
  }

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
          <Item href="/logs" icon={Icon.logs({ size: 18 })} label="Logs" />
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
            </div>
          ))}
        </nav>

        <div className="sidebar-foot" style={collapsed ? { display: "flex", justifyContent: "center" } : { display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 30, height: 30, borderRadius: "50%", background: "var(--surface-3)", color: "var(--brand-blue-2)", display: "grid", placeItems: "center", fontSize: 12, fontWeight: 700, flexShrink: 0 }}>B</span>
          {show && (
            <>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>Signed in</div>
                <div style={{ fontSize: 11, color: "var(--muted)" }}>Keyless sources</div>
              </div>
              <button type="button" className="icon-btn" style={{ width: 34, height: 34 }} onClick={logout} title="Sign out" aria-label="Sign out">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="m16 17 5-5-5-5" /><path d="M21 12H9" /></svg>
              </button>
            </>
          )}
        </div>
      </aside>
    </>
  );
}
