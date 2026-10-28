"use client";
import { useEffect, useState } from "react";
import Sidebar from "./Sidebar";
import { Icon } from "./icons";
import { installGlobalErrorCapture } from "@/lib/client/logs";

export default function Shell({ crumb, children }: { crumb: React.ReactNode; children: React.ReactNode }) {
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => installGlobalErrorCapture(), []);

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", cur);
    try {
      localStorage.setItem("theme", cur);
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="shell">
      <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="main">
        <header className="topbar">
          <button type="button" className="icon-btn menu-btn mobile-only" aria-label="Open menu" onClick={() => setNavOpen(true)}>
            {Icon.menu({ size: 18 })}
          </button>
          <div className="crumb">{crumb}</div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 10, alignItems: "center" }}>
            <button type="button" className="icon-btn" aria-label="Toggle theme" onClick={toggleTheme} title="Toggle theme">
              {Icon.moon({ size: 17 })}
            </button>
          </div>
        </header>
        <div className="content">{children}</div>
      </div>
    </div>
  );
}
