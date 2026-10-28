"use client";
import { useMemo, useState } from "react";
import { ASSET_CATEGORIES, inventoryCounts, type Inventory, type AssetKey } from "@/lib/inventory";
import { Card, DataTable, CopyBtn, type Column } from "./ui";
import type { Asset } from "@/lib/inventory";

export default function InventoryCard({ inv, title = "Asset inventory", target }: { inv: Inventory; title?: string; target?: string }) {
  const counts = useMemo(() => inventoryCounts(inv), [inv]);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const [active, setActive] = useState<AssetKey>(() => ASSET_CATEGORIES.find((c) => counts[c.key] > 0)?.key ?? "subdomain");
  const cat = ASSET_CATEGORIES.find((c) => c.key === active)!;
  const rows: Asset[] = inv[active];
  const cols: Column<Asset>[] = [
    { key: "label", header: cat.label, render: (r) => <span className="value wrap-anywhere">{r.url ? <a className="value-link" href={r.url} target="_blank" rel="noreferrer noopener">{r.label}</a> : r.label}</span>, value: (r) => r.label, sortable: true },
    { key: "detail", header: "Detail", render: (r) => <span className="muted small wrap-anywhere">{r.detail || "—"}</span> },
    { key: "source", header: "Found by", render: (r) => <span className="muted small">{r.source}</span> },
  ];
  return (
    <Card title={title} count={`${total} assets${target ? ` · ${target}` : ""}`} actions={<CopyBtn text={rows.map((r) => r.label).join("\n")} label="Copy list" />} pad={false}>
      <div className="card-body" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: 8 }}>
        {ASSET_CATEGORIES.map((c) => (
          <button key={c.key} type="button" aria-pressed={active === c.key} onClick={() => setActive(c.key)} className={`chip${active === c.key ? "" : ""}`} style={{ justifyContent: "space-between", cursor: "pointer", background: active === c.key ? "var(--brand-blue)" : undefined, borderColor: active === c.key ? "var(--brand-blue)" : undefined, color: active === c.key ? "#fff" : undefined, padding: "8px 10px" }}>
            <span style={{ fontWeight: 600 }}>{c.label}</span>
            <span style={{ fontSize: 12, opacity: counts[c.key] ? 1 : 0.5 }}>{counts[c.key]}</span>
          </button>
        ))}
      </div>
      <div className="muted small" style={{ padding: "10px 18px 0" }}>{cat.hint}</div>
      <DataTable rows={rows} columns={cols} filterKeys={(r) => `${r.label} ${r.detail ?? ""} ${r.source}`} empty={`No ${cat.label.toLowerCase()} assets found in the modules that ran.`} />
    </Card>
  );
}
