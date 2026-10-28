"use client";
import { useState } from "react";
import type { Finding, Severity } from "@/lib/types";
import { Icon } from "./icons";
import { copyText } from "@/lib/client/export";

export function Badge({ kind, children }: { kind?: "ok" | "warn" | "bad" | "info" | "orange"; children: React.ReactNode }) {
  return <span className={`badge${kind ? ` ${kind}` : ""}`}>{children}</span>;
}

const SEV_KIND: Record<Severity, "bad" | "orange" | "warn" | "info"> = { high: "bad", medium: "orange", low: "warn", info: "info" };
const SEV_LABEL: Record<Severity, string> = { high: "High", medium: "Medium", low: "Low", info: "Info" };

export function SeverityBadge({ s }: { s: Severity }) {
  return <Badge kind={SEV_KIND[s]}>{SEV_LABEL[s]}</Badge>;
}

export function Card({ title, count, actions, icon, children, pad }: { title?: React.ReactNode; count?: number | string; actions?: React.ReactNode; icon?: React.ReactNode; children: React.ReactNode; pad?: boolean }) {
  return (
    <section className="card">
      {title && (
        <div className="card-head">
          {icon && <span className="ch-icon">{icon}</span>}
          <h3>{title}</h3>
          {count != null && <span className="count">{count}</span>}
          {actions && <span className="actions">{actions}</span>}
        </div>
      )}
      <div className={pad === false ? "" : "card-body"}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, sub, accent }: { label: string; value: React.ReactNode; sub?: React.ReactNode; accent?: "blue" | "orange" | "green" | "silver" }) {
  return (
    <div className={`card stat accent-${accent ?? "blue"}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub != null && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Findings({ items }: { items: Finding[] }) {
  if (!items.length)
    return (
      <Card title="Findings" count={0}>
        <div className="empty" style={{ padding: 20 }}>
          <div className="muted">No notable findings.</div>
        </div>
      </Card>
    );
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  items.forEach((f) => counts[f.severity]++);
  return (
    <Card
      title="Findings"
      actions={
        <span style={{ display: "flex", gap: 6 }}>
          {(["high", "medium", "low", "info"] as Severity[]).filter((s) => counts[s]).map((s) => (
            <Badge key={s} kind={SEV_KIND[s]}>
              {counts[s]} {SEV_LABEL[s]}
            </Badge>
          ))}
        </span>
      }
      pad={false}
    >
      {items.map((f, i) => (
        <div key={i} className="check-row" style={{ gridTemplateColumns: "84px minmax(0,1fr)" }}>
          <SeverityBadge s={f.severity} />
          <div>
            <div className="cr-title">{f.title}</div>
            <div className="cr-detail">{f.detail}</div>
            {f.evidence && <div className="cr-value" style={{ whiteSpace: "pre-line" }}>{f.evidence}</div>}
            {f.recommendation && (
              <div className="cr-rec">
                <b>Recommendation:</b> {f.recommendation}
              </div>
            )}
          </div>
        </div>
      ))}
    </Card>
  );
}

export function KeyValue({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <div className="kv">
      {rows.filter(([, v]) => v != null && v !== "").map(([k, v], i) => (
        <div className="kv-row" key={i}>
          <div className="kv-key">{k}</div>
          <div className="kv-val">{v}</div>
        </div>
      ))}
    </div>
  );
}

export function CopyBtn({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-sm"
      onClick={async () => {
        if (await copyText(text)) {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }
      }}
    >
      {Icon.copy({ size: 14 })} {done ? "Copied" : label}
    </button>
  );
}

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => React.ReactNode;
  num?: boolean;
  sortable?: boolean;
  value?: (row: T) => string | number;
}

export function DataTable<T>({ rows, columns, filterKeys, pageSize = 50, empty = "No results." }: { rows: T[]; columns: Column<T>[]; filterKeys?: (row: T) => string; pageSize?: number; empty?: string }) {
  const [q, setQ] = useState("");
  const [limit, setLimit] = useState(pageSize);
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);

  let view = rows;
  if (q && filterKeys) {
    const needle = q.toLowerCase();
    view = view.filter((r) => filterKeys(r).toLowerCase().includes(needle));
  }
  if (sort) {
    const col = columns.find((c) => c.key === sort.key);
    if (col?.value) view = [...view].sort((a, b) => (col.value!(a) > col.value!(b) ? sort.dir : col.value!(a) < col.value!(b) ? -sort.dir : 0));
  }
  const shown = view.slice(0, limit);

  return (
    <>
      {filterKeys && (
        <div className="table-tools">
          <div className="table-filter">
            {Icon.search({ size: 15 })}
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter…" aria-label="Filter results" />
          </div>
          <span className="muted small">{view.length} rows</span>
        </div>
      )}
      <div className="table-wrap">
        <table className="dt">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={`${c.num ? "num" : ""} ${c.sortable && c.value ? "sortable" : ""}`} onClick={() => c.sortable && c.value && setSort((s) => ({ key: c.key, dir: s?.key === c.key && s.dir === 1 ? -1 : 1 }))}>
                  {c.header}
                  {sort?.key === c.key ? (sort.dir === 1 ? " ▲" : " ▼") : ""}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.length === 0 && (
              <tr>
                <td colSpan={columns.length} style={{ textAlign: "center", color: "var(--muted)", padding: 24 }}>
                  {empty}
                </td>
              </tr>
            )}
            {shown.map((row, i) => (
              <tr key={i}>
                {columns.map((c) => (
                  <td key={c.key} className={c.num ? "num" : ""}>
                    {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? "")}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {view.length > limit && (
        <div className="table-foot">
          <button type="button" className="btn btn-sm" onClick={() => setLimit((l) => l + pageSize)}>
            Show more ({view.length - limit} left)
          </button>
        </div>
      )}
    </>
  );
}

export function Chips<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: { value: T; label: string; count?: number; warn?: boolean }[] }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={value === o.value} onClick={() => onChange(o.value)} className="chip" style={value === o.value ? { background: "var(--brand-blue)", borderColor: "var(--brand-blue)", color: "#fff" } : o.warn ? { borderColor: "#6b3a14", color: "var(--brand-orange-2)" } : undefined}>
          {o.label}
          {o.count != null && <span style={{ opacity: 0.8 }}>{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Alert({ kind, title, children }: { kind: "bad" | "warn" | "info"; title?: string; children: React.ReactNode }) {
  const icon = kind === "bad" ? <path d="M18 6 6 18M6 6l12 12" /> : kind === "warn" ? <><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" /><path d="M12 9v4M12 17h.01" /></> : <><circle cx="12" cy="12" r="10" /><path d="M12 16v-4M12 8h.01" /></>;
  return (
    <div className={`alert ${kind}`}>
      <svg className="alert-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        {icon}
      </svg>
      <div>
        {title && <strong>{title}</strong>}
        <span>{children}</span>
      </div>
    </div>
  );
}
