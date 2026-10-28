"use client";
import type { Assessment } from "@/lib/assessment";
import { Card, Badge } from "./ui";

export default function AssessmentCard({ a }: { a: Assessment }) {
  const color = a.grade.startsWith("A") ? "var(--ok)" : a.grade === "B" ? "var(--brand-blue)" : a.grade === "C" ? "var(--warn)" : "var(--bad)";
  return (
    <Card title="Assessment" actions={<Badge kind={a.counts.high ? "bad" : a.counts.medium ? "orange" : "ok"}>{a.counts.high} high · {a.counts.medium} medium</Badge>}>
      <div style={{ display: "flex", gap: 20, alignItems: "center", flexWrap: "wrap" }}>
        <div className="grade-badge" style={{ border: `8px solid ${color}` }}>
          <div>
            <div style={{ fontSize: 30, fontWeight: 800, color }}>{a.grade}</div>
            <div className="muted small">{a.score}/100</div>
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 240 }}>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>{a.headline}</div>
          <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-2)", fontSize: 13, lineHeight: 1.7 }}>
            {a.lines.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </div>
      </div>
      {a.priorities.length > 0 && (
        <div style={{ marginTop: 18 }}>
          <div className="muted small" style={{ textTransform: "uppercase", letterSpacing: "0.6px", marginBottom: 6 }}>Top priorities</div>
          {a.priorities.map((p, i) => (
            <div key={i} className="list-item" style={{ padding: "8px 0" }}>
              <Badge kind={p.severity === "high" ? "bad" : p.severity === "medium" ? "orange" : p.severity === "low" ? "warn" : "info"}>{p.severity}</Badge>
              <span style={{ flex: 1, minWidth: 0 }}>{p.title}</span>
              <span className="muted small">{p.module}</span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
