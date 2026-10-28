"use client";
import { useState } from "react";
import { MODE_LABEL } from "@/lib/modules-config";
import type { ChildScan, ModuleEntry, ScanRecord } from "@/lib/scan-types";
import { buildInventory } from "@/lib/inventory";
import { computeAssessment } from "@/lib/assessment";
import { renderModule } from "./renderers";
import AssessmentCard from "./AssessmentCard";
import InventoryCard from "./InventoryCard";
import { Card, Stat, Findings, Badge } from "./ui";

type OkModule = Extract<ModuleEntry, { ok: true }>;

/** Shared result view for a finished Full Scan: assessment, assets, chained subdomains and modules. */
export default function ScanResult({ rec }: { rec: ScanRecord }) {
  const [openMod, setOpenMod] = useState<string | null>(null);
  const [openChild, setOpenChild] = useState<string | null>(null);
  const [openChildMod, setOpenChildMod] = useState<string | null>(null);

  const rootOk = rec.modules.filter((m): m is OkModule => m.ok);
  const counts = rec.counts ?? { high: 0, medium: 0, low: 0, info: 0 };

  return (
    <div className="stack">
      <AssessmentCard a={computeAssessment(rec.modules)} />
      <InventoryCard inv={buildInventory(rec.modules, rec.children)} title="Discovered assets" target={rec.target} />

      <div className="grid grid-4">
        <Stat label="Findings" value={rec.findings.length} sub={`${counts.high} high · ${counts.medium} medium`} accent={counts.high ? "orange" : "blue"} />
        <Stat label="Modules run" value={rec.modulesRun ?? 0} sub={`${rec.modulesOk ?? 0} succeeded`} accent="silver" />
        <Stat label="Chained hosts" value={rec.hosts ?? 0} sub="live subdomains scanned" accent="blue" />
        <Stat label="Mode" value={MODE_LABEL[rec.mode]} accent="silver" />
      </div>

      {rec.findings.length > 0 && (
        <>
          <Findings items={rec.findings} />
          <div className="muted small" style={{ marginTop: -8, paddingLeft: 2 }}>
            Findings are aggregated from: {[...new Set(rec.findings.map((f) => f.module))].join(", ")}
          </div>
        </>
      )}

      {rec.children.length > 0 && (
        <Card title="Chained subdomains" count={rec.children.length} pad={false}>
          {rec.children.map((c: ChildScan) => {
            const ok = c.modules.filter((m) => m.ok).length;
            const findings = c.modules.flatMap((m) => (m.ok ? m.findings : []));
            const high = findings.filter((f) => f.severity === "high").length;
            const medium = findings.filter((f) => f.severity === "medium").length;
            return (
              <div key={c.host}>
                <button type="button" className="acc-head" aria-expanded={openChild === c.host} onClick={() => setOpenChild(openChild === c.host ? null : c.host)}>
                  <span className="muted" style={{ width: 14 }}>{openChild === c.host ? "▾" : "▸"}</span>
                  <b className="wrap-anywhere" style={{ width: 280, flexShrink: 0 }}>{c.host}</b>
                  <span className="muted small mono" style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.ips.join(", ") || "no address"}</span>
                  <span className="muted small">{ok}/{c.modules.length} modules</span>
                  {high > 0 && <Badge kind="bad">{high} high</Badge>}
                  {medium > 0 && <Badge kind="orange">{medium} medium</Badge>}
                </button>
                {openChild === c.host && (
                  <div className="acc-body">
                    {c.modules.map((m) => (
                      <div key={`${m.id}`} style={{ marginBottom: 6 }}>
                        <button type="button" className="acc-head" aria-expanded={openChildMod === `${c.host}:${m.id}`} onClick={() => setOpenChildMod(openChildMod === `${c.host}:${m.id}` ? null : `${c.host}:${m.id}`)}>
                          <span className="muted" style={{ width: 14 }}>{openChildMod === `${c.host}:${m.id}` ? "▾" : "▸"}</span>
                          <b style={{ width: 200, flexShrink: 0 }}>{m.title}</b>
                          <span className="muted small" style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.ok ? m.summary : m.error}</span>
                          {!m.ok && <Badge kind="bad">failed</Badge>}
                        </button>
                        {m.ok && openChildMod === `${c.host}:${m.id}` && <div className="acc-body">{renderModule(m.id, { summary: m.summary, findings: m.findings, data: m.data, warnings: m.warnings })}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      )}

      <Card title="Results by module" pad={false}>
        {rootOk.map((m) => (
          <div key={m.id}>
            <button type="button" className="acc-head" aria-expanded={openMod === m.id} onClick={() => setOpenMod(openMod === m.id ? null : m.id)}>
              <span className="muted" style={{ width: 14 }}>{openMod === m.id ? "▾" : "▸"}</span>
              <b style={{ width: 220, flexShrink: 0 }}>{m.title}</b>
              <span className="muted small" style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.summary}</span>
              <span className={`tier ${m.tier}`}>{m.tier}</span>
            </button>
            {openMod === m.id && <div className="acc-body">{renderModule(m.id, { summary: m.summary, findings: m.findings, data: m.data, warnings: m.warnings })}</div>}
          </div>
        ))}
        {rec.modules.filter((m) => !m.ok).map((m) => (
          <div key={m.id} className="acc-head" style={{ cursor: "default" }}>
            <span style={{ width: 14 }} />
            <b style={{ width: 220, flexShrink: 0 }}>{m.title}</b>
            <span className="muted small" style={{ flex: 1 }}>{!m.ok ? m.error : ""}</span>
            <Badge kind="bad">failed</Badge>
          </div>
        ))}
      </Card>
    </div>
  );
}
