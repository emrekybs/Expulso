"use client";
import type { FullScanResponse } from "./api.ts";
import type { Finding } from "../types.ts";
import { computeAssessment } from "../assessment.ts";

const SEV_COLOR: Record<string, string> = { high: "#d93a2f", medium: "#d9661a", low: "#b7790a", info: "#1d6ff2" };

function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
}

/** Self-contained HTML report for one or more targets. */
export function buildHtmlReport(results: { target: string; res: FullScanResponse }[], mode: string): string {
  const now = new Date().toLocaleString();
  const sections = results
    .filter((r) => r.res.ok)
    .map((r) => {
      const c = r.res.counts ?? { high: 0, medium: 0, low: 0, info: 0 };
      const findings = (r.res.findings ?? [])
        .map(
          (f: Finding & { module: string }) => `
      <div class="f">
        <span class="sev" style="background:${SEV_COLOR[f.severity]}">${esc(f.severity)}</span>
        <div>
          <div class="ft">${esc(f.title)}</div>
          <div class="fd">${esc(f.detail)}</div>
          ${f.evidence ? `<pre>${esc(f.evidence)}</pre>` : ""}
          ${f.recommendation ? `<div class="fr"><b>Recommendation:</b> ${esc(f.recommendation)}</div>` : ""}
          <div class="fm">${esc(f.module)}</div>
        </div>
      </div>`,
        )
        .join("");
      const a = computeAssessment((r.res.modules ?? []) as Parameters<typeof computeAssessment>[0]);
      const assess = `<div class="assess"><div class="grade">${esc(a.grade)} <small>${a.score}/100</small></div><div><div class="ft">${esc(a.headline)}</div><ul>${a.lines.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div></div>`;
      const mods = (r.res.modules ?? [])
        .map((m) => (m.ok ? `<tr><td>${esc(m.title)}</td><td><span class="tag ${m.tier}">${esc(m.tier)}</span></td><td>${esc(m.summary)}</td><td>${Math.round(m.durationMs)}ms</td></tr>` : `<tr class="err"><td>${esc(m.title)}</td><td></td><td>${esc(m.error)}</td><td>${Math.round(m.durationMs)}ms</td></tr>`))
        .join("");
      return `
    <section class="target">
      <h2>${esc(r.target)}</h2>
      ${assess}
      <div class="counts">
        <span style="color:${SEV_COLOR.high}">${c.high} High</span>
        <span style="color:${SEV_COLOR.medium}">${c.medium} Medium</span>
        <span style="color:${SEV_COLOR.low}">${c.low} Low</span>
        <span style="color:${SEV_COLOR.info}">${c.info} Info</span>
      </div>
      ${findings ? `<h3>Findings</h3>${findings}` : "<p class='muted'>No notable findings.</p>"}
      <h3>Modules</h3>
      <table><thead><tr><th>Module</th><th>Tier</th><th>Summary</th><th>Time</th></tr></thead><tbody>${mods}</tbody></table>
    </section>`;
    })
    .join("");

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Recon report</title>
<style>
:root{color-scheme:light}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;background:#f3f5f9;color:#0f1722;font-size:14px;line-height:1.5}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px}
header{border-bottom:3px solid;border-image:linear-gradient(90deg,#c9d3de,#1d6ff2,#f5701a) 1;padding-bottom:16px;margin-bottom:24px}
h1{margin:0 0 4px;font-size:22px}
.muted{color:#5f6f84}
.target{background:#fff;border:1px solid #e1e7ef;border-radius:12px;padding:20px;margin-bottom:20px}
.target h2{margin:0 0 8px;font-size:18px}
.counts{display:flex;gap:14px;font-weight:600;font-size:13px;margin-bottom:12px}
h3{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:#5f6f84;margin:18px 0 8px}
.f{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid #eef1f6}
.sev{align-self:flex-start;color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;text-transform:capitalize}
.ft{font-weight:600}.fd{color:#334155;margin-top:2px}.fr{color:#1d6ff2;font-size:13px;margin-top:4px}.fm{color:#8a97a8;font-size:12px;margin-top:4px}
pre{background:#f6f8fb;border:1px solid #e1e7ef;border-radius:6px;padding:8px;overflow:auto;font-size:12px;margin:6px 0;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:#5f6f84;font-size:11px;text-transform:uppercase;padding:8px;border-bottom:1px solid #e1e7ef}
td{padding:8px;border-bottom:1px solid #eef1f6;vertical-align:top}
tr.err td{color:#b23}
.tag{font-size:11px;font-weight:700;padding:1px 7px;border-radius:99px;border:1px solid #cdd6e2}
.tag.passive{color:#15a142}.tag.active{color:#d9661a}.tag.light{color:#5f6f84}
.assess{display:flex;gap:18px;align-items:center;background:#f6f8fb;border:1px solid #e1e7ef;border-radius:10px;padding:14px;margin-bottom:14px}.grade{font-size:34px;font-weight:800;color:#1d6ff2;min-width:120px}.grade small{font-size:13px;color:#5f6f84;font-weight:600}.assess ul{margin:6px 0 0;padding-left:18px;color:#334155}
footer{color:#8a97a8;font-size:12px;text-align:center;margin-top:24px}
</style></head><body><div class="wrap">
<header><h1>Passive Recon Report</h1><div class="muted">Mode: ${esc(mode)} · ${esc(results.length)} target(s) · generated ${esc(now)}</div></header>
${sections}
<footer>Generated by B24-engine. For authorized security research only.</footer>
</div></body></html>`;
}
