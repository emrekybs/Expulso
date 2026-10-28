// Cross-module assessment: one risk score, priorities, attack-surface numbers and coverage.
// Pure functions, used by the Full Scan page and the HTML report.
import type { Finding, Severity } from "./types.ts";

export interface AssessmentInput {
  id: string;
  title?: string;
  ok: boolean;
  findings?: Finding[];
  data?: unknown;
  code?: string;
  error?: string;
}

export interface Priority extends Finding {
  module: string;
}

export interface Assessment {
  score: number;
  grade: string;
  headline: string;
  lines: string[];
  priorities: Priority[];
  counts: Record<Severity, number>;
  coverage: { total: number; ok: number; failed: number; notApplicable: number };
}

const WEIGHT: Record<Severity, number> = { high: 10, medium: 4, low: 1, info: 0 };
const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

export function gradeOf(score: number): string {
  return score >= 95 ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";
}

// Loose views of module data: only the fields we read. Missing fields are treated as absent.
type Obj = Record<string, unknown>;
const get = (o: unknown, k: string): unknown => (o && typeof o === "object" ? (o as Obj)[k] : undefined);
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

export function computeAssessment(mods: AssessmentInput[]): Assessment {
  const okMods = mods.filter((m) => m.ok);
  const failed = mods.filter((m) => !m.ok && m.code !== "not_applicable").length;
  const notApplicable = mods.filter((m) => m.code === "not_applicable").length;

  const priorities: Priority[] = [];
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  for (const m of okMods) {
    for (const f of m.findings ?? []) {
      counts[f.severity]++;
      penalty += WEIGHT[f.severity];
      priorities.push({ ...f, module: m.title ?? m.id });
    }
  }
  priorities.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const score = Math.max(0, Math.round(100 - Math.min(penalty, 85)));

  // Attack-surface numbers from module data (only where the module ran).
  const byId = (id: string) => okMods.find((m) => m.id === id)?.data;
  const sub = byId("subdomains");
  const subStats = get(sub, "stats");
  const dns = byId("dns");
  const mail = get(dns, "mail");
  const mailIssues = ["spf", "dmarc"].filter((k) => {
    const v = get(get(mail, k), "verdict");
    return v === "missing" || v === "weak";
  }).length;
  const dirs = get(byId("dirs"), "stats");
  const js = get(byId("js"), "stats");
  const ports = byId("ports-passive");
  const web = byId("webtech");
  const techs = (get(web, "technologies") as unknown[] | undefined) ?? [];
  const geo = byId("geoip");
  const cloud = byId("cloud");
  const providers = new Set<string>([...((get(cloud, "providers") as string[] | undefined) ?? [])]);
  const geoEntries = (get(geo, "entries") as unknown[] | undefined) ?? [];
  const exposure = byId("exposure");
  const failedChecks = ((get(exposure, "checks") as { status?: string }[] | undefined) ?? []).filter((c) => c.status === "fail").length;

  const lines: string[] = [];
  if (subStats) lines.push(`${num(get(subStats, "total"))} subdomains found, ${num(get(subStats, "live"))} answering over HTTP, ${num(get(subStats, "takeover"))} takeover candidate(s).`);
  if (dirs) lines.push(`${num(get(dirs, "found"))} reachable path(s), ${num(get(dirs, "admin"))} login or admin panel(s).`);
  if (js) lines.push(`${num(get(js, "files"))} JavaScript file(s), ${num(get(js, "secrets"))} possible secret(s).`);
  if (mail) lines.push(`Mail: SPF ${String(get(get(mail, "spf"), "verdict") ?? "unknown")}, DMARC ${String(get(get(mail, "dmarc"), "verdict") ?? "unknown")}.`);
  if (ports) lines.push(`${num(get(ports, "totalPorts"))} open port(s) and ${num(get(ports, "totalCves"))} CVE(s) in passive index data.`);
  if (techs.length) {
    const outdated = priorities.filter((p) => p.module.toLowerCase().includes("web tech")).length;
    lines.push(`${techs.length} web technolog${techs.length === 1 ? "y" : "ies"} identified${outdated ? `, ${outdated} finding(s) about versions` : ""}.`);
  }
  const cloudHits = (get(cloud, "hits") as unknown[] | undefined)?.length ?? 0;
  const ipCount = geoEntries.length || cloudHits;
  if (ipCount) {
    const p = [...providers].filter((x) => x && !x.startsWith("Unknown")).slice(0, 4);
    lines.push(`${ipCount} IP address(es)${p.length ? ` on ${p.join(", ")}` : ""}.`);
  }
  if (failedChecks) lines.push(`${failedChecks} failed HTTP security check(s).`);
  if (mailIssues) lines.push(`${mailIssues} email-authentication record(s) are missing or weak.`);
  lines.push(`Coverage: ${okMods.length} of ${mods.length - notApplicable} applicable module(s) completed${failed ? `, ${failed} failed` : ""}.`);

  const top = priorities[0];
  const headline = priorities.length
    ? `${counts.high} high and ${counts.medium} medium finding(s). Highest priority: ${top.title}.`
    : okMods.length
      ? "No notable issues in the modules that completed."
      : "No module completed, so no assessment is possible.";

  return {
    score,
    grade: gradeOf(score),
    headline,
    lines,
    priorities: priorities.slice(0, 8),
    counts,
    coverage: { total: mods.length - notApplicable, ok: okMods.length, failed, notApplicable },
  };
}
