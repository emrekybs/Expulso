import * as cheerio from "cheerio";
import { fetchWithTimeout, safeFetch, UserError, htmlTitle, mapLimit } from "../net.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";
import { SIG_BY_NAME, TECH_SIGS, type Cat, type Rule, type TechSig } from "./webtech-sigs.ts";

export type Confidence = "high" | "medium";

export interface DetectedTech {
  name: string;
  cat: Cat;
  version?: string;
  confidence: Confidence;
  evidence: string;
  /** True when added only because another technology implies it. */
  implied?: boolean;
}

export interface TechInput {
  headers: Headers;
  html: string;
  /** Final URL after redirects (currently informational). */
  finalUrl?: string;
}

const STRONG_SOURCES = new Set(["header", "cookie", "meta", "script"]);

function collect(input: TechInput) {
  const html = input.html.slice(0, 800_000);
  const $ = cheerio.load(html);
  const scripts = [
    ...$("script[src]").map((_, s) => $(s).attr("src") ?? "").get(),
    ...$("link[href]").map((_, l) => $(l).attr("href") ?? "").get(),
  ].filter(Boolean);
  const metas = $('meta[name="generator" i]').map((_, m) => $(m).attr("content") ?? "").get().filter(Boolean);
  const setCookies = (input.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
  const headerValue = (name: string) => input.headers.get(name) ?? "";
  return { html, scripts, metas, cookies: setCookies.join("\n"), headerValue };
}

function matchRule(rule: Rule, ctx: ReturnType<typeof collect>): { value: string | null; ok: boolean; sample: string } {
  const [on, re] = rule;
  let subject: string | null = null;
  if (on.startsWith("header:")) subject = ctx.headerValue(on.slice(7)) || null;
  else if (on === "cookie") subject = ctx.cookies || null;
  else if (on === "html") subject = ctx.html;
  else if (on === "script") subject = ctx.scripts.join("\n") || null;
  else if (on === "meta") subject = ctx.metas.join("\n") || null;
  if (!subject) return { value: null, ok: false, sample: "" };
  const m = subject.match(re);
  if (!m) return { value: null, ok: false, sample: "" };
  const v = rule[2] ? (m[1] ?? "").trim() || null : null;
  return { value: v, ok: true, sample: m[0].slice(0, 80) };
}

/** Passive detection from one response: headers, cookies, script/link URLs, generator meta and HTML. */
export function detectWebTech(input: TechInput): DetectedTech[] {
  const ctx = collect(input);
  const found = new Map<string, DetectedTech>();

  for (const sig of TECH_SIGS) {
    let version: string | undefined;
    let evidence = "";
    let strong = false;
    let matched = false;
    for (const rule of sig.rules) {
      const r = matchRule(rule, ctx);
      if (!r.ok) continue;
      if (!matched) {
        matched = true;
        evidence = `${rule[0]} matched "${r.sample}"`;
      }
      if (STRONG_SOURCES.has(rule[0].split(":")[0])) strong = true;
      if (r.value && !version) version = r.value;
    }
    if (matched) found.set(sig.name, { name: sig.name, cat: sig.cat, version, confidence: strong ? "high" : "medium", evidence });
  }

  // Implied technologies (e.g. WooCommerce implies WordPress).
  for (const tech of [...found.values()]) {
    const sig = SIG_BY_NAME.get(tech.name) as TechSig | undefined;
    for (const imp of sig?.implies ?? []) {
      if (found.has(imp)) continue;
      const is = SIG_BY_NAME.get(imp);
      if (is) found.set(imp, { name: imp, cat: is.cat, confidence: "medium", evidence: `implied by ${tech.name}`, implied: true });
    }
  }
  return [...found.values()].sort((a, b) => a.cat.localeCompare(b.cat) || a.name.localeCompare(b.name));
}

/* ------------------------------ Version comparison ------------------------------ */

export function versionLt(a: string, b: string): boolean {
  const pa = a.split(/[.\-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.\-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}

/* ------------------------------ Known-outdated checks (static, offline) ------------------------------ */

interface OutdatedRule {
  tech: string;
  when: (v: string) => boolean;
  severity: Finding["severity"];
  title: (v: string) => string;
  detail: string;
  recommendation: string;
}

const OUTDATED: OutdatedRule[] = [
  { tech: "PHP", when: (v) => versionLt(v, "8.0"), severity: "high", title: (v) => `PHP ${v} is end of life`, detail: "PHP branches before 8.0 no longer receive security fixes.", recommendation: "Upgrade to a supported PHP branch (8.2 or newer)." },
  { tech: "PHP", when: (v) => versionLt(v, "8.2") && !versionLt(v, "8.0"), severity: "low", title: (v) => `PHP ${v} is an older branch`, detail: "Check the official support calendar; this branch may be close to end of security support.", recommendation: "Plan an upgrade to the current supported branch." },
  { tech: "jQuery", when: (v) => versionLt(v, "3.5.0"), severity: "medium", title: (v) => `jQuery ${v} has known XSS issues`, detail: "jQuery before 3.5.0 is affected by CVE-2020-11022 and CVE-2020-11023 (XSS through HTML manipulation).", recommendation: "Upgrade jQuery to 3.5.0 or newer (3.7.x is current)." },
  { tech: "Bootstrap", when: (v) => versionLt(v, "3.4.1") || (v.startsWith("4.") && versionLt(v, "4.3.1")), severity: "medium", title: (v) => `Bootstrap ${v} has a known XSS issue`, detail: "Bootstrap versions before 3.4.1 and 4.3.1 are affected by CVE-2019-8331 (XSS in tooltip/popover).", recommendation: "Upgrade to a current Bootstrap release." },
  { tech: "Lodash", when: (v) => versionLt(v, "4.17.21"), severity: "medium", title: (v) => `Lodash ${v} is vulnerable`, detail: "Lodash before 4.17.21 is affected by CVE-2021-23337 (command injection in template) and prototype pollution issues.", recommendation: "Upgrade Lodash to 4.17.21 or newer." },
  { tech: "Moment.js", when: () => true, severity: "low", title: () => "Moment.js is deprecated", detail: "Moment.js is in maintenance mode and no longer receives new features; it is kept for legacy projects.", recommendation: "Plan a migration to date-fns, Luxon or the Temporal API." },
  { tech: "WordPress", when: (v) => versionLt(v, "6.0"), severity: "medium", title: (v) => `WordPress ${v} is outdated`, detail: "Older WordPress releases miss security fixes and are commonly targeted through plugins.", recommendation: "Update WordPress core and all plugins and themes." },
  { tech: "Drupal", when: (v) => versionLt(v, "8.0"), severity: "high", title: (v) => `Drupal ${v} is end of life`, detail: "Drupal 7 reached end of life and no longer receives security advisories.", recommendation: "Migrate to a currently supported Drupal release." },
  { tech: "Joomla", when: (v) => versionLt(v, "4.0"), severity: "medium", title: (v) => `Joomla ${v} is end of life`, detail: "Joomla 3 reached end of life; later branches receive security fixes only.", recommendation: "Upgrade to a supported Joomla branch." },
  { tech: "Apache HTTP Server", when: (v) => v === "2.4.49" || v === "2.4.50", severity: "high", title: (v) => `Apache ${v} path traversal (CVE-2021-41773/42013)`, detail: "This exact Apache release line is affected by a path traversal and remote code execution issue when misconfigured.", recommendation: "Upgrade Apache to 2.4.51 or newer." },
];

export function outdatedFindings(techs: DetectedTech[]): Finding[] {
  const out: Finding[] = [];
  for (const t of techs) {
    if (!t.version) {
      if (t.name === "Moment.js") out.push({ severity: "low", title: "Moment.js is deprecated", detail: "Moment.js is in maintenance mode and no longer receives new features.", recommendation: "Plan a migration to a maintained date library." });
      continue;
    }
    for (const rule of OUTDATED) {
      if (rule.tech !== t.name || !rule.when(t.version)) continue;
      out.push({ severity: rule.severity, title: rule.title(t.version), detail: rule.detail, evidence: `${t.name} ${t.version} (${t.evidence})`, recommendation: rule.recommendation });
      break;
    }
  }
  return out;
}

/* ------------------------------ Known vulnerabilities (OSV.dev, keyless) ------------------------------ */

export interface CveHit {
  tech: string;
  version: string;
  ids: { id: string; summary: string }[];
}

export async function osvLookup(npm: string, version: string): Promise<{ id: string; summary: string }[]> {
  const res = await fetchWithTimeout(
    "https://api.osv.dev/v1/query",
    { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ version, package: { name: npm, ecosystem: "npm" } }) },
    8000,
  );
  if (!res.ok) throw new UserError(`OSV.dev returned HTTP ${res.status}.`, "upstream_error");
  const j = (await res.json()) as { vulns?: { id: string; summary?: string; details?: string }[] };
  return (j.vulns ?? []).slice(0, 10).map((v) => ({ id: v.id, summary: (v.summary || v.details || "").replace(/\s+/g, " ").slice(0, 160) }));
}

/* ------------------------------ Module ------------------------------ */

export interface WebTechData {
  target: string;
  finalUrl: string;
  status: number;
  title: string;
  technologies: DetectedTech[];
  byCategory: Record<string, string[]>;
  cves: CveHit[];
}

export async function runWebTech(t: ParsedTarget): Promise<ModuleOutput<WebTechData>> {
  if (t.kind === "cidr") throw new UserError("Web Technologies needs a single domain, URL or IP.");
  const start = t.url ?? `https://${t.host}/`;
  const warnings: string[] = [];
  let res;
  try {
    res = await safeFetch(start, { timeoutMs: 12000, maxBytes: 1_200_000 });
  } catch (e) {
    if (start.startsWith("https://") && !t.url) res = await safeFetch(`http://${t.host}/`, { timeoutMs: 12000, maxBytes: 1_200_000 });
    else throw e;
  }
  const technologies = detectWebTech({ headers: res.headers, html: res.body, finalUrl: res.finalUrl });

  const findings: Finding[] = outdatedFindings(technologies);

  // CVE lookup only for npm libraries whose version we actually saw.
  const cves: CveHit[] = [];
  const versioned = technologies.filter((x) => x.version && SIG_BY_NAME.get(x.name)?.npm);
  await mapLimit(versioned, 4, async (x) => {
    const npm = SIG_BY_NAME.get(x.name)!.npm!;
    try {
      const ids = await osvLookup(npm, x.version!);
      if (ids.length) cves.push({ tech: x.name, version: x.version!, ids });
    } catch (e) {
      warnings.push(`CVE lookup for ${x.name} ${x.version} failed: ${e instanceof UserError ? e.message : "unknown error"}`);
    }
  });
  for (const c of cves) {
    findings.push({
      severity: "medium",
      title: `${c.ids.length} known vulnerabilit${c.ids.length > 1 ? "ies" : "y"} in ${c.tech} ${c.version}`,
      detail: "Public advisories (OSV.dev) list issues for this version of a front-end library. Exploitability depends on how the library is used.",
      evidence: c.ids.slice(0, 6).map((i) => `${i.id}${i.summary ? ` — ${i.summary}` : ""}`).join("\n"),
      recommendation: `Upgrade ${c.tech} to the latest release on its current branch.`,
    });
  }

  const byCategory: Record<string, string[]> = {};
  for (const x of technologies) (byCategory[x.cat] ??= []).push(x.version ? `${x.name} ${x.version}` : x.name);

  const outdated = findings.filter((f) => f.title.includes("outdated") || f.title.includes("end of life") || f.title.includes("known XSS") || f.title.includes("vulnerable") || f.title.includes("known vulnerab") || f.title.includes("deprecated")).length;
  const summary = `${technologies.length} technologies${technologies.length ? ` · ${Object.keys(byCategory).slice(0, 3).join(", ")}` : ""}${outdated ? ` · ${outdated} outdated/vulnerable` : ""}`;
  return {
    summary,
    findings,
    data: { target: start, finalUrl: res.finalUrl, status: res.status, title: htmlTitle(res.body), technologies, byCategory, cves },
    warnings,
  };
}
