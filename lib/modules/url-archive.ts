import "server-only";
import { fetchText, UserError } from "../net.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, SourceStatus } from "../types.ts";

// Historic URLs from public web archives (Wayback Machine and Common Crawl). Nothing is sent to the target:
// the archives already hold these URLs. Results are only classified here, never requested.

const LIMIT = 5000;
const MAX_LIST = 3000;
const SENSITIVE = /\.(env|sql|bak|old|orig|backup|zip|tar|tgz|gz|7z|rar|log|ini|conf|config|pem|key|p12|pfx|kdbx|db|sqlite|csv|xlsx?|swp|ds_store|git|svn)$|\/\.(git|svn|env|htaccess|htpasswd|ds_store)(\/|$)/i;
const JS = /\.(m?js|map)$/i;
const API = /\/(api|graphql|rest|rpc|ws|v\d+)(\/|$)/i;
const ADMIN = /(admin|login|signin|dashboard|wp-admin|phpmyadmin|cpanel|console|manage)/i;

export interface ArchiveData {
  domain: string;
  total: number;
  byCategory: { javascript: number; sensitive: number; api: number; admin: number; withParameters: number };
  parameters: { name: string; count: number }[];
  sensitive: string[];
  api: string[];
  admin: string[];
  urls: string[];
  sources: SourceStatus[];
}

async function wayback(domain: string): Promise<string[]> {
  const queries = [`${domain}/*`, `*.${domain}/*`];
  const out: string[] = [];
  for (const q of queries) {
    const { status, text } = await fetchText(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(q)}&output=json&fl=original&collapse=urlkey&limit=${LIMIT}`, 60000);
    if (status !== 200) throw new UserError(`Wayback Machine answered HTTP ${status}.`, "source");
    if (!text.trim()) continue;
    const rows = JSON.parse(text) as string[][];
    for (const r of rows.slice(1)) if (r[0]) out.push(r[0]);
  }
  return out;
}

async function commonCrawl(domain: string): Promise<string[]> {
  const info = await fetchText("https://index.commoncrawl.org/collinfo.json", 20000);
  if (info.status !== 200) throw new UserError(`Common Crawl index list answered HTTP ${info.status}.`, "source");
  const indexes = JSON.parse(info.text) as { id: string; "cdx-api": string }[];
  const api = indexes[0]?.["cdx-api"];
  if (!api) throw new UserError("Common Crawl has no index available.", "source");
  const { status, text } = await fetchText(`${api}?url=${encodeURIComponent(`*.${domain}`)}&output=json&fields=url&limit=${LIMIT}`, 90000);
  if (status !== 200) throw new UserError(`Common Crawl answered HTTP ${status}.`, "source");
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line) as { url?: string };
      if (row.url) out.push(row.url);
    } catch {
      /* skip a malformed line */
    }
  }
  return out;
}

function normalize(raw: string): string | null {
  try {
    const u = new URL(raw);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    u.hash = "";
    const s = u.toString();
    return s.length > 2048 ? null : s;
  } catch {
    return null;
  }
}

export async function runUrlArchive(t: ParsedTarget): Promise<ModuleOutput<ArchiveData>> {
  const domain = t.host;
  const sources: SourceStatus[] = [];
  const warnings: string[] = [];
  const raw: string[] = [];

  for (const [name, fn] of [
    ["Wayback Machine", () => wayback(domain)],
    ["Common Crawl", () => commonCrawl(domain)],
  ] as const) {
    const started = Date.now();
    try {
      const found = await fn();
      raw.push(...found);
      sources.push({ name, ok: true, count: found.length, ms: Date.now() - started });
    } catch (e) {
      const msg = e instanceof UserError ? e.message : `${name} could not be reached (${(e as Error).message || "network error"}).`;
      sources.push({ name, ok: false, count: 0, error: msg, ms: Date.now() - started });
      warnings.push(msg);
    }
  }

  const unique = [...new Set(raw.map(normalize).filter((u): u is string => !!u))];
  const params = new Map<string, number>();
  const sensitive: string[] = [];
  const api: string[] = [];
  const admin: string[] = [];
  let javascript = 0;
  let withParameters = 0;

  for (const url of unique) {
    const u = new URL(url);
    const path = u.pathname;
    if (JS.test(path)) javascript++;
    if (SENSITIVE.test(path)) sensitive.push(url);
    if (API.test(path)) api.push(url);
    if (ADMIN.test(path)) admin.push(url);
    if (u.search) withParameters++;
    for (const key of u.searchParams.keys()) params.set(key, (params.get(key) ?? 0) + 1);
  }

  const parameters = [...params.entries()].sort((a, b) => b[1] - a[1]).slice(0, 80).map(([name, count]) => ({ name, count }));
  const findings: Finding[] = [];
  if (unique.length) {
    findings.push({ severity: "info", title: `${unique.length} unique archived URL(s)`, detail: "Historic URLs for this domain from public web archives. Many may no longer exist; check each one on the live site before reporting it." });
  }
  if (sensitive.length) {
    findings.push({
      severity: "medium",
      title: `${sensitive.length} archived URL(s) point to sensitive file types`,
      detail: "Files such as configs, dumps, backups, archives or version-control folders were archived. They may still be online.",
      evidence: sensitive.slice(0, 15).join("\n"),
      recommendation: "Check whether each file still exists on the live site, and remove any that are public.",
    });
  }
  if (api.length) {
    findings.push({ severity: "low", title: `${api.length} archived API-style URL(s)`, detail: "Paths that look like API endpoints (/api/, /graphql, /v1/...). Useful as a starting list of endpoints.", evidence: api.slice(0, 15).join("\n") });
  }
  if (parameters.length) {
    findings.push({ severity: "info", title: `${parameters.length} query parameter name(s) seen in archived URLs`, detail: "Parameter names that were used in archived links. They show where the application takes user input.", evidence: parameters.slice(0, 30).map((p) => `${p.name} (${p.count})`).join(", ") });
  }

  const okCount = sources.filter((s) => s.ok).length;
  return {
    summary: `${unique.length} unique URLs from ${okCount}/${sources.length} archives · ${sensitive.length} sensitive · ${api.length} API-style`,
    findings,
    data: {
      domain,
      total: unique.length,
      byCategory: { javascript, sensitive: sensitive.length, api: api.length, admin: admin.length, withParameters },
      parameters,
      sensitive: sensitive.slice(0, MAX_LIST),
      api: api.slice(0, MAX_LIST),
      admin: admin.slice(0, MAX_LIST),
      urls: unique.slice(0, MAX_LIST),
      sources,
    },
    sources,
    warnings,
  };
}
