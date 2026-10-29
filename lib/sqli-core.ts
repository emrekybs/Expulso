// Pure parts of the SQL Injection page: candidate selection, the sqlmap command, and reading sqlmap output.
// Shared by the server and the page, so it must not import server-only modules.
import { VULN_KB } from "./vuln-kb.ts";
import type { Finding } from "./types.ts";

/** Parameter names that usually reach a database query (a built-in approximation of the gf sqli patterns). */
export const SQLI_PARAM_NAMES = /^(id|uid|userid|user_id|pid|product|productid|cat|catid|category|item|itemid|num|no|order|sort|select|from|where|table|column|news|article|post|p|year|month|day|ref|key|code|account|invoice|order_id|lang)$/i;

export const SQLMAP_TECHNIQUES = ["B", "E", "U", "T", "S"] as const;
const STATIC_FILE = /\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)$/i;

export interface SqliRequest {
  targets: string[];
  level: number;
  risk: number;
  techniques: string[];
  threads: number;
  limit: number;
  /** Nuclei tags run on the same candidate URLs, for example sqli. */
  nucleiTags: string[];
}

export function validateSqli(r: SqliRequest): string | null {
  if (!(r.level >= 1 && r.level <= 5)) return "Level must be between 1 and 5.";
  if (!(r.risk >= 1 && r.risk <= 3)) return "Risk must be between 1 and 3.";
  if (r.techniques.some((t) => !(SQLMAP_TECHNIQUES as readonly string[]).includes(t))) return "Unknown technique.";
  if (!r.techniques.length) return "Choose at least one technique.";
  if (!(r.threads >= 1 && r.threads <= 4)) return "Threads must be between 1 and 4.";
  if (!(r.limit >= 1 && r.limit <= 200)) return "Candidate limit must be between 1 and 200.";
  if ((r.nucleiTags ?? []).some((t) => !/^[a-z0-9-]{1,40}$/.test(t))) return "Nuclei tags use lower-case letters, digits and dashes only.";
  return null;
}

/** URLs with a database-like parameter, one per URL shape. */
export function sqliCandidates(urls: string[], limit: number): { url: string; params: string[] }[] {
  const seen = new Set<string>();
  const out: { url: string; params: string[] }[] = [];
  for (const raw of urls) {
    if (out.length >= limit) break;
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    if (!u.search || STATIC_FILE.test(u.pathname)) continue;
    const params = [...new Set(u.searchParams.keys())].filter((k) => SQLI_PARAM_NAMES.test(k));
    if (!params.length) continue;
    const shape = `${u.origin}${u.pathname}?${[...params].sort().join("&")}`;
    if (seen.has(shape)) continue;
    seen.add(shape);
    out.push({ url: `${u.origin}${u.pathname}${u.search}`, params });
  }
  return out;
}

/**
 * The sqlmap arguments for one URL and parameter. Detection only: no --dump, --os-shell, --sql-shell or
 * file access flags are ever added. --batch means nothing waits for input.
 */
export function sqlmapArgs(r: SqliRequest, url: string, param: string, outDir: string, proxy?: string | null): string[] {
  return [
    "-u", url,
    "-p", param,
    "--batch",
    "--level", String(r.level),
    "--risk", String(r.risk),
    "--technique", r.techniques.join(""),
    "--threads", String(r.threads),
    "--timeout", "10",
    "--retries", "1",
    "--random-agent",
    "--flush-session",
    "--disable-coloring",
    "--output-dir", outDir,
    ...(proxy ? ["--proxy", proxy] : []),
  ];
}

/** Turns sqlmap output into findings: one per injection point it confirmed. */
export function parseSqlmapOutput(lines: string[], url: string): Finding[] {
  const kb = VULN_KB["sqli-error"];
  const out: Finding[] = [];
  let param: string | null = null;
  let dbms: string | null = null;
  let current: { param: string; technique: string; title: string; payload?: string } | null = null;
  const flush = () => {
    if (!current) return;
    out.push({
      severity: "high",
      title: `SQL injection in parameter ${current.param} (${current.technique})`,
      detail: `${kb.what} sqlmap confirmed it with ${current.title}.${dbms ? ` Back-end database: ${dbms}.` : ""}`,
      evidence: [url, current.payload ? `Payload: ${current.payload}` : ""].filter(Boolean).join("\n"),
      recommendation: kb.fix,
      kind: "sqli-error",
      impact: kb.impact,
      cwe: kb.cwe,
      references: kb.references,
      confidence: "confirmed",
    });
    current = null;
  };
  for (const raw of lines) {
    const line = raw.trim();
    const p = line.match(/^Parameter: (\S+) \((GET|POST|COOKIE|HEADER|JSON|URI)\)/);
    if (p) {
      flush();
      param = p[1];
      continue;
    }
    const d = line.match(/back-end DBMS(?: is)?:? ?(?:is )?([A-Za-z ]+)/i);
    if (d && !dbms) dbms = d[1].trim().slice(0, 60);
    if (!param) continue;
    if (line.startsWith("Type:")) {
      flush();
      current = { param, technique: line.slice(5).trim(), title: "" };
    } else if (line.startsWith("Title:") && current) current.title = line.slice(6).trim();
    else if (line.startsWith("Payload:") && current) current.payload = line.slice(8).trim().slice(0, 300);
  }
  flush();
  return out;
}
