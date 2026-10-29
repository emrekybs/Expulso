// Pure parts of the Dalfox page: choosing XSS candidate URLs and reading Dalfox output.
// Shared by the server and the page, so it must not import server-only modules.
import { VULN_KB } from "./vuln-kb.ts";
import type { Finding } from "./types.ts";

/** Parameter names that usually reach the page output (a built-in approximation of the gf xss patterns). */
export const XSS_PARAM_NAMES = /^(q|s|search|query|keyword|keywords|kw|lang|language|id|name|value|input|data|text|content|page|view|template|redirect|url|next|return|callback|cb|jsonp|msg|message|title|ref|from|to|feed|body|html|out|dest|item|category|tag|filter|sort|field|fn|func|path)$/i;

const STATIC_FILE = /\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|pdf)$/i;

/** URLs with at least one XSS-likely parameter. Each URL shape (path and parameter names) is kept once. */
export function xssCandidates(urls: string[], limit: number): { url: string; params: string[] }[] {
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
    const params = [...new Set(u.searchParams.keys())].filter((k) => XSS_PARAM_NAMES.test(k));
    if (!params.length) continue;
    const shape = `${u.origin}${u.pathname}?${[...params].sort().join("&")}`;
    if (seen.has(shape)) continue;
    seen.add(shape);
    out.push({ url: `${u.origin}${u.pathname}${u.search}`, params });
  }
  return out;
}

interface DalfoxLine {
  type?: string;
  data?: string;
  param?: string;
  payload?: string;
  evidence?: string;
  type_description?: string;
}

/**
 * Reads Dalfox JSON lines. Type V (verified) is confirmed, R (reflected) and G (grep) are suspected.
 * Lines that are not JSON, such as banners, are skipped.
 */
export function parseDalfoxLines(lines: string[]): Finding[] {
  const kb = VULN_KB["xss-reflected"];
  const out: Finding[] = [];
  for (const line of lines) {
    let row: DalfoxLine;
    try {
      row = JSON.parse(line) as DalfoxLine;
    } catch {
      continue;
    }
    if (!row.type || !row.data) continue;
    const verified = row.type === "V";
    out.push({
      severity: verified ? "high" : "medium",
      title: `${row.type_description ?? "Cross-site scripting"} in parameter ${row.param ?? "?"}`,
      detail: `${kb.what} ${kb.why}`,
      evidence: [row.data, row.payload ? `Payload: ${row.payload}` : "", row.evidence ? `Evidence: ${row.evidence}` : ""].filter(Boolean).join("\n"),
      recommendation: kb.fix,
      kind: "xss-reflected",
      impact: kb.impact,
      cwe: kb.cwe,
      references: kb.references,
      confidence: verified ? "confirmed" : "suspected",
    });
  }
  return out;
}
