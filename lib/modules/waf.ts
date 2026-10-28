import { safeFetch, UserError } from "../net.ts";
import { doh } from "../dns-core.ts";
import type { ParsedTarget } from "../target.ts";
import type { ModuleOutput } from "../types.ts";
import { detectWaf, type WafMatch } from "./fingerprint-core.ts";

export interface WafData {
  target: string;
  finalUrl: string;
  status: number;
  ip?: string;
  matches: WafMatch[];
  primary: WafMatch | null;
}

export async function runWaf(t: ParsedTarget): Promise<ModuleOutput<WafData>> {
  if (t.kind === "cidr") throw new UserError("WAF / CDN Detection needs a single domain, URL or IP.");
  const start = t.url ?? `https://${t.host}/`;
  let res;
  try {
    res = await safeFetch(start, { timeoutMs: 12000, maxBytes: 600_000 });
  } catch (e) {
    if (start.startsWith("https://") && !t.url) res = await safeFetch(`http://${t.host}/`, { timeoutMs: 12000, maxBytes: 600_000 });
    else throw e;
  }
  const cnames: string[] = [];
  if (!/^[\d.:]+$/.test(t.host)) {
    const cn = await doh(t.host, "CNAME").catch(() => null);
    cn?.records.forEach((r) => cnames.push(r.value));
  }
  const matches = detectWaf(res.headers, res.body, cnames).sort((a, b) => (a.confidence === "High" ? -1 : 1) - (b.confidence === "High" ? -1 : 1));
  const primary = matches[0] ?? null;
  const summary = primary ? `${primary.name} (${primary.confidence} confidence)` : "No WAF/CDN detected";
  return { summary, findings: [], data: { target: start, finalUrl: res.finalUrl, status: res.status, matches, primary } };
}
