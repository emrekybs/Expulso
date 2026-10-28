import { mapLimit, UserError } from "../net.ts";
import { doh } from "../dns-core.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";

export interface TypoEntry {
  domain: string;
  kind: string;
  registered: boolean;
  hasMx: boolean;
  ip?: string;
}
export interface TypoData {
  base: string;
  total: number;
  checked: number;
  entries: TypoEntry[];
}

const KEYBOARD: Record<string, string> = {
  a: "qwsz", b: "vghn", c: "xdfv", d: "serfcx", e: "wrsdf", f: "drtgvc", g: "ftyhbv", h: "gyujnb", i: "ujko", j: "huikmn", k: "jiolm", l: "kop", m: "njk", n: "bhjm", o: "iklp", p: "ol", q: "wa", r: "edft", s: "awedxz", t: "rfgy", u: "yhji", v: "cfgb", w: "qase", x: "zsdc", y: "tghu", z: "asx",
};
const HOMOGLYPH: Record<string, string> = { a: "4", b: "8", e: "3", i: "1", l: "1", o: "0", s: "5", t: "7", g: "9" };
const TLDS = ["com", "net", "org", "co", "io", "info", "biz", "online", "site", "xyz", "app", "co.uk", "com.tr", "de", "ru"];

export function generateVariations(domain: string): { domain: string; kind: string }[] {
  const dot = domain.indexOf(".");
  const name = domain.slice(0, dot);
  const tld = domain.slice(dot + 1);
  const out = new Map<string, string>();
  const put = (label: string, kind: string) => {
    const d = `${label}.${tld}`.toLowerCase();
    if (d !== domain && /^[a-z0-9-]+\.[a-z.]{2,}$/.test(d)) out.set(d, out.get(d) ?? kind);
  };
  const chars = [...name];
  // omission
  for (let i = 0; i < chars.length; i++) put(chars.slice(0, i).concat(chars.slice(i + 1)).join(""), "omission");
  // repetition
  for (let i = 0; i < chars.length; i++) put(chars.slice(0, i + 1).concat(chars[i], chars.slice(i + 1)).join(""), "repetition");
  // transposition
  for (let i = 0; i < chars.length - 1; i++) {
    const c = [...chars];
    [c[i], c[i + 1]] = [c[i + 1], c[i]];
    put(c.join(""), "transposition");
  }
  // replacement (adjacent key) + homoglyph
  for (let i = 0; i < chars.length; i++) {
    for (const r of KEYBOARD[chars[i]] ?? "") put(chars.slice(0, i).concat(r, chars.slice(i + 1)).join(""), "replacement");
    const h = HOMOGLYPH[chars[i]];
    if (h) put(chars.slice(0, i).concat(h, chars.slice(i + 1)).join(""), "homoglyph");
  }
  // insertion (adjacent key)
  for (let i = 0; i <= chars.length; i++) {
    const prev = chars[i - 1] ?? chars[i];
    for (const r of (KEYBOARD[prev] ?? "").slice(0, 2)) put(chars.slice(0, i).concat(r, chars.slice(i)).join(""), "insertion");
  }
  // hyphenation
  for (let i = 1; i < chars.length; i++) put(chars.slice(0, i).concat("-", chars.slice(i)).join(""), "hyphenation");
  // TLD swap
  const list = [...out.entries()].map(([domain, kind]) => ({ domain, kind }));
  for (const alt of TLDS) if (alt !== tld) list.push({ domain: `${name}.${alt}`, kind: "tld-swap" });
  return list;
}

export async function runTyposquatting(t: ParsedTarget): Promise<ModuleOutput<TypoData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Typosquatting needs a domain.");
  const base = registrableDomain(t.host);
  const variations = generateVariations(base).slice(0, 400);
  const deadline = Date.now() + 40000;
  let checked = 0;
  const results = await mapLimit(variations, 24, async (v): Promise<TypoEntry | null> => {
    if (Date.now() > deadline) return null;
    checked++;
    const a = await doh(v.domain, "A").catch(() => null);
    const ip = a?.records[0]?.value;
    if (!ip) {
      // maybe only NS/MX
      const ns = await doh(v.domain, "NS").catch(() => null);
      if (!ns || !ns.records.length) return { domain: v.domain, kind: v.kind, registered: false, hasMx: false };
    }
    const mx = await doh(v.domain, "MX").catch(() => null);
    return { domain: v.domain, kind: v.kind, registered: true, hasMx: !!mx?.records.length, ip };
  });
  const entries = results.filter((e): e is TypoEntry => !!e && e.registered).sort((a, b) => Number(b.hasMx) - Number(a.hasMx) || a.domain.localeCompare(b.domain));
  const withMx = entries.filter((e) => e.hasMx);
  const findings: Finding[] = [];
  if (entries.length)
    findings.push({
      severity: withMx.length ? "medium" : "low",
      title: `${entries.length} lookalike domain(s) registered${withMx.length ? `, ${withMx.length} can receive email` : ""}`,
      detail: "Registered lookalikes, especially ones with mail servers, are commonly used for phishing and invoice fraud against staff and customers.",
      evidence: entries.slice(0, 10).map((e) => `${e.domain} (${e.kind})${e.hasMx ? " · MX" : ""}`).join("\n"),
      recommendation: "Review ownership, monitor these domains, and consider takedown requests for recently registered ones.",
    });
  return { summary: `${checked} checked · ${entries.length} registered · ${withMx.length} with MX`, findings, data: { base, total: variations.length, checked, entries } };
}
