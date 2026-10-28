import { safeFetch, UserError } from "../net.ts";
import { extractFromHtml, matchKeywords, platformLabel } from "./uscrapper-core.ts";
import type { ParsedTarget } from "../target.ts";
import type { ModuleOutput } from "../types.ts";

export interface OsintPage {
  url: string;
  status: number | null;
  title: string;
  error?: string;
  matched?: string[];
}
export interface Found {
  value: string;
  sources: string[];
  label?: string;
}
export interface OsintData {
  target: string;
  mode: "details" | "keywords";
  pages: OsintPage[];
  emails: Found[];
  social: Found[];
  phones: Found[];
  authors: Found[];
  geolocations: Found[];
  usernames: Found[];
  keywordMatches: { keyword: string; urls: string[] }[];
  stats: { emails: number; social: number; phones: number; pages: number };
}

class Bucket {
  private m = new Map<string, Found>();
  add(value: string, src: string, label?: string) {
    const key = value.trim();
    if (!key) return;
    const f = this.m.get(key) ?? { value: key, sources: [], ...(label ? { label } : {}) };
    if (!f.sources.includes(src)) f.sources.push(src);
    this.m.set(key, f);
  }
  list() {
    return [...this.m.values()];
  }
}

export async function runOsint(t: ParsedTarget, opts: { crawl?: number; nonStrict?: boolean; keywords?: string }): Promise<ModuleOutput<OsintData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("OSINT Harvester needs a domain or URL.");
  const start = t.url ?? `https://${t.host}/`;
  const maxPages = Math.max(1, Math.min(30, Math.floor(opts.crawl ?? 10)));
  const nonStrict = !!opts.nonStrict;
  const keywords = (opts.keywords ?? "").split(",").map((k) => k.trim()).filter(Boolean).slice(0, 50);
  const mode: OsintData["mode"] = keywords.length ? "keywords" : "details";
  const deadline = Date.now() + 45000;
  const warnings: string[] = [];

  const b = { emails: new Bucket(), social: new Bucket(), phones: new Bucket(), authors: new Bucket(), geo: new Bucket(), usernames: new Bucket() };
  const kw = new Map<string, Set<string>>(keywords.map((k) => [k, new Set()]));
  const pages: OsintPage[] = [];
  const visited = new Set<string>();
  const queue = [start];
  let first = true;

  const base = new URL(start);
  while (queue.length && visited.size < maxPages && Date.now() < deadline) {
    const batch = queue.splice(0, first ? 1 : 4).filter((u) => !visited.has(u));
    if (!batch.length) continue;
    batch.forEach((u) => visited.add(u));
    const results = await Promise.all(
      batch.map(async (url) => {
        try {
          const res = await safeFetch(url, { timeoutMs: first ? 18000 : 10000, maxBytes: 2_000_000 });
          if (first && res.status === 404) throw new UserError(`Target page not found (HTTP ${res.status}).`);
          const ct = res.headers.get("content-type") ?? "";
          if (ct && !/html|xml|text\/plain/i.test(ct)) {
            pages.push({ url: res.finalUrl, status: res.status, title: "", error: "Non-HTML content skipped." });
            return [] as string[];
          }
          if (res.status !== 200 && res.status !== 404 && first) warnings.push(`HTTP ${res.status}: the site may use anti-scraping. The response was still analysed.`);
          const ex = extractFromHtml(res.body, res.finalUrl, nonStrict);
          if (ex.challenge && !warnings.some((w) => w.includes("results are limited"))) {
            warnings.push(`The site returned a ${ex.challenge} page instead of content, so results are limited. The site blocks automated access; this is not an empty result.`);
          }
          const page: OsintPage = { url: res.finalUrl, status: res.status, title: ex.title };
          if (mode === "keywords") {
            page.matched = matchKeywords(res.body, keywords);
            page.matched.forEach((k) => kw.get(k)?.add(res.finalUrl));
          } else {
            ex.emails.forEach((v) => b.emails.add(v, res.finalUrl));
            ex.textEmails.forEach((v) => b.emails.add(v, res.finalUrl));
            ex.socialLinks.forEach((s) => b.social.add(s.url, res.finalUrl, platformLabel(s.platform)));
            ex.phones.forEach((v) => b.phones.add(v, res.finalUrl));
            ex.authors.forEach((v) => b.authors.add(v, res.finalUrl));
            ex.geolocations.forEach((v) => b.geo.add(v, res.finalUrl));
            ex.usernames.forEach((v) => b.usernames.add(v, res.finalUrl));
          }
          pages.push(page);
          return ex.links;
        } catch (e) {
          if (first) throw e instanceof UserError ? e : new UserError("Could not fetch the target page.");
          pages.push({ url, status: null, title: "", error: e instanceof UserError ? e.message : "fetch failed" });
          return [] as string[];
        }
      }),
    );
    first = false;
    for (const links of results) for (const l of links) if (!visited.has(l) && !queue.includes(l) && new URL(l).host === base.host) queue.push(l);
  }
  if (queue.length && Date.now() >= deadline) warnings.push("Stopped early at the time limit.");

  const stats = { emails: b.emails.list().length, social: b.social.list().length, phones: b.phones.list().length, pages: pages.filter((p) => !p.error).length };
  const data: OsintData = {
    target: start,
    mode,
    pages,
    emails: b.emails.list(),
    social: b.social.list(),
    phones: b.phones.list(),
    authors: b.authors.list(),
    geolocations: b.geo.list(),
    usernames: b.usernames.list(),
    keywordMatches: [...kw].map(([keyword, urls]) => ({ keyword, urls: [...urls] })),
    stats,
  };
  const summary = mode === "keywords" ? `${data.keywordMatches.filter((k) => k.urls.length).length}/${keywords.length} keywords matched · ${stats.pages} pages` : `${stats.emails} emails · ${stats.social} social · ${stats.phones} phones · ${stats.pages} pages`;
  return { summary, findings: [], data, warnings };
}
