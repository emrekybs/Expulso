import { safeFetch, UserError } from "../net.ts";
import { extractFromHtml, matchKeywords } from "./uscrapper-core.ts";
import type { ParsedTarget } from "../target.ts";

export interface UscrapperOptions {
  /** Aynı alan adında taranacak en fazla sayfa sayısı (0 = yalnızca hedef sayfa) */
  crawl?: number;
  /** Eşzamanlı istek sayısı (orijinaldeki -t) */
  threads?: number;
  /** Kesin olmayan kullanıcı adlarını da göster (orijinaldeki -ns) */
  nonStrict?: boolean;
  /** Anahtar kelime modu (orijinaldeki -k) */
  keywords?: string[];
}

export interface Found {
  value: string;
  /** Bulunduğu sayfalar */
  sources: string[];
  platform?: string;
}

export interface ScrapedPage {
  url: string;
  status: number | null;
  title: string;
  error?: string;
  matchedKeywords?: string[];
  antiScraping?: boolean;
}

export interface UscrapperResult {
  target: string;
  mode: "details" | "keywords";
  nonStrict: boolean;
  pages: ScrapedPage[];
  hyperlinked: { emails: Found[]; socialLinks: Found[]; authors: Found[]; geolocations: Found[] };
  nonHyperlinked: { emails: Found[]; phones: Found[]; usernames: Found[] };
  keywordMatches: { keyword: string; urls: string[] }[];
  summary: { emails: number; socialLinks: number; phones: number; geolocations: number; pages: number };
  warnings: string[];
}

const MAX_CRAWL = 30;

class Bucket {
  private m = new Map<string, Found>();
  add(value: string, src: string, platform?: string) {
    const key = value.trim();
    if (!key) return;
    const f = this.m.get(key) ?? { value: key, sources: [], ...(platform ? { platform } : {}) };
    if (!f.sources.includes(src)) f.sources.push(src);
    this.m.set(key, f);
  }
  list(): Found[] {
    return [...this.m.values()];
  }
}

export async function runUscrapper(t: ParsedTarget, opts: UscrapperOptions): Promise<UscrapperResult> {
  if (t.kind === "cidr") throw new UserError("Uscrapper bir URL veya alan adı bekler.");
  const start = t.url ?? `https://${t.host}/`;
  const maxPages = Math.max(1, Math.min(MAX_CRAWL, Math.floor(opts.crawl ?? 0) || 1));
  const threads = Math.max(1, Math.min(8, Math.floor(opts.threads ?? 4)));
  const keywords = (opts.keywords ?? []).map((k) => k.trim()).filter(Boolean).slice(0, 50);
  const mode: UscrapperResult["mode"] = keywords.length ? "keywords" : "details";
  const nonStrict = !!opts.nonStrict;
  const deadline = Date.now() + 50_000;

  const warnings: string[] = [];
  const pages: ScrapedPage[] = [];
  const b = {
    emails: new Bucket(),
    social: new Bucket(),
    authors: new Bucket(),
    geo: new Bucket(),
    textEmails: new Bucket(),
    phones: new Bucket(),
    usernames: new Bucket(),
  };
  const kw = new Map<string, Set<string>>(keywords.map((k) => [k, new Set()]));

  const visited = new Set<string>();
  const queue: string[] = [start];
  let first = true;

  const scrape = async (url: string): Promise<string[]> => {
    let res;
    try {
      res = await safeFetch(url, { timeoutMs: first ? 20000 : 12000 });
    } catch (e) {
      const msg = e instanceof UserError ? e.message : "Sayfa alınamadı.";
      if (first) throw new UserError(msg);
      pages.push({ url, status: null, title: "", error: msg });
      return [];
    }
    const finalUrl = res.finalUrl;
    if (first && res.status === 404) throw new UserError(`Hedef sayfa bulunamadı (durum kodu ${res.status}).`);
    const ct = res.headers.get("content-type") ?? "";
    if (ct && !/html|xml|text\/plain/i.test(ct)) {
      pages.push({ url: finalUrl, status: res.status, title: "", error: "HTML olmayan içerik atlandı." });
      return [];
    }
    const antiScraping = res.status !== 200 && res.status !== 404;
    if (antiScraping && first) {
      warnings.push(
        `Durum kodu ${res.status}: Site web kazımaya karşı koruma kullanıyor olabilir. Alınan içerik yine de analiz edildi (tarayıcı tabanlı atlatma sunucusuz ortamda desteklenmez).`,
      );
    }
    if (res.truncated) warnings.push(`${finalUrl} sayfası çok büyük olduğu için ilk 3 MB analiz edildi.`);

    const ex = extractFromHtml(res.body, finalUrl, nonStrict);
    const page: ScrapedPage = { url: finalUrl, status: res.status, title: ex.title, ...(antiScraping ? { antiScraping } : {}) };

    if (mode === "keywords") {
      const matched = matchKeywords(res.body, keywords);
      page.matchedKeywords = matched;
      for (const k of matched) kw.get(k)?.add(finalUrl);
    } else {
      ex.emails.forEach((v) => b.emails.add(v, finalUrl));
      ex.socialLinks.forEach((s) => b.social.add(s.url, finalUrl, s.platform));
      ex.authors.forEach((v) => b.authors.add(v, finalUrl));
      ex.geolocations.forEach((v) => b.geo.add(v, finalUrl));
      ex.textEmails.forEach((v) => b.textEmails.add(v, finalUrl));
      ex.phones.forEach((v) => b.phones.add(v, finalUrl));
      ex.usernames.forEach((v) => b.usernames.add(v, finalUrl));
    }
    pages.push(page);
    if (first) {
      // Yönlendirme sonrası alan adını kapsam olarak kullan
      visited.add(finalUrl);
    }
    return ex.links;
  };

  // Aynı kapsam içinde tara ve kazı (orijinaldeki web_crawler)
  let scheduled = 0;
  while (queue.length && scheduled < maxPages && Date.now() < deadline) {
    const batch: string[] = [];
    while (queue.length && batch.length < (first ? 1 : threads) && scheduled + batch.length < maxPages) {
      const u = queue.shift()!;
      if (!visited.has(u)) batch.push(u);
    }
    if (!batch.length) continue;
    batch.forEach((u) => visited.add(u));
    scheduled += batch.length;
    const results = await Promise.all(batch.map((u) => scrape(u)));
    first = false;
    for (const links of results) for (const l of links) if (!visited.has(l) && !queue.includes(l)) queue.push(l);
  }
  if (queue.length && scheduled < maxPages && Date.now() >= deadline) warnings.push("Zaman sınırına ulaşıldığı için tarama erken durduruldu.");

  const emails = b.emails.list();
  const textEmails = b.textEmails.list();
  const uniqueEmails = new Set([...emails, ...textEmails].map((e) => e.value.toLowerCase()));

  return {
    target: start,
    mode,
    nonStrict,
    pages,
    hyperlinked: { emails, socialLinks: b.social.list(), authors: b.authors.list(), geolocations: b.geo.list() },
    nonHyperlinked: { emails: textEmails, phones: b.phones.list(), usernames: b.usernames.list() },
    keywordMatches: [...kw].map(([keyword, urls]) => ({ keyword, urls: [...urls] })),
    summary: {
      emails: uniqueEmails.size,
      socialLinks: b.social.list().length,
      phones: b.phones.list().length,
      geolocations: b.geo.list().length,
      pages: pages.filter((p) => !p.error).length,
    },
    warnings,
  };
}
