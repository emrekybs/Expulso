import "server-only";
import { safeFetch, UserError } from "../net.ts";
import { activeProxy } from "../settings.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";
import { VULN_KB } from "../vuln-kb.ts";
import { crawlGraph, parseOpenApi, isOpenApiDocument, GRAPHQL_PROBE, GRAPHQL_INTROSPECTION, looksLikeGraphql, introspectionEnabled, API_DOC_PATHS, GRAPHQL_PATHS, sameSite, type FormInfo, type ApiEndpoint } from "../crawl-core.ts";

// Crawls the site (static HTML, plus an optional headless browser pass for JavaScript-built pages), finds
// OpenAPI documents and GraphQL endpoints, and returns URLs with parameters for the vulnerability tests.

export interface CrawlOptions {
  pages: number;
  browser: boolean;
}

export interface CrawlData {
  origin: string;
  pagesVisited: string[];
  urls: string[];
  forms: FormInfo[];
  endpoints: (ApiEndpoint & { url: string })[];
  apiDocs: { url: string; endpoints: number }[];
  graphql: { url: string; introspection: boolean }[];
  browserUsed: boolean;
}

const MAX_URLS = 2000;

async function fetchPage(url: string): Promise<{ html: string; url: string } | null> {
  try {
    const r = await safeFetch(url, { timeoutMs: 10000, maxBytes: 400000 });
    if (r.status >= 400) return null;
    if (!/html/i.test(r.headers.get("content-type") ?? "")) return null;
    return { html: r.body, url: r.finalUrl };
  } catch {
    return null;
  }
}

/** Renders pages in headless Chromium and records every same-site request the page makes (XHR, fetch, scripts). */
async function browserPass(seed: string, host: string, pages: number, warnings: string[]): Promise<string[]> {
  let pw: typeof import("playwright");
  try {
    pw = await import("playwright");
  } catch {
    warnings.push("Playwright is not available, so the browser pass was skipped.");
    return [];
  }
  const proxy = activeProxy();
  let browser;
  try {
    browser = await pw.chromium.launch({
      executablePath: process.env.CHROMIUM_PATH || undefined,
      args: process.env.CHROMIUM_NO_SANDBOX === "1" ? ["--no-sandbox"] : [],
      proxy: proxy ? { server: proxy.url } : undefined,
    });
  } catch {
    warnings.push("Chromium could not start, so the browser pass was skipped. Install it on the Tools page.");
    return [];
  }
  const found = new Set<string>();
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    page.on("request", (req) => {
      if (sameSite(req.url(), host)) found.add(req.url().split("#")[0]);
    });
    const done = new Set<string>();
    const queue = [seed];
    while (queue.length && done.size < pages && found.size < MAX_URLS) {
      const url = queue.shift()!;
      if (done.has(url)) continue;
      done.add(url);
      try {
        await page.goto(url, { waitUntil: "networkidle", timeout: 20000 });
        const anchors = await page.$$eval("a[href]", (els) => els.map((a) => (a as HTMLAnchorElement).href));
        for (const a of anchors) if (sameSite(a, host)) found.add(a.split("#")[0]);
        if (done.size + queue.length < pages) {
          for (const a of anchors) {
            const clean = a.split("#")[0];
            if (sameSite(clean, host) && !done.has(clean) && !queue.includes(clean)) queue.push(clean);
          }
        }
      } catch {
        /* a page that fails to render is skipped */
      }
    }
  } finally {
    await browser.close().catch(() => undefined);
  }
  return [...found];
}

export async function crawlSite(t: ParsedTarget, o: CrawlOptions): Promise<ModuleOutput<CrawlData>> {
  const origin = t.url ? new URL(t.url).origin : `https://${t.host}`;
  const host = t.host;
  const warnings: string[] = [];
  const pages = Math.max(1, Math.min(50, o.pages || 15));

  // Probe the start page first, so an unreachable or blocked target is reported instead of an empty result.
  try {
    await safeFetch(`${origin}/`, { timeoutMs: 10000, maxBytes: 1000 });
  } catch (e) {
    throw new UserError(e instanceof UserError ? e.message : "The target did not respond. Check the domain, or the proxy in Settings.", "connect_failed");
  }

  const crawled = await crawlGraph(`${origin}/`, host, pages, fetchPage);
  if (!crawled.visited.length) warnings.push("The start page is not HTML, or it returned an error, so no links were followed.");
  let urls = new Set(crawled.urls);
  let browserUsed = false;
  if (o.browser) {
    browserUsed = true;
    for (const u of await browserPass(`${origin}/`, host, Math.min(pages, 10), warnings)) urls.add(u);
  }

  const findings: Finding[] = [];
  const apiDocs: CrawlData["apiDocs"] = [];
  const endpoints: (ApiEndpoint & { url: string })[] = [];
  for (const path of API_DOC_PATHS) {
    try {
      const r = await safeFetch(`${origin}${path}`, { timeoutMs: 8000, maxBytes: 2_000_000 });
      if (r.status !== 200) continue;
      const doc = JSON.parse(r.body) as unknown;
      if (!isOpenApiDocument(doc)) continue;
      const eps = parseOpenApi(doc);
      apiDocs.push({ url: `${origin}${path}`, endpoints: eps.length });
      for (const e of eps) endpoints.push({ ...e, url: `${origin}${e.path}` });
      const kb = VULN_KB["api-docs-exposed"];
      findings.push({ severity: "medium", title: `${kb.title} (${path})`, detail: `${kb.what} ${kb.why} ${eps.length} endpoint(s) are listed.`, evidence: `${origin}${path}`, recommendation: kb.fix, kind: "api-docs-exposed", impact: kb.impact, cwe: kb.cwe, references: kb.references, confidence: "confirmed" });
    } catch {
      /* not JSON or not reachable */
    }
  }

  const graphql: CrawlData["graphql"] = [];
  for (const path of GRAPHQL_PATHS) {
    try {
      const probe = await safeFetch(`${origin}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: GRAPHQL_PROBE, timeoutMs: 8000, maxBytes: 200000 });
      if (!looksLikeGraphql(probe.body)) continue;
      const intro = await safeFetch(`${origin}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: GRAPHQL_INTROSPECTION, timeoutMs: 10000, maxBytes: 2_000_000 });
      const enabled = introspectionEnabled(intro.body);
      graphql.push({ url: `${origin}${path}`, introspection: enabled });
      if (enabled) {
        const kb = VULN_KB["graphql-introspection"];
        findings.push({ severity: "medium", title: `${kb.title} (${path})`, detail: `${kb.what} ${kb.why}`, evidence: `${origin}${path}`, recommendation: kb.fix, kind: "graphql-introspection", impact: kb.impact, cwe: kb.cwe, references: kb.references, confidence: "confirmed" });
      }
    } catch {
      /* not reachable */
    }
  }

  // Every documented endpoint becomes a URL, with its query parameters, so the tests can reach it.
  for (const e of endpoints) {
    const base = e.url.replace(/\{[^}]+\}/g, "1");
    const u = new URL(base);
    for (const q of e.queryParams) u.searchParams.set(q, "test");
    urls.add(u.toString());
  }

  const list = [...urls].slice(0, MAX_URLS);
  const withParams = list.filter((u) => u.includes("?")).length;
  return {
    summary: `${crawled.visited.length} page(s) crawled · ${list.length} URL(s) (${withParams} with parameters) · ${endpoints.length} API endpoint(s) · ${findings.length} finding(s)`,
    findings,
    data: {
      origin,
      pagesVisited: crawled.visited,
      urls: list,
      forms: crawled.forms.slice(0, 200),
      endpoints: endpoints.slice(0, 500),
      apiDocs,
      graphql,
      browserUsed,
    },
    warnings,
  };
}

/** The URL list a crawl adds to the autopipeline's parameter filter. Errors give an empty list. */
export async function crawlUrlsFor(host: string, pages: number): Promise<string[]> {
  try {
    const parsed = { input: host, kind: "domain" as const, host };
    const r = await crawlSite(parsed, { pages, browser: false });
    return r.data.urls;
  } catch (e) {
    if (!(e instanceof UserError)) console.error("[crawl]", e);
    return [];
  }
}
