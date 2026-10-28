import { safeFetch, UserError, mapLimit } from "../net.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";

export interface JsFile {
  url: string;
  origin: "first-party" | "third-party";
  status: number | null;
  size: number;
  endpoints: number;
  map: boolean;
  foundOn: string;
}
export interface Endpoint {
  value: string;
  type: string;
  file: string;
}
export interface Secret {
  kind: string;
  masked: string;
  file: string;
  confidence: "High" | "Medium" | "Low (often public)";
}
export interface JsData {
  target: string;
  pages: number;
  files: JsFile[];
  endpoints: Endpoint[];
  secrets: Secret[];
  stats: { files: number; firstParty: number; endpoints: number; secrets: number; maps: number };
}

const SECRET_PATTERNS: { kind: string; re: RegExp; confidence: Secret["confidence"] }[] = [
  { kind: "AWS access key ID", re: /\bAKIA[0-9A-Z]{16}\b/g, confidence: "High" },
  { kind: "AWS secret key", re: /\baws_secret_access_key["']?\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/gi, confidence: "High" },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, confidence: "Low (often public)" },
  { kind: "Firebase / GCP", re: /\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b/g, confidence: "Low (often public)" },
  { kind: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g, confidence: "High" },
  { kind: "Stripe secret key", re: /\bsk_live_[0-9A-Za-z]{24,}\b/g, confidence: "High" },
  { kind: "Stripe publishable key", re: /\bpk_live_[0-9A-Za-z]{24,}\b/g, confidence: "Low (often public)" },
  { kind: "GitHub token", re: /\bgh[pousr]_[0-9A-Za-z]{36}\b/g, confidence: "High" },
  { kind: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, confidence: "Medium" },
  { kind: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, confidence: "High" },
  { kind: "Generic secret assignment", re: /["']?(?:api[_-]?key|secret|token|passwd|password|access[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{16,64}["']/gi, confidence: "Medium" },
];

const ENDPOINT_RE = /["'`](\/[a-zA-Z0-9_?&=%./-]{2,}|https?:\/\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_?&=%./-]*|wss?:\/\/[a-zA-Z0-9_.:/-]+)["'`]/g;

function mask(s: string): string {
  if (s.length <= 10) return s.slice(0, 2) + "••••";
  return s.slice(0, 4) + "•".repeat(Math.min(12, s.length - 7)) + s.slice(-3);
}

function classifyEndpoint(e: string): string | null {
  if (/^wss?:\/\//.test(e)) return "WebSocket";
  if (/graphql/i.test(e)) return "GraphQL";
  if (/^https?:\/\//.test(e)) return "Full URL";
  if (/\/api\/|\/v\d+\/|\/rest\//i.test(e)) return "API";
  if (/\.(png|jpe?g|gif|svg|webp|css|woff2?|ttf|ico|map|mp4|webm)(\?|$)/i.test(e)) return null;
  if (e.length > 4 && e.startsWith("/")) return "Path";
  return null;
}

export async function runJs(t: ParsedTarget, opts: { maxPages?: number; thirdParty?: boolean }): Promise<ModuleOutput<JsData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("JS Crawler needs a domain or URL.");
  const start = t.url ?? `https://${t.host}/`;
  const base = new URL(start);
  const maxPages = Math.max(1, Math.min(60, Math.floor(opts.maxPages ?? 25)));
  const thirdParty = !!opts.thirdParty;
  const deadline = Date.now() + 50000;
  const warnings: string[] = [];

  // Crawl pages within scope, collect JS URLs.
  const visited = new Set<string>();
  const queue = [start];
  const jsUrls = new Map<string, string>(); // url -> first page it was seen on
  const seedPaths = ["/robots.txt", "/sitemap.xml"];

  const collectFromHtml = (html: string, pageUrl: string) => {
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) addJs(m[1], pageUrl);
    for (const m of html.matchAll(/["'`]([^"'`]+\.js(?:\?[^"'`]*)?)["'`]/gi)) addJs(m[1], pageUrl);
    for (const m of html.matchAll(/<a[^>]+href=["']([^"'#]+)["']/gi)) {
      try {
        const u = new URL(m[1], pageUrl);
        u.hash = "";
        if (u.host === base.host && (u.protocol === "http:" || u.protocol === "https:") && !/\.(png|jpe?g|gif|svg|webp|pdf|zip|css|js)$/i.test(u.pathname)) {
          if (!visited.has(u.toString()) && !queue.includes(u.toString())) queue.push(u.toString());
        }
      } catch {
        /* ignore */
      }
    }
  };
  const addJs = (ref: string, pageUrl: string) => {
    try {
      const u = new URL(ref, pageUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      if (!u.pathname.endsWith(".js")) return;
      const isFirst = u.host === base.host;
      if (!isFirst && !thirdParty) return;
      if (!jsUrls.has(u.toString())) jsUrls.set(u.toString(), pageUrl);
    } catch {
      /* ignore */
    }
  };

  for (const sp of seedPaths) queue.push(base.origin + sp);

  while (queue.length && visited.size < maxPages && Date.now() < deadline) {
    const batch = queue.splice(0, 5).filter((u) => !visited.has(u));
    if (!batch.length) continue;
    batch.forEach((u) => visited.add(u));
    await Promise.all(
      batch.map(async (url) => {
        try {
          const res = await safeFetch(url, { timeoutMs: 10000, maxBytes: 1_500_000 });
          const ct = res.headers.get("content-type") ?? "";
          if (/html|xml/i.test(ct) || /\.(html?|xml)$/i.test(new URL(url).pathname) || url.endsWith("/")) collectFromHtml(res.body, res.finalUrl);
        } catch (e) {
          if (visited.size === 1) warnings.push(`Start page: ${e instanceof UserError ? e.message : "fetch failed"}`);
        }
      }),
    );
  }
  if (!jsUrls.size && visited.size === 0) throw new UserError("Could not load the target site.", "connect_failed");

  // Fetch and analyse JS files.
  const files: JsFile[] = [];
  const endpoints = new Map<string, Endpoint>();
  const secrets = new Map<string, Secret>();
  const jsList = [...jsUrls.entries()].slice(0, 120);
  await mapLimit(jsList, 10, async ([url, page]) => {
    if (Date.now() > deadline) return;
    const isFirst = new URL(url).host === base.host;
    try {
      const res = await safeFetch(url, { timeoutMs: 10000, maxBytes: 4_000_000 });
      const body = res.body;
      let count = 0;
      for (const m of body.matchAll(ENDPOINT_RE)) {
        const type = classifyEndpoint(m[1]);
        if (!type) continue;
        count++;
        const key = m[1];
        if (!endpoints.has(key) && endpoints.size < 2000) endpoints.set(key, { value: key, type, file: shortName(url) });
      }
      for (const p of SECRET_PATTERNS)
        for (const m of body.matchAll(p.re)) {
          const val = m[0];
          const key = `${p.kind}:${val}`;
          if (!secrets.has(key)) secrets.set(key, { kind: p.kind, masked: mask(val.replace(/["']/g, "")), file: `${shortName(url)}`, confidence: p.confidence });
        }
      const hasMap = /\/\/[#@]\s*sourceMappingURL=/.test(body) || res.headers.get("sourcemap") != null;
      files.push({ url, origin: isFirst ? "first-party" : "third-party", status: res.status, size: body.length, endpoints: count, map: hasMap, foundOn: shortName(page) });
    } catch {
      files.push({ url, origin: isFirst ? "first-party" : "third-party", status: null, size: 0, endpoints: 0, map: false, foundOn: shortName(page) });
    }
  });
  if (jsUrls.size > jsList.length) warnings.push(`Analysed the first ${jsList.length} of ${jsUrls.size} JS files (limit).`);

  files.sort((a, b) => b.endpoints - a.endpoints);
  const stats = {
    files: files.length,
    firstParty: files.filter((f) => f.origin === "first-party").length,
    endpoints: endpoints.size,
    secrets: secrets.size,
    maps: files.filter((f) => f.map).length,
  };
  const findings: Finding[] = [];
  const realSecrets = [...secrets.values()].filter((s) => s.confidence !== "Low (often public)");
  if (realSecrets.length)
    findings.push({
      severity: "high",
      title: `${realSecrets.length} possible secret(s) in JavaScript`,
      detail: "Strings matching credential patterns were found in client-side JavaScript, where anyone can read them.",
      evidence: realSecrets.slice(0, 6).map((s) => `${s.kind}: ${s.masked} (${s.file})`).join("\n"),
      recommendation: "Verify each match. Rotate any real secret and move it server-side; client code should never hold privileged credentials.",
    });

  const data: JsData = { target: start, pages: visited.size, files, endpoints: [...endpoints.values()], secrets: [...secrets.values()], stats };
  return { summary: `${visited.size} pages · ${stats.files} JS files · ${stats.endpoints} endpoints${stats.secrets ? ` · ${stats.secrets} possible secrets` : ""}`, findings, data, warnings };
}

function shortName(url: string): string {
  try {
    const u = new URL(url);
    const file = u.pathname.split("/").pop() || u.pathname;
    return u.host === "" ? file : file || u.host;
  } catch {
    return url;
  }
}
