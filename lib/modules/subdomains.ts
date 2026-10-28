import dns from "node:dns/promises";
import { fetchJson, fetchText, mapLimit, safeFetch, UserError, htmlTitle, isPrivateIp } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, SourceStatus } from "../types.ts";
import { matchTakeover } from "./takeover-core.ts";
import { runTool } from "../tools.ts";
import { SUB_WORDS } from "./sub-words.ts";

export interface SubEntry {
  host: string;
  sources: string[];
  ips: string[];
  cname?: string;
  resolved: boolean | null;
  http?: { status: number; title: string; server?: string; redirect?: string; scheme: "https" | "http" } | null;
  takeover?: { service: string } | null;
  /** File name under data/screenshots when a screenshot was taken. */
  shot?: string;
}

export interface SubData {
  domain: string;
  wildcard: boolean;
  entries: SubEntry[];
  stats: { total: number; resolved: number; live: number; ok200: number; takeover: number; screenshots: number };
}

export interface SubOptions {
  resolve?: boolean;
  httpStatus?: boolean;
  /** Run the installed subfinder / assetfinder / findomain binaries when they are available. */
  tools?: boolean;
  /** Built-in DNS brute force with a wordlist (knockpy-style: wildcard-aware). */
  dnsBrute?: boolean;
  bruteSize?: "small" | "large";
  screenshots?: boolean;
}

type Found = { host: string; ip?: string };
type Source = { name: string; run: (d: string) => Promise<Found[]> };

async function retry<T>(fn: () => Promise<T>, attempts = 2): Promise<T> {
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      last = e;
      if (e instanceof UserError && e.code === "rate_limited") break;
    }
  }
  throw last;
}

const PASSIVE_APIS: Source[] = [
  {
    name: "crt.sh",
    run: async (d) => {
      const j = await retry(() => fetchJson<{ name_value: string }[]>(`https://crt.sh/?q=${encodeURIComponent(`%.${d}`)}&output=json`, 40000));
      return j.flatMap((r) => r.name_value.split(/\s+/)).map((host) => ({ host }));
    },
  },
  {
    name: "CertSpotter",
    run: async (d) => {
      const j = await fetchJson<{ dns_names: string[] }[]>(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(d)}&include_subdomains=true&expand=dns_names`, 30000);
      return j.flatMap((r) => r.dns_names).map((host) => ({ host }));
    },
  },
  {
    name: "HackerTarget",
    run: async (d) => {
      const text = await htQuery("hostsearch", d, 30000);
      return text.split("\n").filter(Boolean).map((l) => {
        const [host, ip] = l.split(",");
        return { host, ip };
      });
    },
  },
  {
    name: "AlienVault OTX",
    run: async (d) => {
      const j = await fetchJson<{ passive_dns?: { hostname: string; address: string; record_type: string }[] }>(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(d)}/passive_dns`, 30000);
      return (j.passive_dns ?? []).map((r) => ({ host: r.hostname, ip: r.record_type === "A" ? r.address : undefined }));
    },
  },
  {
    name: "Anubis",
    run: async (d) => {
      const j = await fetchJson<string[]>(`https://jldc.me/anubis/subdomains/${encodeURIComponent(d)}`, 30000);
      return (Array.isArray(j) ? j : []).map((host) => ({ host }));
    },
  },
  {
    name: "RapidDNS",
    run: async (d) => {
      const { status, text } = await fetchText(`https://rapiddns.io/subdomain/${encodeURIComponent(d)}?full=1`, 30000);
      if (status !== 200) throw new Error(`HTTP ${status}`);
      const out: Found[] = [];
      for (const m of text.matchAll(/<td>([a-z0-9._-]+\.[a-z]{2,})<\/td>/gi)) out.push({ host: m[1] });
      return out;
    },
  },
  {
    name: "Wayback Machine",
    run: async (d) => {
      // CDX index: every URL archived under the domain; keep unique hostnames.
      const rows = await fetchJson<string[][]>(`https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(d)}/*&output=json&fl=original&collapse=urlkey&limit=20000`, 60000);
      return rows.slice(1).flatMap(([url]) => {
        try {
          return [{ host: new URL(url).hostname }];
        } catch {
          return [];
        }
      });
    },
  },
  {
    name: "urlscan.io",
    run: async (d) => {
      const j = await fetchJson<{ results?: { page?: { domain?: string }; task?: { domain?: string } }[] }>(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(d)}&size=1000`, 30000);
      return (j.results ?? []).flatMap((r) => [r.page?.domain, r.task?.domain]).filter(Boolean).map((host) => ({ host: host as string }));
    },
  },
  {
    name: "ThreatMiner",
    run: async (d) => {
      const j = await fetchJson<{ results?: string[] }>(`https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(d)}&rt=5`, 30000);
      return (j.results ?? []).map((host) => ({ host }));
    },
  },
  {
    name: "Sonar (omnisint)",
    run: async (d) => {
      const j = await fetchJson<string[]>(`https://sonar.omnisint.io/subdomains/${encodeURIComponent(d)}`, 30000);
      return (Array.isArray(j) ? j : []).map((host) => ({ host }));
    },
  },
];

/** Installed command-line tools. Each returns hostnames, one per output line. */
const TOOL_SOURCES: Source[] = [
  { name: "subfinder", run: async (d) => toHosts((await runTool("subfinder", ["-d", d, "-silent"], 240000)), "subfinder") },
  { name: "assetfinder", run: async (d) => toHosts((await runTool("assetfinder", ["--subs-only", d], 240000)), "assetfinder") },
  { name: "findomain", run: async (d) => toHosts((await runTool("findomain", ["-t", d, "-q"], 240000)), "findomain") },
];

function toHosts(r: { ok: boolean; lines: string[]; error?: string }, tool: string): Found[] {
  if (!r.ok) throw new UserError(r.error ?? `${tool} failed`, "tool_missing");
  return r.lines.map((host) => ({ host: host.split(/\s+/)[0] }));
}

export function normalizeHost(h: string, domain: string): string | null {
  const host = h.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!host || host.includes("*") || host.includes("@") || host.includes(" ")) return null;
  if (host !== domain && !host.endsWith(`.${domain}`)) return null;
  if (!/^[a-z0-9._-]+$/.test(host)) return null;
  return host;
}

/** Local resolution with the system resolver (A, then CNAME). */
async function resolveLocal(host: string): Promise<{ ips: string[]; cname?: string }> {
  const [a, cname] = await Promise.all([
    dns.resolve4(host).catch(() => [] as string[]),
    dns.resolveCname(host).then((c) => c[0]).catch(() => undefined),
  ]);
  return { ips: a, cname };
}

/** Random label under the domain: if it resolves, the zone answers every name (wildcard DNS). */
async function wildcardIps(domain: string): Promise<Set<string>> {
  const probe = `b24x${Math.random().toString(36).slice(2, 10)}.${domain}`;
  return new Set(await dns.resolve4(probe).catch(() => [] as string[]));
}

export async function runSubdomains(t: ParsedTarget, opts: SubOptions): Promise<ModuleOutput<SubData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Subdomain Enumeration needs a domain.");
  const domain = registrableDomain(t.host);
  const map = new Map<string, SubEntry>();
  const addFound = (sourceName: string, host: string, ip?: string) => {
    const h = normalizeHost(host, domain);
    if (!h) return false;
    const e = map.get(h) ?? { host: h, sources: [], ips: [], resolved: null };
    const fresh = !e.sources.includes(sourceName);
    if (fresh) e.sources.push(sourceName);
    if (ip && /^[\d.]+$/.test(ip) && !e.ips.includes(ip)) e.ips.push(ip);
    map.set(h, e);
    return fresh;
  };

  const sources: SourceStatus[] = [];
  const useTools = opts.tools !== false;
  const all = [...PASSIVE_APIS, ...(useTools ? TOOL_SOURCES : [])];
  const results = await Promise.all(
    all.map(async (s): Promise<SourceStatus> => {
      const t0 = Date.now();
      try {
        const rows = await s.run(domain);
        let count = 0;
        for (const r of rows) if (addFound(s.name, r.host, r.ip)) count++;
        return { name: s.name, ok: true, count, ms: Date.now() - t0 };
      } catch (e) {
        const isTool = TOOL_SOURCES.some((x) => x.name === s.name);
        return {
          name: s.name,
          ok: false,
          count: 0,
          error: e instanceof UserError ? e.message : isTool ? `${s.name} failed.` : "Source unreachable or timed out.",
          ms: Date.now() - t0,
        };
      }
    }),
  );
  sources.push(...results);
  if (!useTools) sources.push({ name: "Installed tools", ok: false, count: 0, error: "Tool sources turned off in options." });

  const warnings: string[] = [];
  const missing = TOOL_SOURCES.filter((t) => sources.find((s) => s.name === t.name && !s.ok && /not installed/.test(s.error ?? "")));
  if (missing.length) warnings.push(`Not installed (skipped): ${missing.map((t) => t.name).join(", ")}. See the Tools page for install commands.`);
  if (sources.every((s) => !s.ok) && opts.dnsBrute === false) warnings.push("No source returned data. Check your internet connection, and install subfinder, assetfinder or findomain to add more sources.");

  // DNS brute force (built-in wordlist, wildcard-aware).
  let wildcard = false;
  let wild = new Set<string>();
  try {
    wild = await wildcardIps(domain);
    wildcard = wild.size > 0;
    if (wildcard) warnings.push(`Wildcard DNS detected (${[...wild].join(", ")}). Brute-force answers that point to the wildcard IP are ignored.`);
  } catch {
    /* ignore */
  }
  if (opts.dnsBrute !== false) {
    const words = opts.bruteSize === "large" ? SUB_WORDS : SUB_WORDS.slice(0, 150);
    const candidates = words.map((w) => `${w}.${domain}`).filter((c) => !map.has(c));
    let hits = 0;
    await mapLimit(candidates, 40, async (c) => {
      const { ips } = await resolveLocal(c);
      if (!ips.length) return;
      if (ips.every((ip) => wild.has(ip))) return;
      if (addFound("DNS brute (built-in)", c, ips[0])) hits++;
    });
    sources.push({ name: "DNS brute (built-in, knockpy-style)", ok: true, count: hits });
  }

  const entries = [...map.values()].sort((a, b) => a.host.localeCompare(b.host));

  if (opts.resolve !== false) {
    const deadline = Date.now() + 90000;
    await mapLimit(entries.slice(0, 1200), 30, async (e) => {
      if (Date.now() > deadline) return;
      const r = await resolveLocal(e.host);
      e.resolved = r.ips.length > 0 || !!r.cname;
      r.ips.forEach((ip) => e.ips.includes(ip) || e.ips.push(ip));
      if (r.cname) e.cname = r.cname.replace(/\.$/, "");
      if (e.cname) {
        const tk = matchTakeover(e.cname, "");
        if (tk && !e.resolved) e.takeover = { service: tk };
      }
    });
    if (entries.length > 1200) warnings.push(`Resolved the first 1200 of ${entries.length} names (limit).`);
  }

  if (opts.httpStatus) {
    const live = entries.filter((e) => e.resolved && e.ips.some((ip) => !isPrivateIp(ip))).slice(0, 300);
    const deadline = Date.now() + 150000;
    await mapLimit(live, 25, async (e) => {
      if (Date.now() > deadline) return;
      for (const scheme of ["https", "http"] as const) {
        try {
          const res = await safeFetch(`${scheme}://${e.host}/`, { timeoutMs: 8000, maxBytes: 200000, followRedirects: false });
          e.http = {
            scheme,
            status: res.status,
            title: htmlTitle(res.body),
            server: res.headers.get("server") ?? undefined,
            redirect: res.status >= 300 && res.status < 400 ? res.headers.get("location") ?? undefined : undefined,
          };
          if (!e.takeover && e.cname) {
            const tk = matchTakeover(e.cname, res.body);
            if (tk) e.takeover = { service: tk };
          }
          return;
        } catch {
          /* try the next scheme */
        }
      }
      e.http = null;
    });
    if (live.length === 300) warnings.push("HTTP status checked for the first 300 live hosts (limit).");
  }

  if (opts.screenshots) {
    const { captureScreenshots } = await import("../screenshot.ts");
    const targets = entries
      .filter((e) => e.http && e.http.status > 0 && e.http.status < 500)
      .slice(0, 40)
      .map((e) => ({ host: e.host, scheme: e.http!.scheme }));
    const shots = await captureScreenshots(targets);
    for (const s of shots) {
      const e = map.get(s.host);
      if (e && s.file) e.shot = s.file;
      if (s.error) warnings.push(`Screenshot ${s.host}: ${s.error}`);
    }
  }

  const stats = {
    total: entries.length,
    resolved: entries.filter((e) => e.resolved).length,
    live: entries.filter((e) => e.http && e.http.status > 0).length,
    ok200: entries.filter((e) => e.http?.status === 200).length,
    takeover: entries.filter((e) => e.takeover).length,
    screenshots: entries.filter((e) => e.shot).length,
  };

  const findings: Finding[] = [];
  const tk = entries.filter((e) => e.takeover);
  if (tk.length)
    findings.push({
      severity: "high",
      title: `${tk.length} possible subdomain takeover${tk.length > 1 ? "s" : ""}`,
      detail: "A CNAME points to a third-party service that looks unclaimed. Anyone who claims it could serve content under your domain.",
      evidence: tk.slice(0, 6).map((e) => `${e.host} → ${e.cname} (${e.takeover?.service})`).join("\n"),
      recommendation: "Remove the stale DNS record or re-claim the resource on the provider.",
    });
  const devHosts = entries.filter((e) => /\b(dev|test|stag|staging|uat|preprod|internal|admin|vpn|jenkins|gitlab|jira)\b/.test(e.host)).slice(0, 12);
  if (devHosts.length)
    findings.push({
      severity: "info",
      title: "Development / internal-looking hosts are publicly listed",
      detail: "These names appear in public sources and may be less hardened than production.",
      evidence: devHosts.map((e) => e.host).join(", "),
      recommendation: "Confirm they are meant to be internet-facing; restrict access where possible.",
    });

  const data: SubData = { domain, wildcard, entries, stats };
  const okSrc = sources.filter((s) => s.ok).length;
  return {
    summary: `${stats.total} subdomains · ${stats.resolved} resolved${opts.httpStatus ? ` · ${stats.ok200} return 200` : ""} · ${okSrc}/${sources.length} sources`,
    findings,
    data,
    sources,
    warnings,
  };
}
