import { fetchJson, mapLimit, safeFetch, UserError, htmlTitle } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { resolveA, doh } from "../dns-core.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, SourceStatus } from "../types.ts";
import { TAKEOVER_SIGNATURES, matchTakeover } from "./takeover-core.ts";

export interface SubEntry {
  host: string;
  sources: string[];
  ips: string[];
  cname?: string;
  resolved: boolean | null;
  http?: { status: number; title: string; server?: string; redirect?: string } | null;
  takeover?: { service: string } | null;
}

export interface SubData {
  domain: string;
  wildcard: boolean;
  entries: SubEntry[];
  stats: { total: number; resolved: number; live: number; ok200: number; takeover: number };
}

type Source = { name: string; run: (d: string) => Promise<{ host: string; ip?: string }[]> };

/** One retry for flaky public endpoints (crt.sh often answers 502/timeout on the first try). */
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

const SOURCES: Source[] = [
  {
    name: "crt.sh",
    run: async (d) => {
      const j = await retry(() => fetchJson<{ name_value: string }[]>(`https://crt.sh/?q=${encodeURIComponent(`%.${d}`)}&output=json`, 20000));
      return j.flatMap((r) => r.name_value.split(/\s+/)).map((host) => ({ host }));
    },
  },
  {
    name: "Wayback Machine",
    run: async (d) => {
      // CDX index: every URL ever archived under the domain; keep unique hostnames.
      const rows = await fetchJson<string[][]>(`https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(d)}/*&output=json&fl=original&collapse=urlkey&limit=20000`, 25000);
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
    name: "Sonar (omnisint)",
    run: async (d) => {
      const j = await fetchJson<string[]>(`https://sonar.omnisint.io/subdomains/${encodeURIComponent(d)}`, 15000);
      return (Array.isArray(j) ? j : []).map((host) => ({ host }));
    },
  },
  {
    name: "CertSpotter",
    run: async (d) => {
      const j = await fetchJson<{ dns_names: string[] }[]>(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(d)}&include_subdomains=true&expand=dns_names`, 15000);
      return j.flatMap((r) => r.dns_names).map((host) => ({ host }));
    },
  },
  {
    name: "HackerTarget",
    run: async (d) => {
      const text = await htQuery("hostsearch", d, 20000);
      return text.split("\n").filter(Boolean).map((l) => {
        const [host, ip] = l.split(",");
        return { host, ip };
      });
    },
  },
  {
    name: "AlienVault OTX",
    run: async (d) => {
      const j = await fetchJson<{ passive_dns?: { hostname: string; address: string; record_type: string }[] }>(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(d)}/passive_dns`, 20000);
      return (j.passive_dns ?? []).map((r) => ({ host: r.hostname, ip: r.record_type === "A" ? r.address : undefined }));
    },
  },
  {
    name: "Anubis",
    run: async (d) => {
      const j = await fetchJson<string[]>(`https://jldc.me/anubis/subdomains/${encodeURIComponent(d)}`, 15000);
      return (Array.isArray(j) ? j : []).map((host) => ({ host }));
    },
  },
  {
    name: "RapidDNS",
    run: async (d) => {
      const { status, text } = await import("../net.ts").then((m) => m.fetchText(`https://rapiddns.io/subdomain/${encodeURIComponent(d)}?full=1`, 20000));
      if (status !== 200) throw new Error(`HTTP ${status}`);
      const out: { host: string }[] = [];
      for (const m of text.matchAll(/<td>([a-z0-9._-]+\.[a-z]{2,})<\/td>/gi)) out.push({ host: m[1] });
      return out;
    },
  },
  {
    name: "urlscan.io",
    run: async (d) => {
      const j = await fetchJson<{ results?: { page?: { domain?: string }; task?: { domain?: string } }[] }>(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(d)}&size=1000`, 15000);
      return (j.results ?? []).flatMap((r) => [r.page?.domain, r.task?.domain]).filter(Boolean).map((host) => ({ host: host as string }));
    },
  },
  {
    name: "ThreatMiner",
    run: async (d) => {
      const j = await fetchJson<{ results?: string[] }>(`https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(d)}&rt=5`, 15000);
      return (j.results ?? []).map((host) => ({ host }));
    },
  },
];

export function normalizeHost(h: string, domain: string): string | null {
  const host = h.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!host || host.includes("*") || host.includes("@") || host.includes(" ")) return null;
  if (host !== domain && !host.endsWith(`.${domain}`)) return null;
  if (!/^[a-z0-9._-]+$/.test(host)) return null;
  return host;
}

export async function runSubdomains(t: ParsedTarget, opts: { resolve?: boolean; httpStatus?: boolean }): Promise<ModuleOutput<SubData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Subdomain Enumeration needs a domain.");
  const domain = registrableDomain(t.host);
  const map = new Map<string, SubEntry>();
  // One overall time budget: Vercel functions are cut at 60 s, so every phase is bounded from the start.
  const started = Date.now();
  const deadline = started + 36000;

  const sources: SourceStatus[] = await Promise.all(
    SOURCES.map(async (s): Promise<SourceStatus> => {
      const t0 = Date.now();
      try {
        const rows = await s.run(domain);
        let count = 0;
        for (const r of rows) {
          const host = normalizeHost(r.host, domain);
          if (!host) continue;
          const e = map.get(host) ?? { host, sources: [], ips: [], resolved: null };
          if (!e.sources.includes(s.name)) {
            e.sources.push(s.name);
            count++;
          }
          if (r.ip && /^[\d.]+$/.test(r.ip) && !e.ips.includes(r.ip)) e.ips.push(r.ip);
          map.set(host, e);
        }
        return { name: s.name, ok: true, count, ms: Date.now() - t0 };
      } catch (e) {
        return { name: s.name, ok: false, count: 0, error: e instanceof UserError ? e.message : "Source unreachable or timed out.", ms: Date.now() - t0 };
      }
    }),
  );
  if (sources.every((s) => !s.ok)) throw new UserError("No subdomain source could be reached. Try again later.", "all_sources_failed");

  const entries = [...map.values()].sort((a, b) => a.host.localeCompare(b.host));
  const warnings: string[] = [];

  // Wildcard detection
  let wildcard = false;
  try {
    const rnd = `zzq${Math.random().toString(36).slice(2, 8)}.${domain}`;
    wildcard = (await resolveA(rnd)).length > 0;
    if (wildcard) warnings.push("Wildcard DNS detected: resolution results may include non-existent hosts.");
  } catch {
    /* ignore */
  }

  if (opts.resolve !== false) {
    const subset = entries.slice(0, 400);
    await mapLimit(subset, 20, async (e) => {
      if (Date.now() > deadline) return;
      try {
        const cn = await doh(e.host, "CNAME").catch(() => null);
        if (cn && cn.records.length) e.cname = cn.records[0].value;
        const ips = await resolveA(e.host);
        e.resolved = ips.length > 0;
        for (const ip of ips) if (!e.ips.includes(ip)) e.ips.push(ip);
        if (e.cname) {
          const tk = matchTakeover(e.cname, "");
          if (tk) e.takeover = { service: tk };
        }
      } catch {
        e.resolved = false;
      }
    });
    if (entries.length > subset.length) warnings.push(`Resolved the first ${subset.length} of ${entries.length} names (limit).`);
  }

  if (opts.httpStatus) {
    const live = entries.filter((e) => e.resolved).slice(0, 150);
    const httpDeadline = started + 50000;
    await mapLimit(live, 16, async (e) => {
      if (Date.now() > httpDeadline) return;
      try {
        const res = await safeFetch(`https://${e.host}/`, { timeoutMs: 8000, maxBytes: 200000, followRedirects: false });
        e.http = {
          status: res.status,
          title: htmlTitle(res.body),
          server: res.headers.get("server") ?? undefined,
          redirect: res.status >= 300 && res.status < 400 ? res.headers.get("location") ?? undefined : undefined,
        };
        if (e.takeover == null) {
          const tk = matchTakeover(e.cname ?? "", res.body);
          if (tk) e.takeover = { service: tk };
        }
      } catch {
        e.http = null;
      }
    });
    if (entries.filter((e) => e.resolved).length > live.length) warnings.push(`HTTP status checked for the first ${live.length} live hosts (limit).`);
  }

  const stats = {
    total: entries.length,
    resolved: entries.filter((e) => e.resolved).length,
    live: entries.filter((e) => e.http && e.http.status > 0).length,
    ok200: entries.filter((e) => e.http?.status === 200).length,
    takeover: entries.filter((e) => e.takeover).length,
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
  return { summary: `${stats.total} subdomains · ${stats.resolved} resolved${opts.httpStatus ? ` · ${stats.ok200} return 200` : ""}${stats.takeover ? ` · ${stats.takeover} takeover` : ""}`, findings, data, sources, warnings };
}

export { TAKEOVER_SIGNATURES };
