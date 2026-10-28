import { fetchJson, mapLimit, UserError } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { resolveA } from "./dns.ts";
import { registrableDomain } from "./whois.ts";
import type { ParsedTarget } from "../target.ts";

export interface SubdomainEntry {
  host: string;
  sources: string[];
  ips: string[];
  alive: boolean | null;
}

export interface SourceStatus {
  name: string;
  ok: boolean;
  count: number;
  error?: string;
}

export interface SubdomainResult {
  domain: string;
  subdomains: SubdomainEntry[];
  sources: SourceStatus[];
  resolved: number;
  resolveLimit: number;
}

type Source = { name: string; run: (d: string) => Promise<{ host: string; ip?: string }[]> };

const SOURCES: Source[] = [
  {
    name: "crt.sh (Sertifika Şeffaflığı)",
    run: async (d) => {
      const j = await fetchJson<{ name_value: string }[]>(`https://crt.sh/?q=${encodeURIComponent(`%.${d}`)}&output=json`, 25000);
      return j.flatMap((r) => r.name_value.split(/\s+/)).map((host) => ({ host }));
    },
  },
  {
    name: "HackerTarget",
    run: async (d) => {
      const text = await htQuery("hostsearch", d, 20000);
      return text
        .split("\n")
        .filter(Boolean)
        .map((l) => {
          const [host, ip] = l.split(",");
          return { host, ip };
        });
    },
  },
  {
    name: "AlienVault OTX",
    run: async (d) => {
      const j = await fetchJson<{ passive_dns?: { hostname: string; address: string; record_type: string }[] }>(
        `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(d)}/passive_dns`,
        20000,
      );
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
    name: "CertSpotter",
    run: async (d) => {
      const j = await fetchJson<{ dns_names: string[] }[]>(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(d)}&include_subdomains=true&expand=dns_names`,
        15000,
      );
      return j.flatMap((r) => r.dns_names).map((host) => ({ host }));
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

export async function runSubdomains(t: ParsedTarget, opts: { resolve?: boolean }): Promise<SubdomainResult> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Alt alan adı keşfi için bir alan adı girin.");
  const domain = registrableDomain(t.host);
  const map = new Map<string, SubdomainEntry>();
  const statuses = await Promise.all(
    SOURCES.map(async (s): Promise<SourceStatus> => {
      try {
        const rows = await s.run(domain);
        let count = 0;
        for (const r of rows) {
          const host = normalizeHost(r.host, domain);
          if (!host) continue;
          const e = map.get(host) ?? { host, sources: [], ips: [], alive: null };
          if (!e.sources.includes(s.name)) {
            e.sources.push(s.name);
            count++;
          }
          if (r.ip && /^[\d.]+$/.test(r.ip) && !e.ips.includes(r.ip)) e.ips.push(r.ip);
          map.set(host, e);
        }
        return { name: s.name, ok: true, count };
      } catch (e) {
        return { name: s.name, ok: false, count: 0, error: e instanceof UserError ? e.message : "Kaynağa ulaşılamadı veya zaman aşımı." };
      }
    }),
  );
  if (statuses.every((s) => !s.ok)) throw new UserError("Hiçbir alt alan adı kaynağına ulaşılamadı. Lütfen daha sonra tekrar deneyin.");

  const subdomains = [...map.values()].sort((a, b) => a.host.localeCompare(b.host));
  const resolveLimit = 200;
  let resolved = 0;
  if (opts.resolve !== false) {
    const subset = subdomains.slice(0, resolveLimit);
    const deadline = Date.now() + 20000;
    await mapLimit(subset, 16, async (e) => {
      if (Date.now() > deadline) return;
      try {
        const ips = await resolveA(e.host);
        e.alive = ips.length > 0;
        for (const ip of ips) if (!e.ips.includes(ip)) e.ips.push(ip);
        resolved++;
      } catch {
        /* çözümlenemedi */
      }
    });
  }
  return { domain, subdomains, sources: statuses, resolved, resolveLimit };
}
