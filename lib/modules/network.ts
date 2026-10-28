import { mapLimit, UserError } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { ptr, resolveA4 } from "../dns-core.ts";
import { expandCidr, type ParsedTarget } from "../target.ts";
import type { ModuleOutput } from "../types.ts";

/* --------------------------- Reverse DNS --------------------------- */

export interface ReverseDnsData {
  target: string;
  entries: { ip: string; hostnames: string[] }[];
}

export async function runReverseDns(t: ParsedTarget): Promise<ModuleOutput<ReverseDnsData>> {
  let ips: string[];
  if (t.kind === "cidr") ips = expandCidr(t.host).slice(0, 256);
  else if (t.kind === "ip") ips = [t.host];
  else {
    ips = (await resolveA4(t.host)).slice(0, 16);
    if (!ips.length) throw new UserError(`No A record found for ${t.host}.`);
  }
  const entries = await mapLimit(ips, 10, async (ip) => ({ ip, hostnames: await ptr(ip).catch(() => []) }));
  const withNames = entries.filter((e) => e.hostnames.length);
  return {
    summary: `${withNames.length} of ${ips.length} IP(s) have PTR records`,
    findings: [],
    data: { target: t.input, entries },
  };
}

/* --------------------------- Reverse IP --------------------------- */

export interface ReverseIpData {
  target: string;
  byIp: { ip: string; domains: string[] }[];
  total: number;
  limited: boolean;
}

async function rapidDnsSameIp(ip: string): Promise<string[]> {
  const { status, text } = await import("../net.ts").then((m) => m.fetchText(`https://rapiddns.io/sameip/${encodeURIComponent(ip)}?full=1`, 20000));
  if (status !== 200) throw new Error(`HTTP ${status}`);
  const out = new Set<string>();
  for (const m of text.matchAll(/<td>([a-z0-9._-]+\.[a-z]{2,})<\/td>/gi)) out.add(m[1].toLowerCase());
  return [...out];
}

export async function runReverseIp(t: ParsedTarget): Promise<ModuleOutput<ReverseIpData>> {
  if (t.kind === "cidr") throw new UserError("Reverse IP needs a single domain or IP.");
  const ips = t.kind === "ip" ? [t.host] : (await resolveA4(t.host)).slice(0, 5);
  if (!ips.length) throw new UserError(`No A record found for ${t.host}.`);
  const warnings: string[] = [];
  const byIp = await mapLimit(ips, 3, async (ip) => {
    const set = new Set<string>();
    const ht = await htQuery("reverseiplookup", ip, 20000).catch((e) => {
      warnings.push(`HackerTarget for ${ip}: ${e instanceof UserError ? e.message : "failed"}`);
      return "";
    });
    ht.split("\n").map((l) => l.trim().toLowerCase()).filter((l) => l && !/\s/.test(l)).forEach((d) => set.add(d));
    const rd = await rapidDnsSameIp(ip).catch(() => [] as string[]);
    rd.forEach((d) => set.add(d));
    return { ip, domains: [...set].sort() };
  });
  const total = new Set(byIp.flatMap((x) => x.domains)).size;
  return {
    summary: `${total} domain(s) across ${ips.length} IP(s)`,
    findings: [],
    data: { target: t.input, byIp, total, limited: byIp.some((x) => x.domains.length >= 500) },
    warnings,
  };
}

/* --------------------------- GeoIP & ASN --------------------------- */

export interface GeoEntry {
  ip: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: number;
  org?: string;
  isp?: string;
  prefixes?: string[];
}

export interface GeoData {
  target: string;
  entries: GeoEntry[];
  asns: { asn: number; holder?: string; prefixCount?: number; prefixes: string[] }[];
}

interface IpWhoIs {
  success: boolean;
  message?: string;
  ip: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  connection?: { asn?: number; org?: string; isp?: string };
}

async function lookupGeo(ip: string): Promise<GeoEntry> {
  const { fetchJson } = await import("../net.ts");
  const j = await fetchJson<IpWhoIs>(`https://ipwho.is/${encodeURIComponent(ip)}`, 10000).catch(() => null);
  if (j && j.success)
    return { ip: j.ip, country: j.country, countryCode: j.country_code, region: j.region, city: j.city, latitude: j.latitude, longitude: j.longitude, asn: j.connection?.asn, org: j.connection?.org, isp: j.connection?.isp };
  // Fallback to RIPEstat network-info + whois for ASN only.
  const net = await fetchJson<{ data?: { asns?: string[]; prefix?: string } }>(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, 10000).catch(() => null);
  const asn = net?.data?.asns?.[0] ? Number(net.data.asns[0]) : undefined;
  return { ip, asn };
}

async function asnInfo(asn: number): Promise<{ asn: number; holder?: string; prefixCount?: number; prefixes: string[] }> {
  const { fetchJson } = await import("../net.ts");
  const [overview, prefixes] = await Promise.all([
    fetchJson<{ data?: { holder?: string } }>(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${asn}`, 10000).catch(() => null),
    fetchJson<{ data?: { prefixes?: { prefix: string }[] } }>(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`, 12000).catch(() => null),
  ]);
  const list = (prefixes?.data?.prefixes ?? []).map((p) => p.prefix);
  return { asn, holder: overview?.data?.holder, prefixCount: list.length, prefixes: list.slice(0, 500) };
}

export async function runGeoip(t: ParsedTarget): Promise<ModuleOutput<GeoData>> {
  let ips: string[];
  if (t.kind === "cidr") ips = expandCidr(t.host).filter((_, i) => i % 32 === 0).slice(0, 8);
  else if (t.kind === "ip" || /^[\d.]+$/.test(t.host)) ips = [t.host];
  else {
    ips = (await resolveA4(t.host)).slice(0, 8);
    if (!ips.length) throw new UserError(`No A record found for ${t.host}.`);
  }
  const entries = await mapLimit(ips, 5, lookupGeo);
  const uniqAsns = [...new Set(entries.map((e) => e.asn).filter((a): a is number => !!a))];
  const asns = await mapLimit(uniqAsns.slice(0, 5), 3, asnInfo);
  for (const e of entries) {
    const a = asns.find((x) => x.asn === e.asn);
    if (a) e.prefixes = a.prefixes.slice(0, 20);
  }
  const first = entries[0];
  const where = first ? [first.city, first.country].filter(Boolean).join(", ") : "";
  return {
    summary: `${entries.length} IP(s)${where ? ` · ${where}` : ""}${asns[0]?.holder ? ` · ${asns[0].holder}` : ""}`,
    findings: [],
    data: { target: t.input, entries, asns },
  };
}
