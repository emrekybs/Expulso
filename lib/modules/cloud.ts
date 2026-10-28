import { fetchJson, UserError } from "../net.ts";
import { resolveA4 } from "../dns-core.ts";
import { expandCidr, ipInCidr, ipv4ToInt, type ParsedTarget } from "../target.ts";
import type { ModuleOutput } from "../types.ts";

export interface CloudHit {
  ip: string;
  provider: string;
  detail?: string;
}
export interface CloudData {
  target: string;
  hits: CloudHit[];
  providers: string[];
}

interface Range {
  cidr: string;
  provider: string;
  detail?: string;
}

let cache: { at: number; ranges: Range[] } | null = null;
const TTL = 6 * 60 * 60 * 1000;

async function loadRanges(): Promise<Range[]> {
  if (cache && Date.now() - cache.at < TTL) return cache.ranges;
  const ranges: Range[] = [];
  // AWS
  await fetchJson<{ prefixes: { ip_prefix: string; region: string; service: string }[] }>("https://ip-ranges.amazonaws.com/ip-ranges.json", 15000)
    .then((j) => {
      for (const p of j.prefixes) if (p.service !== "AMAZON") ranges.push({ cidr: p.ip_prefix, provider: "AWS", detail: `${p.service} · ${p.region}` });
    })
    .catch(() => {});
  // Google Cloud
  await fetchJson<{ prefixes: { ipv4Prefix?: string; scope?: string; service?: string }[] }>("https://www.gstatic.com/ipranges/cloud.json", 15000)
    .then((j) => {
      for (const p of j.prefixes) if (p.ipv4Prefix) ranges.push({ cidr: p.ipv4Prefix, provider: "Google Cloud", detail: [p.service, p.scope].filter(Boolean).join(" · ") });
    })
    .catch(() => {});
  // Cloudflare
  await import("../net.ts")
    .then((m) => m.fetchText("https://www.cloudflare.com/ips-v4", 10000))
    .then(({ text }) => text.split(/\s+/).filter(Boolean).forEach((c) => ranges.push({ cidr: c, provider: "Cloudflare" })))
    .catch(() => {});
  // Fastly
  await fetchJson<{ addresses: string[] }>("https://api.fastly.com/public-ip-list", 10000)
    .then((j) => j.addresses.forEach((c) => ranges.push({ cidr: c, provider: "Fastly" })))
    .catch(() => {});
  cache = { at: Date.now(), ranges };
  return ranges;
}

function matchIp(ip: string, ranges: Range[]): Range | null {
  for (const r of ranges) {
    if (!r.cidr.includes("/") || r.cidr.includes(":")) continue;
    if (ipInCidr(ip, r.cidr)) return r;
  }
  return null;
}

export async function runCloud(t: ParsedTarget): Promise<ModuleOutput<CloudData>> {
  let ips: string[];
  if (t.kind === "cidr") ips = expandCidr(t.host).filter((_, i) => i % 16 === 0).slice(0, 16);
  else if (t.kind === "ip" || /^[\d.]+$/.test(t.host)) ips = [t.host];
  else {
    ips = (await resolveA4(t.host)).slice(0, 8);
    if (!ips.length) throw new UserError(`No A record found for ${t.host}.`);
  }
  const ranges = await loadRanges();
  const warnings: string[] = [];
  if (!ranges.length) warnings.push("Could not load any provider IP ranges; results may be incomplete.");
  const hits: CloudHit[] = [];
  for (const ip of ips) {
    const m = matchIp(ip, ranges);
    hits.push({ ip, provider: m?.provider ?? "Unknown / on-premise", detail: m?.detail });
  }
  const providers = [...new Set(hits.map((h) => h.provider))];
  void ipv4ToInt;
  return { summary: providers.join(", "), findings: [], data: { target: t.input, hits, providers }, warnings };
}
