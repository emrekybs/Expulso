import "server-only";
import dns from "node:dns/promises";
import { fetchJson, UserError } from "../net.ts";
import { isIPv4, type ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, SourceStatus } from "../types.ts";

// Maps the target's IP addresses to their autonomous systems (Team Cymru DNS) and lists the prefixes
// each AS announces (RIPEstat). Read-only: nothing is sent to the target.

const MAX_IPS = 6;
const MAX_ASNS = 4;
const MAX_PREFIXES = 500;

export interface AsnIp {
  ip: string;
  asn: string;
  prefix: string;
  country: string;
  registry: string;
}

export interface AsnEntry {
  asn: string;
  name: string;
  ipv4Prefixes: number;
  ipv6Prefixes: number;
  addresses: number;
  prefixes: string[];
}

export interface AsnData {
  ips: AsnIp[];
  asns: AsnEntry[];
  sources: SourceStatus[];
}

interface RipeAnnounced {
  data?: { prefixes?: { prefix: string }[] };
}

function txt(records: string[][]): string {
  return records.map((r) => r.join("")).join(" ");
}

async function cymruOrigin(ip: string): Promise<AsnIp | null> {
  const reversed = ip.split(".").reverse().join(".");
  const fields = txt(await dns.resolveTxt(`${reversed}.origin.asn.cymru.com`)).split("|").map((s) => s.trim());
  if (!fields[0]) return null;
  return { ip, asn: fields[0].split(/\s+/)[0], prefix: fields[1] ?? "", country: fields[2] ?? "", registry: fields[3] ?? "" };
}

async function cymruName(asn: string): Promise<string> {
  try {
    const fields = txt(await dns.resolveTxt(`AS${asn}.asn.cymru.com`)).split("|").map((s) => s.trim());
    return fields[fields.length - 1]?.split(",")[0]?.trim() || "unknown";
  } catch {
    return "unknown";
  }
}

function addressesOf(prefix: string): number {
  const bits = Number(prefix.split("/")[1]);
  return Number.isInteger(bits) && bits >= 0 && bits <= 32 ? 2 ** (32 - bits) : 0;
}

export async function runAsnRanges(t: ParsedTarget): Promise<ModuleOutput<AsnData>> {
  const sources: SourceStatus[] = [];
  const warnings: string[] = [];

  let ips: string[];
  if (t.kind === "ip") ips = [t.host];
  else {
    try {
      ips = [...new Set(await dns.resolve4(t.host))];
    } catch {
      throw new UserError(`${t.host} has no IPv4 address to look up.`, "no_address");
    }
  }
  ips = ips.filter(isIPv4).slice(0, MAX_IPS);

  const started = Date.now();
  const origins = (await Promise.all(ips.map((ip) => cymruOrigin(ip).catch(() => null)))).filter((o): o is AsnIp => !!o);
  sources.push({ name: "Team Cymru (DNS)", ok: origins.length > 0, count: origins.length, ms: Date.now() - started, error: origins.length ? undefined : "No ASN found for the addresses." });

  const asnIds = [...new Set(origins.map((o) => o.asn))].slice(0, MAX_ASNS);
  const entries: AsnEntry[] = [];
  for (const asn of asnIds) {
    const started2 = Date.now();
    const name = await cymruName(asn);
    try {
      const res = await fetchJson<RipeAnnounced>(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`, 20000);
      const all = (res.data?.prefixes ?? []).map((p) => p.prefix);
      const v4 = all.filter((p) => !p.includes(":"));
      entries.push({
        asn,
        name,
        ipv4Prefixes: v4.length,
        ipv6Prefixes: all.length - v4.length,
        addresses: v4.reduce((n, p) => n + addressesOf(p), 0),
        prefixes: all.slice(0, MAX_PREFIXES),
      });
      sources.push({ name: `RIPEstat AS${asn}`, ok: true, count: all.length, ms: Date.now() - started2 });
    } catch {
      sources.push({ name: `RIPEstat AS${asn}`, ok: false, count: 0, error: "Prefix list could not be loaded.", ms: Date.now() - started2 });
      warnings.push(`Prefix list for AS${asn} could not be loaded.`);
      entries.push({ asn, name, ipv4Prefixes: 0, ipv6Prefixes: 0, addresses: 0, prefixes: [] });
    }
  }
  if (origins.length < ips.length) warnings.push(`${ips.length - origins.length} address(es) had no ASN record.`);

  const findings: Finding[] = entries.map((e) => ({
    severity: "info",
    title: `AS${e.asn} (${e.name}) announces ${e.ipv4Prefixes} IPv4 prefix(es)`,
    detail: `About ${e.addresses.toLocaleString("en-US")} IPv4 addresses are announced by this network${e.ipv6Prefixes ? `, plus ${e.ipv6Prefixes} IPv6 prefix(es)` : ""}. Every address in these prefixes belongs to the same organisation.`,
    evidence: e.prefixes.slice(0, 30).join("\n") || undefined,
  }));

  const totalPrefixes = entries.reduce((n, e) => n + e.ipv4Prefixes + e.ipv6Prefixes, 0);
  return {
    summary: `${entries.length} ASN(s) · ${totalPrefixes} announced prefix(es) for ${origins.length} IP(s)`,
    findings,
    data: {
      ips: origins,
      asns: entries,
      sources,
    },
    sources,
    warnings,
  };
}
