import { fetchJson, UserError } from "./net.ts";

export const RR_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"] as const;
export type RRType = (typeof RR_TYPES)[number] | "PTR";

const TYPE_NUM: Record<number, RRType> = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA" };

export interface DnsRecord {
  type: RRType;
  name: string;
  ttl: number;
  value: string;
  priority?: number;
}

interface DohResponse {
  Status: number;
  Answer?: { name: string; type: number; TTL: number; data: string }[];
}

const RESOLVERS = [
  (n: string, t: string) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
  (n: string, t: string) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`,
];

/** DNS-over-HTTPS query with Cloudflare, falling back to Google. Status 3 = NXDOMAIN. */
export async function doh(name: string, type: RRType): Promise<{ status: number; records: DnsRecord[] }> {
  let lastErr: unknown;
  for (const build of RESOLVERS) {
    try {
      const j = await fetchJson<DohResponse>(build(name, type), 8000, { accept: "application/dns-json" });
      const records = (j.Answer ?? [])
        .filter((a) => TYPE_NUM[a.type] === type)
        .map((a): DnsRecord => {
          const nm = a.name.replace(/\.$/, "");
          if (type === "MX") {
            const [p, ...rest] = a.data.split(" ");
            return { type, name: nm, ttl: a.TTL, priority: Number(p), value: rest.join(" ").replace(/\.$/, "") };
          }
          if (type === "TXT") return { type, name: nm, ttl: a.TTL, value: a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, "") };
          return { type, name: nm, ttl: a.TTL, value: a.data.replace(/\.$/, "") };
        });
      return { status: j.Status, records };
    } catch (e) {
      lastErr = e;
    }
  }
  throw new UserError(`DNS query failed${lastErr instanceof Error ? ` (${lastErr.message})` : ""}.`, "dns_failed");
}

export async function resolveA(host: string): Promise<string[]> {
  const [a, aaaa] = await Promise.all([doh(host, "A").catch(() => null), doh(host, "AAAA").catch(() => null)]);
  const out = new Set<string>();
  a?.records.forEach((r) => out.add(r.value));
  aaaa?.records.forEach((r) => out.add(r.value));
  return [...out];
}

export async function resolveA4(host: string): Promise<string[]> {
  return (await doh(host, "A").catch(() => ({ records: [] as DnsRecord[] }))).records.map((r) => r.value);
}

/** True if the name resolves to anything (A/AAAA/CNAME). */
export async function isRegistered(host: string): Promise<boolean> {
  const r = await doh(host, "A").catch(() => null);
  if (r && (r.records.length > 0 || r.status === 0)) return r.records.length > 0 || (await hasAny(host));
  return false;
}

async function hasAny(host: string): Promise<boolean> {
  for (const t of ["AAAA", "CNAME", "MX", "NS"] as RRType[]) {
    const r = await doh(host, t).catch(() => null);
    if (r && r.records.length) return true;
  }
  return false;
}

export function reverseName(ip: string): string {
  if (ip.includes(":")) {
    const full = expandV6(ip).replace(/:/g, "");
    return [...full].reverse().join(".") + ".ip6.arpa";
  }
  return ip.split(".").reverse().join(".") + ".in-addr.arpa";
}

function expandV6(ip: string): string {
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const mid = Array(Math.max(0, 8 - h.length - t.length)).fill("0");
  return [...h, ...mid, ...t].map((g) => g.padStart(4, "0")).join(":");
}

export async function ptr(ip: string): Promise<string[]> {
  return (await doh(reverseName(ip), "PTR")).records.map((r) => r.value);
}
