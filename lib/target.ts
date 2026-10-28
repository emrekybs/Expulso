// Target parsing shared by client and server. No Node APIs here.

export type TargetKind = "domain" | "ip" | "cidr" | "url";

export interface ParsedTarget {
  input: string;
  kind: TargetKind;
  /** Lower-cased, punycode host name or IP. For CIDR this is the network in a.b.c.d/n form. */
  host: string;
  /** Only set when kind === "url". */
  url?: string;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const DOMAIN = /^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

export function isIPv4(v: string): boolean {
  return IPV4.test(v);
}

export function isIPv6(v: string): boolean {
  if (!v.includes(":") || !/^[0-9a-f:.]+$/i.test(v)) return false;
  if (v.split("::").length > 2) return false;
  const groups = v.split(":").filter(Boolean);
  return groups.length <= 8 && groups.every((g) => g.length <= 4 || isIPv4(g));
}

export function isIP(v: string): boolean {
  return isIPv4(v) || isIPv6(v);
}

export function isDomain(v: string): boolean {
  return DOMAIN.test(v);
}

function toAsciiHost(host: string): string | null {
  try {
    return new URL(`http://${host}`).hostname.replace(/\.$/, "");
  } catch {
    return null;
  }
}

export const MAX_CIDR_PREFIX = 24; // a /24 (256 addresses) is the largest range we expand

export function parseTarget(raw: string): ParsedTarget | { error: string } {
  const input = raw.trim();
  if (!input) return { error: "Enter a target." };
  if (input.length > 2048) return { error: "Target is too long." };

  const cidr = input.match(/^([\d.]+)\/(\d{1,2})$/);
  if (cidr) {
    if (!isIPv4(cidr[1]) || Number(cidr[2]) > 32) return { error: `"${input}" is not a valid IPv4 range.` };
    const bits = Number(cidr[2]);
    if (bits < MAX_CIDR_PREFIX) return { error: `Ranges larger than /${MAX_CIDR_PREFIX} (256 addresses) are not supported.` };
    return { input, kind: "cidr", host: `${networkAddress(cidr[1], bits)}/${bits}` };
  }

  const bare = input.replace(/^\[|\]$/g, "");
  if (isIP(bare)) return { input, kind: "ip", host: bare.toLowerCase() };

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
  const hasPath = /[/?#]/.test(input);
  if (hasScheme || hasPath) {
    try {
      const u = new URL(hasScheme ? input : `https://${input}`);
      if (u.protocol !== "http:" && u.protocol !== "https:") return { error: "Only http and https URLs are supported." };
      const host = u.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
      if (!isIP(host) && !isDomain(host)) return { error: `"${input}" is not a valid URL.` };
      return { input, kind: "url", host, url: u.toString() };
    } catch {
      return { error: `"${input}" is not a valid URL.` };
    }
  }

  const host = toAsciiHost(input.toLowerCase());
  if (host && isDomain(host)) return { input, kind: "domain", host };
  return { error: `"${input}" is not a valid domain, IP, range or URL.` };
}

/** Splits a bulk text area into unique, non-empty targets (newlines, commas, spaces). */
export function splitTargets(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const noComment = line.replace(/#.*$/, ""); // drop line comments
    for (const part of noComment.split(/[\s,;]+/)) {
      const t = part.trim();
      if (!t) continue;
      const key = t.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(t);
    }
  }
  return out;
}

export function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
}

export function intToIpv4(n: number): string {
  return [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join(".");
}

export function networkAddress(ip: string, bits: number): string {
  const size = 2 ** (32 - bits);
  return intToIpv4(Math.floor(ipv4ToInt(ip) / size) * size);
}

/** All addresses in a CIDR (network and broadcast included for /31 and /32, excluded otherwise). */
export function expandCidr(cidr: string): string[] {
  const [base, b] = cidr.split("/");
  const bits = Number(b);
  const size = 2 ** (32 - bits);
  const start = Math.floor(ipv4ToInt(base) / size) * size;
  const out: string[] = [];
  const skipEdges = size > 2;
  for (let i = 0; i < size; i++) {
    if (skipEdges && (i === 0 || i === size - 1)) continue;
    out.push(intToIpv4(start + i));
  }
  return out;
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, b] = cidr.split("/");
  if (!isIPv4(ip) || !isIPv4(base)) return false;
  const size = 2 ** (32 - Number(b));
  return Math.floor(ipv4ToInt(ip) / size) === Math.floor(ipv4ToInt(base) / size);
}

export const KIND_LABEL: Record<TargetKind, string> = {
  domain: "Domain",
  ip: "IP",
  cidr: "Range",
  url: "URL",
};

const SECOND_LEVEL =
  /\.(com|net|org|gov|edu|gen|web|av|dr|bel|pol|k12|tsk|bbs|tv|info|biz|name|tel|co|ac|or|ne|go|mil|ltd|plc|me|sch|nhs|police|mod)\.[a-z]{2}$/i;

/** example.co.uk -> example.co.uk, a.b.example.com -> example.com */
export function registrableDomain(host: string): string {
  const parts = host.split(".");
  const keep = SECOND_LEVEL.test(host) ? 3 : 2;
  return parts.slice(-keep).join(".");
}

/** True when the host is one of the scope domains or a subdomain of one. An empty scope allows everything. */
export function inScope(host: string, scope?: string[]): boolean {
  if (!scope?.length) return true;
  const h = host.toLowerCase();
  return scope.some((s) => h === s || h.endsWith(`.${s}`));
}
