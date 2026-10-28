// İstemci ve sunucu tarafında ortak kullanılan hedef ayrıştırma yardımcıları.

export type TargetKind = "domain" | "ip" | "cidr" | "url";

export interface ParsedTarget {
  input: string;
  kind: TargetKind;
  /** Küçük harfe çevrilmiş, punycode'a dönüştürülmüş ana makine adı veya IP */
  host: string;
  /** Yalnızca kind === "url" olduğunda dolu */
  url?: string;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const DOMAIN = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

export function isIPv4(v: string): boolean {
  return IPV4.test(v);
}

export function isIPv6(v: string): boolean {
  if (!v.includes(":") || !/^[0-9a-f:.]+$/i.test(v)) return false;
  const parts = v.split("::");
  if (parts.length > 2) return false;
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

export function parseTarget(raw: string): ParsedTarget | { error: string } {
  const input = raw.trim();
  if (!input) return { error: "Lütfen bir hedef girin." };
  if (input.length > 2048) return { error: "Hedef çok uzun." };

  // CIDR (ör. 192.168.1.0/24)
  const cidr = input.match(/^([\d.]+)\/(\d{1,2})$/);
  if (cidr && isIPv4(cidr[1]) && Number(cidr[2]) <= 32) {
    return { input, kind: "cidr", host: input };
  }

  const bare = input.replace(/^\[|\]$/g, "");
  if (isIP(bare)) return { input, kind: "ip", host: bare.toLowerCase() };

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
  const hasPath = /[/?#]/.test(input);
  if (hasScheme || hasPath) {
    try {
      const u = new URL(hasScheme ? input : `https://${input}`);
      if (u.protocol !== "http:" && u.protocol !== "https:") {
        return { error: "Yalnızca http ve https adresleri desteklenir." };
      }
      const host = u.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
      if (!isIP(host) && !isDomain(host)) return { error: "Geçersiz adres." };
      return { input, kind: "url", host, url: u.toString() };
    } catch {
      return { error: "Geçersiz URL." };
    }
  }

  const host = toAsciiHost(input.toLowerCase());
  if (host && isDomain(host)) return { input, kind: "domain", host };
  return { error: "Geçerli bir alan adı, IP adresi veya URL girin." };
}

export const KIND_LABEL: Record<TargetKind, string> = {
  domain: "Alan adı",
  ip: "IP adresi",
  cidr: "IP aralığı",
  url: "URL",
};
