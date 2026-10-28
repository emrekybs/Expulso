import dns from "node:dns/promises";
import net from "node:net";

/** Kullanıcıya olduğu gibi gösterilebilecek (Türkçe) hata. */
export class UserError extends Error {}

export const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
];

export function randomUA(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function inV4Range(ip: string, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

const PRIVATE_V4: [string, number][] = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 3],
];

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) return PRIVATE_V4.some(([b, n]) => inV4Range(ip, b, n));
  const v6 = ip.toLowerCase();
  const mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIp(mapped[1]);
  return (
    v6 === "::" ||
    v6 === "::1" ||
    v6.startsWith("fc") ||
    v6.startsWith("fd") ||
    /^fe[89ab]/.test(v6) ||
    v6.startsWith("ff")
  );
}

/** SSRF koruması: yerel / özel ağ adreslerine giden istekleri engeller. */
export async function assertPublicHost(host: string): Promise<void> {
  const h = host.replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".internal") || h.endsWith(".local")) {
    throw new UserError("Yerel ağ adreslerine erişim engellendi.");
  }
  let addrs: string[];
  if (net.isIP(h)) {
    addrs = [h];
  } else {
    try {
      addrs = (await dns.lookup(h, { all: true })).map((a) => a.address);
    } catch {
      throw new UserError(`"${h}" alan adı çözümlenemedi (DNS kaydı bulunamadı).`);
    }
  }
  if (addrs.some(isPrivateIp)) {
    throw new UserError("Özel veya yerel ağ adreslerine erişim güvenlik nedeniyle engellendi.");
  }
}

export async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 15000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, cache: "no-store" });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw new UserError("İstek zaman aşımına uğradı.");
    throw e;
  } finally {
    clearTimeout(t);
  }
}

/** Güvenilir (sabit) üçüncü taraf API'ler için JSON isteği. */
export async function fetchJson<T>(url: string, ms = 15000, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetchWithTimeout(url, { headers: { accept: "application/json", "user-agent": "Expulso-CTI/2.0", ...headers } }, ms);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

export interface SafeResponse {
  status: number;
  statusText: string;
  headers: Headers;
  finalUrl: string;
  redirects: { url: string; status: number }[];
  body: string;
  truncated: boolean;
}

async function readLimited(res: Response, maxBytes: number): Promise<{ text: string; truncated: boolean }> {
  if (!res.body) return { text: "", truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      chunks.push(value.subarray(0, value.byteLength - (size - maxBytes)));
      truncated = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
  }
  const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
  return { text: new TextDecoder("utf-8", { fatal: false }).decode(buf), truncated };
}

/**
 * Kullanıcı tarafından verilen adreslere güvenli istek: her yönlendirmede
 * hedefin herkese açık bir adres olduğu doğrulanır.
 */
export async function safeFetch(
  url: string,
  opts: { timeoutMs?: number; maxBytes?: number; maxRedirects?: number; followRedirects?: boolean; method?: string; headers?: Record<string, string> } = {},
): Promise<SafeResponse> {
  const { timeoutMs = 15000, maxBytes = 3_000_000, maxRedirects = 5, followRedirects = true, method = "GET" } = opts;
  const redirects: { url: string; status: number }[] = [];
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    const u = new URL(current);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new UserError("Desteklenmeyen protokol.");
    await assertPublicHost(u.hostname);
    let res: Response;
    try {
      res = await fetchWithTimeout(
        current,
        {
          method,
          redirect: "manual",
          headers: {
            "user-agent": randomUA(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            ...opts.headers,
          },
        },
        timeoutMs,
      );
    } catch (e) {
      if (e instanceof UserError) throw e;
      const cause = (e as { cause?: { code?: string } }).cause?.code;
      const map: Record<string, string> = {
        ENOTFOUND: "Alan adı çözümlenemedi.",
        ECONNREFUSED: "Bağlantı reddedildi.",
        ECONNRESET: "Bağlantı karşı taraf tarafından kapatıldı.",
        CERT_HAS_EXPIRED: "Sunucunun SSL sertifikasının süresi dolmuş.",
        UNABLE_TO_VERIFY_LEAF_SIGNATURE: "SSL sertifikası doğrulanamadı.",
        DEPTH_ZERO_SELF_SIGNED_CERT: "Sunucu kendinden imzalı sertifika kullanıyor.",
        ERR_TLS_CERT_ALTNAME_INVALID: "SSL sertifikası bu alan adıyla eşleşmiyor.",
      };
      throw new UserError(map[cause ?? ""] ?? `Siteye bağlanılamadı${cause ? ` (${cause})` : ""}.`);
    }
    const loc = res.headers.get("location");
    if (followRedirects && res.status >= 300 && res.status < 400 && loc) {
      redirects.push({ url: current, status: res.status });
      await res.body?.cancel().catch(() => {});
      current = new URL(loc, current).toString();
      continue;
    }
    const { text, truncated } = method === "HEAD" ? { text: "", truncated: false } : await readLimited(res, maxBytes);
    return { status: res.status, statusText: res.statusText, headers: res.headers, finalUrl: current, redirects, body: text, truncated };
  }
  throw new UserError("Çok fazla yönlendirme.");
}

/** Sınırlı eşzamanlılıkla eşleme. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}
