import dns from "node:dns/promises";
import net from "node:net";

/** An error whose message is safe and meaningful to show to the user. */
export class UserError extends Error {
  code: string;
  constructor(message: string, code = "user_error") {
    super(message);
    this.code = code;
  }
}

export const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
];

export function randomUA(): string {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

const API_UA = "ReconPanel/1.0 (+passive recon)";

function v4int(ip: string): number {
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
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
  if (net.isIPv4(ip)) {
    const n = v4int(ip);
    return PRIVATE_V4.some(([b, bits]) => {
      const size = 2 ** (32 - bits);
      return Math.floor(n / size) === Math.floor(v4int(b) / size);
    });
  }
  const v6 = ip.toLowerCase();
  const mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIp(mapped[1]);
  return v6 === "::" || v6 === "::1" || v6.startsWith("fc") || v6.startsWith("fd") || /^fe[89ab]/.test(v6) || v6.startsWith("ff");
}

/** SSRF guard: refuses hosts that resolve to loopback, private or link-local addresses. */
export async function assertPublicHost(host: string): Promise<string[]> {
  const h = host.replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".internal") || h.endsWith(".local")) {
    throw new UserError("Requests to local network names are blocked.", "blocked_host");
  }
  let addrs: string[];
  if (net.isIP(h)) addrs = [h];
  else {
    try {
      addrs = (await dns.lookup(h, { all: true })).map((a) => a.address);
    } catch {
      throw new UserError(`${h} does not resolve (no DNS record).`, "nxdomain");
    }
  }
  if (addrs.some(isPrivateIp)) throw new UserError("Requests to private or internal addresses are blocked.", "blocked_host");
  return addrs;
}

export async function fetchWithTimeout(url: string, init: RequestInit = {}, ms = 15000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, cache: "no-store" });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw new UserError(`Request timed out after ${Math.round(ms / 1000)} s.`, "timeout");
    throw e;
  } finally {
    clearTimeout(t);
  }
}

/** JSON request to a fixed third-party API (not user-controlled, so no SSRF check). */
export async function fetchJson<T>(url: string, ms = 15000, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetchWithTimeout(url, { headers: { accept: "application/json", "user-agent": API_UA, ...headers } }, ms);
  if (res.status === 429) throw new UserError("Rate limited by the source (HTTP 429).", "rate_limited");
  if (!res.ok) throw new UserError(`Source returned HTTP ${res.status}.`, "upstream_error");
  const text = await res.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new UserError("Source returned an invalid response.", "upstream_error");
  }
}

export async function fetchText(url: string, ms = 15000, headers: Record<string, string> = {}): Promise<{ status: number; text: string }> {
  const res = await fetchWithTimeout(url, { headers: { "user-agent": API_UA, ...headers } }, ms);
  return { status: res.status, text: await res.text() };
}

export interface SafeResponse {
  status: number;
  statusText: string;
  headers: Headers;
  finalUrl: string;
  redirects: { url: string; status: number }[];
  body: string;
  truncated: boolean;
  timeMs: number;
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
  return { text: new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks.map((c) => Buffer.from(c)))), truncated };
}

const NET_ERRORS: Record<string, string> = {
  ENOTFOUND: "Host does not resolve.",
  ECONNREFUSED: "Connection refused.",
  ECONNRESET: "Connection reset by the server.",
  ETIMEDOUT: "Connection timed out.",
  EHOSTUNREACH: "Host unreachable.",
  CERT_HAS_EXPIRED: "The server's TLS certificate has expired.",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "The server's TLS certificate could not be verified.",
  DEPTH_ZERO_SELF_SIGNED_CERT: "The server uses a self-signed certificate.",
  ERR_TLS_CERT_ALTNAME_INVALID: "The TLS certificate does not match this host name.",
};

/** Fetch for user-supplied targets: every hop is checked against private address ranges. */
export async function safeFetch(
  url: string,
  opts: { timeoutMs?: number; maxBytes?: number; maxRedirects?: number; followRedirects?: boolean; method?: string; headers?: Record<string, string> } = {},
): Promise<SafeResponse> {
  const { timeoutMs = 15000, maxBytes = 2_000_000, maxRedirects = 5, followRedirects = true, method = "GET" } = opts;
  const redirects: { url: string; status: number }[] = [];
  const started = Date.now();
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    const u = new URL(current);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new UserError("Unsupported protocol.");
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
            "accept-language": "en-US,en;q=0.9,tr;q=0.8",
            ...opts.headers,
          },
        },
        timeoutMs,
      );
    } catch (e) {
      if (e instanceof UserError) throw e;
      const cause = (e as { cause?: { code?: string } }).cause?.code ?? "";
      throw new UserError(NET_ERRORS[cause] ?? `Could not connect${cause ? ` (${cause})` : ""}.`, "connect_failed");
    }
    const loc = res.headers.get("location");
    if (followRedirects && res.status >= 300 && res.status < 400 && loc) {
      redirects.push({ url: current, status: res.status });
      await res.body?.cancel().catch(() => {});
      current = new URL(loc, current).toString();
      continue;
    }
    const { text, truncated } = method === "HEAD" ? { text: "", truncated: false } : await readLimited(res, maxBytes);
    return { status: res.status, statusText: res.statusText, headers: res.headers, finalUrl: current, redirects, body: text, truncated, timeMs: Date.now() - started };
  }
  throw new UserError("Too many redirects.");
}

/** Maps with a concurrency limit. Order of results matches input. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

export function htmlTitle(html: string): string {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? decodeEntities(m[1]).replace(/\s+/g, " ").trim().slice(0, 160) : "";
}

export function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)));
}
