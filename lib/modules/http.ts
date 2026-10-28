import tls from "node:tls";
import { safeFetch, UserError, htmlTitle } from "../net.ts";
import { doh } from "../dns-core.ts";
import type { ParsedTarget } from "../target.ts";
import type { ModuleOutput } from "../types.ts";
import { detectTech, detectWaf, type WafMatch } from "./fingerprint-core.ts";

export interface TlsInfo {
  protocol?: string;
  issuer?: string;
  subject?: string;
  validTo?: string;
  daysLeft?: number;
  san?: string[];
  authorized?: boolean;
}
export interface SchemeResult {
  scheme: "http" | "https";
  status: number | null;
  title: string;
  server?: string;
  contentLength?: number;
  redirectChain: { url: string; status: number }[];
  finalUrl?: string;
  tech: string[];
  waf: WafMatch[];
  error?: string;
}
export interface HttpData {
  host: string;
  ip?: string;
  https: SchemeResult;
  http: SchemeResult;
  tls?: TlsInfo;
  headers: { name: string; value: string }[];
}

function getTls(host: string): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
      const c = sock.getPeerCertificate();
      const daysLeft = c.valid_to ? Math.floor((new Date(c.valid_to).getTime() - Date.now()) / 86_400_000) : undefined;
      const info: TlsInfo = {
        protocol: sock.getProtocol() ?? undefined,
        issuer: [c.issuer?.O, c.issuer?.CN].flat().filter(Boolean).join(" — "),
        subject: [c.subject?.CN].flat().filter(Boolean).join(", ") || undefined,
        validTo: c.valid_to ? new Date(c.valid_to).toISOString() : undefined,
        daysLeft,
        san: (c.subjectaltname ?? "").split(",").map((s) => s.trim().replace(/^DNS:/, "")).filter(Boolean).slice(0, 60),
        authorized: sock.authorized,
      };
      sock.end();
      resolve(info);
    });
    sock.on("timeout", () => (sock.destroy(), reject(new Error("timeout"))));
    sock.on("error", reject);
  });
}

async function probe(scheme: "http" | "https", host: string): Promise<SchemeResult> {
  try {
    const res = await safeFetch(`${scheme}://${host}/`, { timeoutMs: 10000, maxBytes: 1_000_000 });
    return {
      scheme,
      status: res.status,
      title: htmlTitle(res.body),
      server: res.headers.get("server") ?? undefined,
      contentLength: Number(res.headers.get("content-length")) || res.body.length,
      redirectChain: res.redirects,
      finalUrl: res.finalUrl,
      tech: detectTech(res.headers, res.body),
      waf: detectWaf(res.headers, res.body),
    };
  } catch (e) {
    return { scheme, status: null, title: "", redirectChain: [], tech: [], waf: [], error: e instanceof UserError ? e.message : "fetch failed" };
  }
}

export async function runHttp(t: ParsedTarget): Promise<ModuleOutput<HttpData>> {
  if (t.kind === "cidr") throw new UserError("HTTP Fingerprint needs a single domain, URL or IP.");
  const host = t.host;
  const [https, http] = await Promise.all([probe("https", host), probe("http", host)]);
  if (!https.status && !http.status) throw new UserError(https.error ?? http.error ?? "Host did not respond on http or https.", "connect_failed");

  let tlsInfo: TlsInfo | undefined;
  if (https.status) tlsInfo = await getTls(host).catch(() => undefined);
  let ip: string | undefined;
  if (!/^[\d.:]+$/.test(host)) ip = (await doh(host, "A").catch(() => null))?.records[0]?.value;

  // Collect response headers from whichever scheme answered.
  const headers: { name: string; value: string }[] = [];
  try {
    const res = await safeFetch(`${https.status ? "https" : "http"}://${host}/`, { timeoutMs: 8000, maxBytes: 1000 });
    res.headers.forEach((value, name) => headers.push({ name, value }));
    headers.sort((a, b) => a.name.localeCompare(b.name));
  } catch {
    /* ignore */
  }

  const main = https.status ? https : http;
  const summary = `${main.scheme} ${main.status}${main.title ? ` · ${main.title.slice(0, 40)}` : ""}${main.server ? ` · ${main.server}` : ""}`;
  return { summary, findings: [], data: { host, ip, https, http, tls: tlsInfo, headers } };
}
