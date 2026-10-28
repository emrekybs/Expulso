import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import { fetchJson, safeFetch, UserError, isPrivateIp, htmlTitle } from "../net.ts";
import { doh, resolveA4 } from "../dns-core.ts";
import { registrableDomain, ipInCidr, type ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";

export interface OriginCandidate {
  ip: string;
  sources: string[];
  cdn: string | null; // provider name if the IP is in a CDN/WAF range
  verdict: "confirmed" | "likely" | "possible" | "cdn" | "no-match" | "unreachable";
  detail: string;
}
export interface OriginData {
  domain: string;
  frontedBy: string | null;
  baseline: { title: string; server?: string; status: number } | null;
  candidates: OriginCandidate[];
  confirmed: OriginCandidate[];
}

/* ---- Cloudflare + other CDN/WAF ranges (keyless, cached) ---- */
let cdnCache: { at: number; ranges: { cidr: string; provider: string }[] } | null = null;
async function cdnRanges(): Promise<{ cidr: string; provider: string }[]> {
  if (cdnCache && Date.now() - cdnCache.at < 6 * 3600_000) return cdnCache.ranges;
  const ranges: { cidr: string; provider: string }[] = [];
  await import("../net.ts")
    .then((m) => m.fetchText("https://www.cloudflare.com/ips-v4", 10000))
    .then(({ text }) => text.split(/\s+/).filter(Boolean).forEach((c) => ranges.push({ cidr: c, provider: "Cloudflare" })))
    .catch(() => {});
  await fetchJson<{ prefixes: { ip_prefix?: string; service: string }[] }>("https://ip-ranges.amazonaws.com/ip-ranges.json", 12000)
    .then((j) => j.prefixes.forEach((p) => p.ip_prefix && ["CLOUDFRONT"].includes(p.service) && ranges.push({ cidr: p.ip_prefix, provider: "Amazon CloudFront" })))
    .catch(() => {});
  await fetchJson<{ addresses: string[] }>("https://api.fastly.com/public-ip-list", 10000)
    .then((j) => j.addresses.forEach((c) => ranges.push({ cidr: c, provider: "Fastly" })))
    .catch(() => {});
  cdnCache = { at: Date.now(), ranges };
  return ranges;
}
function cdnOf(ip: string, ranges: { cidr: string; provider: string }[]): string | null {
  if (ip.includes(":")) return null;
  for (const r of ranges) if (!r.cidr.includes(":") && ipInCidr(ip, r.cidr)) return r.provider;
  return null;
}

/* ---- Direct request to a candidate IP, pretending to be the domain ---- */
interface Probe {
  status: number;
  title: string;
  server?: string;
  location?: string;
  hash: string;
}
function fetchViaIp(ip: string, domain: string, scheme: "http" | "https"): Promise<Probe | null> {
  return new Promise((resolve) => {
    const lib = scheme === "https" ? https : http;
    const req = lib.request(
      {
        host: ip,
        port: scheme === "https" ? 443 : 80,
        path: "/",
        method: "GET",
        servername: scheme === "https" ? domain : undefined,
        rejectUnauthorized: false,
        timeout: 7000,
        headers: { Host: domain, "User-Agent": "Mozilla/5.0 ReconPanel", Accept: "text/html" },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size <= 200_000) chunks.push(c);
          else res.destroy();
        });
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          resolve({
            status: res.statusCode ?? 0,
            title: htmlTitle(body),
            server: (res.headers["server"] as string) || undefined,
            location: (res.headers["location"] as string) || undefined,
            hash: crypto.createHash("sha1").update(body.replace(/\s+/g, " ").slice(0, 4000)).digest("hex").slice(0, 12),
          });
        });
      },
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => (req.destroy(), resolve(null)));
    req.end();
  });
}

export async function runOrigin(t: ParsedTarget): Promise<ModuleOutput<OriginData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Origin IP Finder needs a domain or URL.");
  const domain = registrableDomain(t.host);
  const warnings: string[] = [];
  const ranges = await cdnRanges();

  // Baseline: how the real site looks when served through the CDN.
  let baseline: OriginData["baseline"] = null;
  let frontedBy: string | null = null;
  try {
    const res = await safeFetch(`https://${t.host}/`, { timeoutMs: 12000, maxBytes: 400_000 });
    baseline = { title: htmlTitle(res.body), server: res.headers.get("server") ?? undefined, status: res.status };
    const apex = (await resolveA4(t.host).catch(() => []))[0];
    if (apex) frontedBy = cdnOf(apex, ranges);
    if (res.headers.get("cf-ray")) frontedBy = "Cloudflare";
  } catch (e) {
    warnings.push(`Could not load the site through its CDN: ${e instanceof UserError ? e.message : "failed"}`);
  }
  const baselineHash = baseline ? crypto.createHash("sha1").update((baseline.title || "").toLowerCase()).digest("hex") : "";

  // Collect candidate IPs from records that often leak the origin.
  const cand = new Map<string, Set<string>>();
  const add = (ip: string, src: string) => {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || isPrivateIp(ip)) return;
    const s = cand.get(ip) ?? new Set<string>();
    s.add(src);
    cand.set(ip, s);
  };

  // 1) Common non-proxied subdomains.
  const subs = ["direct", "origin", "direct-connect", "cpanel", "webmail", "mail", "mail1", "mx", "smtp", "ftp", "ssh", "vpn", "dev", "staging", "test", "server", "web", "ns1", "autodiscover", "remote", "portal", "admin", "api", "cpcontacts", "cpcalendars", "whm"];
  await Promise.all(
    subs.map(async (s) => {
      const ips = await resolveA4(`${s}.${domain}`).catch(() => []);
      ips.forEach((ip) => add(ip, `${s}.${domain}`));
    }),
  );
  // 2) MX records → their A records (mail servers often sit on origin infra).
  const mx = (await doh(domain, "MX").catch(() => null))?.records ?? [];
  await Promise.all(mx.map(async (r) => (await resolveA4(r.value).catch(() => [])).forEach((ip) => add(ip, `MX ${r.value}`))));
  // 3) SPF includes with ip4:.
  const txt = (await doh(domain, "TXT").catch(() => null))?.records ?? [];
  for (const r of txt) for (const m of r.value.matchAll(/ip4:(\d+\.\d+\.\d+\.\d+)/g)) add(m[1], "SPF record");
  // 4) crt.sh host names resolved (cap).
  try {
    const rows = await fetchJson<{ name_value: string }[]>(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, 20000);
    const hosts = [...new Set(rows.flatMap((r) => r.name_value.split(/\s+/)).map((h) => h.trim().toLowerCase().replace(/^\*\./, "")).filter((h) => h.endsWith(domain)))].slice(0, 60);
    await Promise.all(
      hosts.map(async (h) => {
        const ips = await resolveA4(h).catch(() => []);
        ips.forEach((ip) => add(ip, `cert: ${h}`));
      }),
    );
  } catch {
    warnings.push("Certificate source (crt.sh) was unavailable.");
  }

  // Classify + verify.
  const list = [...cand.entries()].map(([ip, srcs]) => ({ ip, sources: [...srcs] }));
  if (!list.length) warnings.push("No candidate IPs were found in public records.");

  const candidates: OriginCandidate[] = [];
  const nonCdn = list.filter((c) => !cdnOf(c.ip, ranges)).slice(0, 40);
  const cdnOnes = list.filter((c) => cdnOf(c.ip, ranges));

  for (const c of cdnOnes) candidates.push({ ip: c.ip, sources: c.sources, cdn: cdnOf(c.ip, ranges), verdict: "cdn", detail: `In ${cdnOf(c.ip, ranges)} range (not an origin).` });

  const deadline = Date.now() + 40000;
  await Promise.all(
    nonCdn.map(async (c) => {
      if (Date.now() > deadline) {
        candidates.push({ ip: c.ip, sources: c.sources, cdn: null, verdict: "possible", detail: "Not verified (time limit)." });
        return;
      }
      const probe = (await fetchViaIp(c.ip, t.host, "https")) ?? (await fetchViaIp(c.ip, t.host, "http"));
      if (!probe) {
        candidates.push({ ip: c.ip, sources: c.sources, cdn: null, verdict: "unreachable", detail: "Did not respond to a direct request with the real Host header." });
        return;
      }
      const titleMatch = !!baseline?.title && probe.title.toLowerCase() === baseline.title.toLowerCase();
      const hashMatch = baselineHash && crypto.createHash("sha1").update((probe.title || "").toLowerCase()).digest("hex") === baselineHash;
      const redirectMatch = !!probe.location && probe.location.includes(domain);
      let verdict: OriginCandidate["verdict"];
      let detail: string;
      if ((titleMatch || hashMatch) && probe.status < 400) {
        verdict = "confirmed";
        detail = `Served the same page as the site (title "${probe.title}") directly from this IP.`;
      } else if (redirectMatch || (probe.status > 0 && probe.status < 400)) {
        verdict = "likely";
        detail = redirectMatch ? `Redirects to ${domain} when asked directly (HTTP ${probe.status}).` : `Responds with HTTP ${probe.status} to the real Host header${probe.server ? ` (server: ${probe.server})` : ""}.`;
      } else {
        verdict = "no-match";
        detail = `Responded (HTTP ${probe.status}) but the content did not match the site.`;
      }
      candidates.push({ ip: c.ip, sources: c.sources, cdn: null, verdict, detail });
    }),
  );

  const order: Record<OriginCandidate["verdict"], number> = { confirmed: 0, likely: 1, possible: 2, "no-match": 3, unreachable: 4, cdn: 5 };
  candidates.sort((a, b) => order[a.verdict] - order[b.verdict] || a.ip.localeCompare(b.ip));
  const confirmed = candidates.filter((c) => c.verdict === "confirmed" || c.verdict === "likely");

  const findings: Finding[] = [];
  if (frontedBy && confirmed.length)
    findings.push({
      severity: "high",
      title: `Possible origin IP found behind ${frontedBy}`,
      detail: `The site is fronted by ${frontedBy}, but ${confirmed.length} IP(s) appear to serve it directly. If reachable, an attacker could bypass the CDN/WAF and hit the origin directly.`,
      evidence: confirmed.map((c) => `${c.ip} (${c.verdict}) — from ${c.sources.slice(0, 2).join(", ")}`).join("\n"),
      recommendation: "Restrict the origin firewall to only accept traffic from the CDN's IP ranges, and rotate the origin IP.",
    });
  else if (frontedBy)
    findings.push({ severity: "info", title: `Site is fronted by ${frontedBy}`, detail: "No origin IP could be confirmed from public records. The origin appears to be well hidden.", recommendation: "Keep the origin firewall locked to CDN ranges." });

  const summary = frontedBy
    ? `${frontedBy}${confirmed.length ? ` · ${confirmed.length} possible origin IP(s)` : " · no origin confirmed"}`
    : `${candidates.length} candidate IP(s)${confirmed.length ? ` · ${confirmed.length} confirmed/likely` : ""}`;
  return { summary, findings, data: { domain, frontedBy, baseline, candidates, confirmed }, warnings };
}
