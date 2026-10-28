import { safeFetch, UserError, mapLimit } from "../net.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, Severity } from "../types.ts";
import { detectTech } from "./fingerprint-core.ts";

export interface Check {
  id: string;
  category: string;
  title: string;
  status: "fail" | "warn" | "pass" | "info";
  severity: Severity;
  detail: string;
  evidence?: string;
  recommendation?: string;
}
export interface ExposureData {
  target: string;
  finalUrl: string;
  score: number;
  grade: string;
  checks: Check[];
  technologies: string[];
  robots?: { disallow: string[]; sitemaps: string[] };
}

const SENSITIVE: { path: string; title: string; sev: Severity; test: (b: string, ct: string) => boolean }[] = [
  { path: "/.git/HEAD", title: "Exposed Git repository (.git)", sev: "high", test: (b) => /^ref:\s*refs\//m.test(b) },
  { path: "/.git/config", title: "Exposed Git config", sev: "high", test: (b) => /\[core\]/.test(b) && /repositoryformatversion/.test(b) },
  { path: "/.env", title: "Exposed environment file (.env)", sev: "high", test: (b, ct) => !/html/i.test(ct) && /^[A-Z][A-Z0-9_]{2,}=.+/m.test(b) },
  { path: "/.svn/entries", title: "Exposed SVN repository (.svn)", sev: "high", test: (b, ct) => !/html/i.test(ct) && /^\d+\s*$/m.test(b.slice(0, 12)) },
  { path: "/.DS_Store", title: "macOS .DS_Store file", sev: "low", test: (b) => b.includes("Bud1") },
  { path: "/config.php.bak", title: "Backup of config.php", sev: "high", test: (b) => /<\?php/.test(b) },
  { path: "/.env.backup", title: "Backup environment file", sev: "high", test: (b, ct) => !/html/i.test(ct) && /=/.test(b) },
  { path: "/wp-config.php.bak", title: "WordPress config backup", sev: "high", test: (b) => /DB_PASSWORD|DB_NAME/.test(b) },
  { path: "/server-status", title: "Apache server-status page", sev: "medium", test: (b) => /Apache Server Status/i.test(b) },
  { path: "/phpinfo.php", title: "phpinfo() page", sev: "medium", test: (b) => /phpinfo\(\)|PHP Version/i.test(b) && /<table/i.test(b) },
  { path: "/actuator/health", title: "Spring Boot actuator exposed", sev: "medium", test: (b) => /"status"\s*:\s*"(UP|DOWN)"/.test(b) },
  { path: "/.well-known/security.txt", title: "security.txt present", sev: "info", test: (b) => /contact:/i.test(b) },
  { path: "/swagger-ui.html", title: "Swagger UI exposed", sev: "low", test: (b) => /swagger-ui/i.test(b) },
];

const WEIGHT: Record<Severity, number> = { high: 25, medium: 12, low: 5, info: 0 };

function grade(score: number): string {
  return score >= 95 ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";
}

function headerChecks(h: Headers, setCookies: string[], isHttps: boolean): Check[] {
  const c: Check[] = [];
  const get = (n: string) => h.get(n) ?? undefined;
  const push = (id: string, category: string, title: string, ok: boolean, sev: Severity, failDetail: string, rec?: string, value?: string) =>
    c.push(ok ? { id, category, title, status: "pass", severity: "info", detail: "Configured." + (value ? "" : ""), evidence: value } : { id, category, title, status: sev === "low" ? "warn" : "fail", severity: sev, detail: failDetail, recommendation: rec });

  const hsts = get("strict-transport-security");
  if (!isHttps) c.push({ id: "https", category: "TLS", title: "HTTPS", status: "fail", severity: "high", detail: "The site is not served over HTTPS." });
  else push("hsts", "Headers", "Strict-Transport-Security (HSTS)", !!hsts, "medium", "No HSTS header; the site may be downgraded over the network.", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", hsts);
  const csp = get("content-security-policy");
  push("csp", "Headers", "Content-Security-Policy", !!csp, "medium", "No CSP header; weaker defence against XSS and injection.", "Define a Content-Security-Policy.", csp?.slice(0, 80));
  push("xfo", "Headers", "Clickjacking protection", !!(get("x-frame-options") || /frame-ancestors/i.test(csp ?? "")), "medium", "No X-Frame-Options or frame-ancestors; the page can be framed by other sites.", "Add X-Frame-Options: DENY or CSP frame-ancestors 'self'.");
  push("xcto", "Headers", "X-Content-Type-Options", get("x-content-type-options")?.toLowerCase() === "nosniff", "low", "nosniff is not set.", "Add X-Content-Type-Options: nosniff.");
  push("refpol", "Headers", "Referrer-Policy", !!get("referrer-policy"), "low", "No Referrer-Policy; full URLs may leak to third parties.", "Add Referrer-Policy: strict-origin-when-cross-origin.");

  const acao = get("access-control-allow-origin");
  if (acao === "*") {
    const cred = get("access-control-allow-credentials") === "true";
    c.push({ id: "cors", category: "Config", title: "CORS configuration", status: cred ? "fail" : "warn", severity: cred ? "high" : "low", detail: cred ? "Wildcard origin with credentials allowed." : "All origins are allowed (*).", evidence: acao });
  }
  const server = get("server");
  if (server && /\d/.test(server)) c.push({ id: "server", category: "Info disclosure", title: "Server version disclosed", status: "warn", severity: "low", detail: "The Server header reveals the software version.", evidence: server });
  for (const n of ["x-powered-by", "x-aspnet-version", "x-generator"]) {
    const v = get(n);
    if (v) c.push({ id: n, category: "Info disclosure", title: `${n} header`, status: "warn", severity: "low", detail: "Technology/version information is disclosed.", evidence: v, recommendation: `Remove the ${n} header.` });
  }
  for (const sc of setCookies) {
    const name = sc.split("=")[0].trim();
    const missing: string[] = [];
    if (isHttps && !/;\s*secure/i.test(sc)) missing.push("Secure");
    if (!/;\s*httponly/i.test(sc)) missing.push("HttpOnly");
    if (!/;\s*samesite=/i.test(sc)) missing.push("SameSite");
    if (missing.length) c.push({ id: `cookie-${name}`, category: "Cookies", title: `Cookie: ${name}`, status: "warn", severity: missing.includes("Secure") ? "medium" : "low", detail: `Missing flags: ${missing.join(", ")}`, evidence: sc.split(";")[0].slice(0, 60) });
  }
  return c;
}

export async function runExposure(t: ParsedTarget): Promise<ModuleOutput<ExposureData>> {
  if (t.kind === "cidr") throw new UserError("Exposure & Misconfig needs a domain, URL or IP.");
  const start = t.url ?? `https://${t.host}/`;
  let res;
  try {
    res = await safeFetch(start, { timeoutMs: 12000, maxBytes: 1_200_000 });
  } catch (e) {
    if (start.startsWith("https://") && !t.url) res = await safeFetch(`http://${t.host}/`, { timeoutMs: 12000, maxBytes: 1_200_000 });
    else throw e;
  }
  const final = new URL(res.finalUrl);
  const isHttps = final.protocol === "https:";
  const origin = `${final.protocol}//${final.host}`;
  const checks = headerChecks(res.headers, res.headers.getSetCookie?.() ?? [], isHttps);

  // Soft-404 baseline: request a random path to learn how "not found" looks.
  let baseline = { status: 404, len: 0 };
  try {
    const rnd = await safeFetch(`${origin}/zzq${Math.random().toString(36).slice(2, 10)}`, { timeoutMs: 7000, maxBytes: 50000, followRedirects: false });
    baseline = { status: rnd.status, len: rnd.body.length };
  } catch {
    /* ignore */
  }

  const found = await mapLimit(SENSITIVE, 6, async (s) => {
    try {
      const r = await safeFetch(origin + s.path, { timeoutMs: 7000, maxBytes: 60000, followRedirects: false });
      const ct = r.headers.get("content-type") ?? "";
      const softMatch = r.status === baseline.status && Math.abs(r.body.length - baseline.len) < 64;
      const hit = r.status === 200 && !softMatch && s.test(r.body, ct);
      return { s, hit };
    } catch {
      return { s, hit: false };
    }
  });
  for (const { s, hit } of found) {
    if (!hit) continue;
    if (s.sev === "info") checks.push({ id: `file-${s.path}`, category: "Config", title: s.title, status: "pass", severity: "info", detail: "Present.", evidence: origin + s.path });
    else checks.push({ id: `file-${s.path}`, category: "Exposed files", title: s.title, status: "fail", severity: s.sev, detail: `${s.path} is publicly accessible.`, evidence: origin + s.path, recommendation: "Block web access to this path and review its contents." });
  }

  // robots.txt
  let robots: ExposureData["robots"];
  try {
    const r = await safeFetch(`${origin}/robots.txt`, { timeoutMs: 6000, maxBytes: 100000 });
    if (r.status === 200 && !/<html/i.test(r.body.slice(0, 200))) {
      const lines = r.body.split(/\r?\n/);
      robots = {
        disallow: [...new Set(lines.filter((l) => /^\s*disallow\s*:/i.test(l)).map((l) => l.split(":").slice(1).join(":").trim()).filter(Boolean))].slice(0, 100),
        sitemaps: lines.filter((l) => /^\s*sitemap\s*:/i.test(l)).map((l) => l.split(":").slice(1).join(":").trim()).slice(0, 20),
      };
    }
  } catch {
    /* ignore */
  }

  const penalty = checks.reduce((s, c) => s + (c.status === "fail" ? WEIGHT[c.severity] : c.status === "warn" ? WEIGHT[c.severity] / 2 : 0), 0);
  const score = Math.max(0, Math.round(100 - penalty));
  const findings: Finding[] = checks
    .filter((c) => c.status === "fail" || (c.status === "warn" && c.severity !== "low"))
    .map((c) => ({ severity: c.severity, title: c.title, detail: c.detail, evidence: c.evidence, recommendation: c.recommendation }));

  const data: ExposureData = { target: start, finalUrl: res.finalUrl, score, grade: grade(score), checks, technologies: detectTech(res.headers, res.body), robots };
  return { summary: `Grade ${data.grade} (${score}/100) · ${checks.filter((c) => c.status === "fail").length} issues`, findings, data };
}
