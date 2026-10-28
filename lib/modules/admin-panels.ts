import { safeFetch, UserError, mapLimit, htmlTitle } from "../net.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";
import { ADMIN_PATHS, looksLikeAdmin } from "./wordlists.ts";

export interface PanelHit {
  path: string;
  url: string;
  status: number;
  title: string;
  product: string | null;
  loginForm: boolean;
}

export interface AdminPanelsData {
  origin: string;
  tested: number;
  panels: PanelHit[];
}

/** Product names for well-known admin / login paths (matched on the path or the page title). */
const PRODUCTS: [RegExp, string, "database" | "panel"][] = [
  [/phpmyadmin|\bpma\b|myadmin/i, "phpMyAdmin", "database"],
  [/adminer/i, "Adminer", "database"],
  [/wp-login|wp-admin/i, "WordPress", "panel"],
  [/grafana/i, "Grafana", "panel"],
  [/kibana/i, "Kibana", "panel"],
  [/jenkins/i, "Jenkins", "panel"],
  [/gitlab/i, "GitLab", "panel"],
  [/jira/i, "Jira", "panel"],
  [/confluence/i, "Confluence", "panel"],
  [/cpanel|whm/i, "cPanel / WHM", "panel"],
  [/owa/i, "Outlook Web Access", "panel"],
  [/citrix/i, "Citrix Gateway", "panel"],
  [/vpn|sslvpn|remote/i, "VPN / remote access", "panel"],
  [/umbraco/i, "Umbraco", "panel"],
  [/typo3/i, "TYPO3 backend", "panel"],
  [/joomla|administrator/i, "Joomla administrator", "panel"],
];
const DATABASE_TOOLS = new Set(["phpMyAdmin", "Adminer"]);

function product(path: string, title: string): { name: string | null; kind: "database" | "panel" | null } {
  for (const [re, name, kind] of PRODUCTS) if (re.test(path) || re.test(title)) return { name, kind };
  return { name: null, kind: null };
}

export async function runAdminPanels(t: ParsedTarget): Promise<ModuleOutput<AdminPanelsData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Admin Panel Finder needs a domain or URL.");
  const origin = t.url ? new URL(t.url).origin : `https://${t.host}`;
  await safeFetch(origin + "/", { timeoutMs: 10000, maxBytes: 1000 }).catch(() => {
    throw new UserError("The target did not respond on https. Check the domain or give an http:// URL.", "connect_failed");
  });

  // Soft-404 baseline: many sites answer every path with a 200 page.
  let baseline = { status: 404, len: 0 };
  try {
    const r = await safeFetch(`${origin}/b24x${Math.random().toString(36).slice(2, 10)}/`, { timeoutMs: 8000, maxBytes: 80000, followRedirects: false });
    baseline = { status: r.status, len: r.body.length };
  } catch {
    /* keep default */
  }

  const paths = [...new Set(ADMIN_PATHS.map((p) => "/" + p.replace(/^\/+/, "")))];
  const found = await mapLimit(paths, 12, async (path): Promise<PanelHit | null> => {
    try {
      const r = await safeFetch(origin + path, { timeoutMs: 7000, maxBytes: 120000, followRedirects: false });
      const soft = r.status === baseline.status && Math.abs(r.body.length - baseline.len) < 48;
      const isLoginRedirect = r.status >= 300 && r.status < 400 && /login|signin|auth|sso/i.test(r.headers.get("location") ?? "");
      const plausible = r.status === 200 || r.status === 401 || r.status === 403 || isLoginRedirect;
      if (!plausible || (soft && r.status === 200)) return null;
      const title = htmlTitle(r.body);
      const loginForm = /<input[^>]+type=["']password["']/i.test(r.body);
      const admin = looksLikeAdmin(path, title, r.body) || r.status === 401 || r.status === 403 || isLoginRedirect;
      if (!admin) return null;
      const p = product(path, title);
      return { path, url: origin + path, status: r.status, title, product: p.name, loginForm };
    } catch {
      return null;
    }
  });
  const panels = found.filter((x): x is PanelHit => !!x).sort((a, b) => Number(b.loginForm) - Number(a.loginForm) || a.path.localeCompare(b.path));

  const findings: Finding[] = [];
  const dbTools = panels.filter((p) => p.product && DATABASE_TOOLS.has(p.product));
  if (dbTools.length)
    findings.push({
      severity: "high",
      title: `Database admin tool reachable: ${dbTools.map((p) => p.product).join(", ")}`,
      detail: "Database administration interfaces should never be reachable from the internet. Their login pages are a common credential-guessing target.",
      evidence: dbTools.map((p) => `${p.status} ${p.url}`).join("\n"),
      recommendation: "Remove the tool from the public web root or restrict it to the local network.",
    });
  if (panels.length)
    findings.push({
      severity: "medium",
      title: `${panels.length} login / admin panel${panels.length > 1 ? "s" : ""} reachable`,
      detail: "Administrative and login interfaces are exposed to the internet. They are typical targets for credential attacks and for unpatched software.",
      evidence: panels.slice(0, 12).map((p) => `${p.status} ${p.url}${p.product ? ` (${p.product})` : ""}`).join("\n"),
      recommendation: "Restrict panels to a VPN or an IP allow-list and enforce MFA where supported.",
    });

  return {
    summary: `${panels.length} panel(s) found · ${paths.length} paths checked`,
    findings,
    data: { origin, tested: paths.length, panels },
  };
}
