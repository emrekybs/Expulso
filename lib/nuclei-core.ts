// Pure parts of the nuclei integration: request validation, argument building and output parsing.
// Shared by the server route and the Nuclei page, so it must not import server-only modules.
import { parseTarget } from "./target.ts";
import type { Finding, Severity } from "./types.ts";

export const NUCLEI_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export const NUCLEI_TEMPLATES = ["cves", "vulnerabilities", "exposures", "misconfigurations", "takeovers", "default-logins", "technologies", "exposed-panels"] as const;
export const NUCLEI_TIMEOUT_MS = 30 * 60 * 1000;

/** Tags grouped for the pickers. Free text tags are accepted too, if they match NUCLEI_TAG_NAME. */
export const NUCLEI_TAG_GROUPS: { label: string; tags: string[] }[] = [
  { label: "Injection", tags: ["sqli", "xss", "lfi", "ssrf", "ssti", "xxe", "cmdi", "crlf", "redirect"] },
  { label: "Known vulnerabilities", tags: ["cve", "kev", "rce"] },
  { label: "Exposure and misconfiguration", tags: ["exposure", "misconfig", "takeover", "default-login", "token", "backup", "config"] },
  { label: "Panels and technology", tags: ["panel", "tech", "wordpress", "jenkins", "grafana", "jira", "confluence", "gitlab", "drupal", "joomla"] },
];
export const NUCLEI_TAG_NAME = /^[a-z0-9-]{1,40}$/;
const TARGET_LIMIT = 200;

export interface NucleiRequest {
  targets: string[];
  severities: string[];
  tags: string[];
  templates: string[];
  /** nuclei -as: detect technologies first and run the matching templates. */
  automatic: boolean;
  rateLimit: number;
  concurrency: number;
}

/** Returns a message for the user when the request cannot run, otherwise null. */
export function validateNuclei(r: NucleiRequest): string | null {
  if (!r.targets.length) return "Enter at least one target.";
  if (r.targets.length > TARGET_LIMIT) return `Up to ${TARGET_LIMIT} targets per run.`;
  if (r.severities.some((s) => !(NUCLEI_SEVERITIES as readonly string[]).includes(s))) return "Unknown severity.";
  if (r.templates.some((t) => !(NUCLEI_TEMPLATES as readonly string[]).includes(t))) return "Unknown template category.";
  if ((r.tags ?? []).some((t) => !NUCLEI_TAG_NAME.test(t))) return "Tags use lower-case letters, digits and dashes only.";
  if (!r.automatic && !r.tags.length && !r.templates.length) return "Choose a template category, a tag, or turn on automatic detection.";
  if (!(r.rateLimit >= 1 && r.rateLimit <= 500)) return "Rate limit must be between 1 and 500 requests per second.";
  if (!(r.concurrency >= 1 && r.concurrency <= 100)) return "Concurrency must be between 1 and 100.";
  return null;
}

/** Private, loopback and link-local IPv4 literals. Hostnames are not resolved here. */
function privateIpv4(ip: string): boolean {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

/** Normalises the target list. Ranges are refused, private IP literals are refused. */
export function normaliseTargets(raw: string[]): { targets: string[]; error?: string } {
  const out: string[] = [];
  for (const item of raw.map((s) => s.trim()).filter(Boolean)) {
    const p = parseTarget(item);
    if ("error" in p) return { targets: [], error: p.error };
    if (p.kind === "cidr") return { targets: [], error: "Ranges are not accepted here. Enter hosts or URLs." };
    if (p.kind === "ip" && privateIpv4(p.host)) return { targets: [], error: `${p.host} is a private address and is not scanned.` };
    out.push(p.kind === "url" && p.url ? p.url : p.host);
  }
  return { targets: [...new Set(out)] };
}

/** The nuclei arguments for a request. The target file is passed separately. */
export function buildNucleiArgs(r: NucleiRequest, listFile: string): string[] {
  const args = ["-l", listFile, "-jsonl", "-silent", "-nc", "-duc", "-rl", String(r.rateLimit), "-c", String(r.concurrency), "-timeout", "8", "-retries", "0"];
  if (r.severities.length) args.push("-severity", r.severities.join(","));
  if (r.tags.length) args.push("-tags", r.tags.join(","));
  if (r.templates.length) args.push("-t", r.templates.map((t) => `${t}/`).join(","));
  if (r.automatic) args.push("-as");
  return args;
}

/** The same command as a copyable line, so the user can see what the panel runs. */
export function nucleiCommandPreview(r: NucleiRequest): string {
  return ["nuclei", ...buildNucleiArgs(r, "targets.txt")].map((a) => (/\s|,/.test(a) ? `'${a}'` : a)).join(" ");
}

const SEV: Record<string, Severity> = { critical: "high", high: "high", medium: "medium", low: "low", info: "info" };

interface NucleiLine {
  "template-id"?: string;
  "matched-at"?: string;
  host?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    tags?: string | string[];
    reference?: string | string[];
    classification?: { "cve-id"?: string[] | string; "cwe-id"?: string[] | string };
  };
}

const first = (v: string | string[] | undefined): string | undefined => (Array.isArray(v) ? v[0] : v);

/** Turns nuclei -jsonl lines into findings. Keeps every severity, marks critical in the title. */
export function parseNucleiJsonl(lines: string[]): Finding[] {
  const out: Finding[] = [];
  for (const line of lines) {
    let row: NucleiLine;
    try {
      row = JSON.parse(line) as NucleiLine;
    } catch {
      continue;
    }
    const info = row.info ?? {};
    const sev = (info.severity ?? "info").toLowerCase();
    const id = row["template-id"] ?? "unknown-template";
    const cves = [info.classification?.["cve-id"]].flat().filter((x): x is string => !!x).map((x) => x.toUpperCase());
    const cwe = first(info.classification?.["cwe-id"]);
    const refs = [info.reference].flat().filter((x): x is string => !!x && /^https?:\/\//.test(x));
    const detail = [info.description?.trim(), cves.length ? `CVE: ${cves.join(", ")}` : ""].filter(Boolean).join(" ");
    out.push({
      severity: SEV[sev] ?? "info",
      title: `${sev === "critical" ? "[critical] " : ""}${info.name ?? id} (${id})`,
      detail: detail || `Matched the nuclei template ${id}.`,
      evidence: row["matched-at"] ?? row.host,
      recommendation: "Confirm the finding on the live site, then follow the template reference to fix it.",
      kind: "nuclei",
      cwe: cwe ? `CWE-${cwe.replace(/^CWE-/i, "")}` : undefined,
      references: refs.slice(0, 5),
      confidence: "confirmed",
    });
  }
  return out;
}
