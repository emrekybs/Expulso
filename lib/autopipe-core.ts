// Pure parts of the autopipeline: stage definitions, host selection, httpx output and the plan.
// Shared by the server and the page, so it must not import server-only modules.

export type StageId = "subdomains" | "probe" | "nucleiAs" | "urlParams" | "xss" | "sqli";

export const STAGES: { id: StageId; title: string; detail: string; engine: string }[] = [
  { id: "subdomains", title: "Subdomain discovery", detail: "All subdomains from passive sources and installed subfinder, assetfinder, findomain, amass, plus DNS brute force.", engine: "subfinder / amass / built-in" },
  { id: "probe", title: "Live host probe", detail: "Status code, title and technologies of every resolved host.", engine: "httpx or built-in" },
  { id: "nucleiAs", title: "nuclei (automatic)", detail: "nuclei -as on the selected hosts: technologies are detected first, then matching templates run. Your tags are added when selected.", engine: "nuclei (needs install)" },
  { id: "urlParams", title: "URLs and parameters", detail: "Known URLs of each selected host (gau, or the built-in archives), filtered into XSS and SQL injection candidates.", engine: "gau or built-in archives" },
  { id: "xss", title: "XSS test", detail: "Dalfox on XSS candidates. Without Dalfox, the built-in reflection check runs.", engine: "Dalfox or built-in" },
  { id: "sqli", title: "SQL injection test", detail: "sqlmap detection on SQL candidates. Without sqlmap, the built-in error check runs.", engine: "sqlmap or built-in" },
];

export type StatusFilter = "2xx" | "2xx-3xx" | "all";

export interface PipelineRequest {
  targets: string[];
  stages: Record<StageId, boolean>;
  statusFilter: StatusFilter;
  hostLimit: number;
  nucleiTags: string[];
  urlLimit: number;
  authorized: boolean;
  /** global: follow the Settings switch. on / off: force the proxy for this run. */
  proxyMode: "global" | "on" | "off";
}

export const ALL_STAGES_ON: Record<StageId, boolean> = { subdomains: true, probe: true, nucleiAs: true, urlParams: true, xss: true, sqli: true };

export function validatePipeline(r: PipelineRequest): string | null {
  if (!r.authorized) return "Confirm that you are authorised to test these targets.";
  if (!r.targets.length) return "Enter at least one domain.";
  if (r.targets.length > 5) return "Up to 5 domains per run.";
  if (!(r.hostLimit >= 1 && r.hostLimit <= 200)) return "Host limit must be between 1 and 200.";
  if (!(r.urlLimit >= 1 && r.urlLimit <= 200)) return "URL limit per test must be between 1 and 200.";
  if (r.nucleiTags.some((t) => !/^[a-z0-9-]{1,40}$/.test(t))) return "Nuclei tags use lower-case letters, digits and dashes only.";
  if (!(["2xx", "2xx-3xx", "all"] as string[]).includes(r.statusFilter)) return "Unknown status filter.";
  if (!(["global", "on", "off"] as string[]).includes(r.proxyMode)) return "Unknown proxy mode.";
  return null;
}

/** Hosts whose status code passes the filter, best first, capped by the limit. */
export function selectHosts<T extends { status: number | null }>(hosts: T[], filter: StatusFilter, limit: number): T[] {
  const pass = (s: number | null) => {
    if (s == null) return false;
    if (filter === "all") return true;
    if (filter === "2xx") return s >= 200 && s < 300;
    return s >= 200 && s < 400;
  };
  return hosts.filter((h) => pass(h.status)).sort((a, b) => Number(b.status === 200) - Number(a.status === 200)).slice(0, limit);
}

export interface ProbeRow {
  host: string;
  status: number | null;
  title: string;
  tech: string[];
  url: string;
}

/** httpx -json lines. Non-JSON lines (banners, progress) are skipped. */
export function parseHttpxJsonl(lines: string[]): ProbeRow[] {
  const out: ProbeRow[] = [];
  for (const line of lines) {
    let row: { url?: string; input?: string; status_code?: number; title?: string; tech?: string[] };
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    if (!row.url) continue;
    let host = row.input ?? "";
    try {
      host = new URL(row.url).hostname;
    } catch {
      /* keep input */
    }
    out.push({ host, status: typeof row.status_code === "number" ? row.status_code : null, title: row.title ?? "", tech: row.tech ?? [], url: row.url });
  }
  return out;
}

/** The plan shown before a run: which stages run, and which engine each one will use. */
export function planLines(r: PipelineRequest, installed: Record<string, boolean>): { stage: string; on: boolean; engine: string; note: string }[] {
  return STAGES.map((s) => {
    const on = r.stages[s.id];
    let engine = s.engine;
    let note = "";
    if (s.id === "subdomains") engine = installed.subfinder ? "subfinder + built-in sources" : "built-in sources (subfinder not installed)";
    if (s.id === "probe") engine = installed.httpx ? "httpx" : "built-in status check";
    if (s.id === "nucleiAs" && !installed.nuclei) note = "nuclei not installed: this stage will be skipped";
    if (s.id === "urlParams") engine = installed.gau ? "gau" : "built-in archives (gau not installed)";
    if (s.id === "xss") engine = installed.dalfox ? "Dalfox" : "built-in reflection check (Dalfox not installed)";
    if (s.id === "sqli") engine = installed.sqlmap ? "sqlmap (detection only)" : "built-in error check (sqlmap not installed)";
    if (on && (s.id === "nucleiAs" || s.id === "urlParams")) note ||= `up to ${r.hostLimit} hosts`;
    if (on && (s.id === "xss" || s.id === "sqli")) note ||= `up to ${r.urlLimit} candidate URLs`;
    return { stage: s.title, on, engine, note };
  });
}
