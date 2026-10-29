import "server-only";
import { safeFetch, mapLimit } from "../net.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, Severity } from "../types.ts";
import { VULN_KB, type VulnKind } from "../vuln-kb.ts";
import {
  makeMarker,
  reflectionContext,
  sqlErrorSignature,
  isRedirectParam,
  withParam,
  queryParams,
  missingSecurityHeaders,
  cookieFlagProblems,
} from "./vuln-core.ts";

// Built-in checks: reflected XSS, error-based SQL injection, CRLF injection, open redirect, CORS, headers
// and cookie flags. Detection only: no data is extracted and no payload is designed to change server state.
// Every request is sent to the target, so the module is Active and needs an authorised scope.

const DEFAULT_BUDGET = 200;
const PROBE_ORIGIN = "https://b24-probe.invalid";

export interface VulnScanOptions {
  urls: string;
  maxRequests: number;
}

export interface VulnScanData {
  tested: { url: string; param: string }[];
  requests: number;
  budgetReached: boolean;
}

function finding(kind: VulnKind, severity: Severity, where: string, evidence: string, confidence: "confirmed" | "suspected"): Finding {
  const kb = VULN_KB[kind];
  return {
    severity,
    title: `${kb.title} at ${where}`,
    detail: `${kb.what} ${kb.why}`,
    evidence,
    recommendation: kb.fix,
    kind,
    impact: kb.impact,
    cwe: kb.cwe,
    references: kb.references,
    confidence,
  };
}

/** Reflection check for one parameter: one request, and a finding only when the special characters came back raw. */
export async function reflectedXss(url: string, param: string): Promise<Finding | null> {
  const marker = makeMarker(`${url}${param}`);
  try {
    const r = await safeFetch(withParam(url, param, `${marker}"'<>`), { timeoutMs: 8000, maxBytes: 300000 });
    const ref = reflectionContext(r.body, marker);
    if (ref.context !== "none" && ref.unencoded) {
      return finding("xss-reflected", "high", `${url} (parameter ${param})`, `Context: ${ref.context}. Characters " ' < > came back unencoded next to the test marker.`, "suspected");
    }
  } catch {
    /* unreachable: no finding */
  }
  return null;
}

export async function runVulnScan(t: ParsedTarget, o: VulnScanOptions): Promise<ModuleOutput<VulnScanData>> {
  const origin = t.url ? new URL(t.url).origin : `https://${t.host}`;
  const https = origin.startsWith("https:");
  const listed = o.urls
    .split(/\s+/)
    .map((u) => u.trim())
    .filter((u) => /^https?:\/\//i.test(u));
  const paramUrls = [...new Set([...(t.url && queryParams(t.url).length ? [t.url] : []), ...listed])];
  const budget = Math.max(10, Math.min(1000, o.maxRequests || DEFAULT_BUDGET));
  let requests = 0;
  let budgetReached = false;
  const findings: Finding[] = [];
  const tested: { url: string; param: string }[] = [];
  const warnings: string[] = [];

  const spend = (): boolean => {
    if (requests >= budget) {
      budgetReached = true;
      return false;
    }
    requests++;
    return true;
  };

  // Homepage: headers, cookies and CORS.
  if (spend()) {
    try {
      const home = await safeFetch(`${origin}/`, { timeoutMs: 10000, maxBytes: 200000, followRedirects: true });
      const missing = missingSecurityHeaders(home.headers, https);
      if (missing.length) {
        findings.push({ ...finding("missing-headers", "low", origin, `Missing: ${missing.join(", ")}`, "confirmed") });
      }
      const setCookie = (home.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
      for (const c of cookieFlagProblems(setCookie)) {
        findings.push(finding("cookie-flags", "low", `${origin} (cookie ${c.name})`, `Missing: ${c.missing.join(", ")}`, "confirmed"));
      }
    } catch (e) {
      warnings.push(`Homepage could not be checked: ${(e as Error).message}`);
    }
  }
  if (spend()) {
    try {
      const cors = await safeFetch(`${origin}/`, { timeoutMs: 10000, maxBytes: 20000, headers: { Origin: PROBE_ORIGIN } });
      const acao = cors.headers.get("access-control-allow-origin");
      const acac = cors.headers.get("access-control-allow-credentials");
      if (acao === PROBE_ORIGIN && acac === "true") {
        findings.push(finding("cors-misconfig", "medium", origin, `Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: ${acac}`, "confirmed"));
      }
    } catch {
      /* skip */
    }
  }

  // Parameter checks.
  const jobs = paramUrls.flatMap((url) => queryParams(url).map((param) => ({ url, param })));
  if (!jobs.length && !paramUrls.length) warnings.push("No URL with query parameters was given, so only the homepage was checked. Add URLs with parameters to test them.");

  await mapLimit(jobs, 5, async ({ url, param }) => {
    if (!spend()) return;
    tested.push({ url, param });
    const seed = `${url}${param}`;
    const marker = makeMarker(seed);
    const where = `${url} (parameter ${param})`;

    // Baseline for the SQL check.
    let baselineBody = "";
    try {
      baselineBody = (await safeFetch(url, { timeoutMs: 8000, maxBytes: 300000 })).body;
    } catch {
      return;
    }

    // Reflected XSS.
    if (spend()) {
      const f = await reflectedXss(url, param);
      if (f) findings.push(f);
    }

    // Error-based SQL injection.
    if (spend()) {
      try {
        const r = await safeFetch(withParam(url, param, "'"), { timeoutMs: 8000, maxBytes: 300000 });
        const err = sqlErrorSignature(r.body);
        if (err && !sqlErrorSignature(baselineBody)) {
          findings.push(finding("sqli-error", "high", where, `Database error after a single quote: "${err}"`, "suspected"));
        }
      } catch {
        /* skip */
      }
    }

    // CRLF injection: a header with the marker name must appear in the response.
    if (spend()) {
      try {
        const headerName = `x-${marker}`;
        const r = await safeFetch(withParam(url, param, `${marker}%0d%0a${headerName}:%201`), { timeoutMs: 8000, maxBytes: 20000, followRedirects: false });
        if (r.headers.has(headerName)) {
          findings.push(finding("crlf-injection", "high", where, `Injected response header ${headerName} was returned.`, "confirmed"));
        }
      } catch {
        /* skip */
      }
    }

    // Open redirect: only parameters with a redirect-like name.
    if (isRedirectParam(param) && spend()) {
      try {
        const target = `https://example.org/${marker}`;
        const r = await safeFetch(withParam(url, param, target), { timeoutMs: 8000, maxBytes: 5000, followRedirects: false });
        const loc = r.headers.get("location") ?? "";
        if (r.status >= 300 && r.status < 400 && loc.startsWith(target)) {
          findings.push(finding("open-redirect", "medium", where, `Redirected (HTTP ${r.status}) to ${loc}`, "confirmed"));
        }
      } catch {
        /* skip */
      }
    }
  });

  if (budgetReached) warnings.push(`Request budget of ${budget} reached. Raise it in the module options to test more.`);

  const counts = { high: findings.filter((f) => f.severity === "high").length, medium: findings.filter((f) => f.severity === "medium").length };
  return {
    summary: `${findings.length} finding(s) · ${counts.high} high · ${counts.medium} medium · ${requests} requests · ${tested.length} parameter(s) tested`,
    findings,
    data: { tested, requests, budgetReached },
    warnings,
  };
}
