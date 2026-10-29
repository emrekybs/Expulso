import "server-only";
import fs from "node:fs/promises";
import path from "node:path";
import { runTool, toolPath } from "../tools.ts";
import { activeProxy } from "../settings.ts";
import type { Finding } from "../types.ts";
import { buildNucleiArgs, nucleiCommandPreview, parseNucleiJsonl, NUCLEI_SEVERITIES, NUCLEI_TIMEOUT_MS, type NucleiRequest } from "../nuclei-core.ts";

// Runs the installed nuclei with the templates, tags and severities chosen on the Nuclei page.
// nuclei sends requests to the target, so runs need the user's confirmation that they are authorised.

export * from "../nuclei-core.ts";

export interface NucleiRunResult {
  ok: boolean;
  command: string;
  findings: Finding[];
  rawCount: number;
  error?: string;
}

export async function runNuclei(r: NucleiRequest): Promise<NucleiRunResult> {
  const command = nucleiCommandPreview(r);
  const dir = path.join(process.cwd(), "data", "tmp");
  await fs.mkdir(dir, { recursive: true });
  const listFile = path.join(dir, `nuclei-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}.txt`);
  await fs.writeFile(listFile, r.targets.join("\n"));
  try {
    const proxy = activeProxy();
    const args = buildNucleiArgs(r, listFile);
    if (proxy) args.push("-proxy", proxy.url);
    const res = await runTool("nuclei", args, NUCLEI_TIMEOUT_MS);
    if (!res.ok) return { ok: false, command, findings: [], rawCount: 0, error: res.error };
    const findings = parseNucleiJsonl(res.lines);
    return { ok: true, command, findings, rawCount: res.lines.length };
  } finally {
    await fs.rm(listFile, { force: true });
  }
}

/**
 * Runs nuclei with the given tags on candidate URLs, for the SQL and XSS pages. Returns no findings and a
 * warning when nuclei is missing or fails, so the page still shows its own results.
 */
export async function nucleiTagFindings(urls: string[], tags: string[], warnings: string[]): Promise<Finding[]> {
  if (!tags.length || !urls.length) return [];
  if (!(await toolPath("nuclei"))) {
    warnings.push("nuclei is not installed, so its templates for the selected tags did not run. Install it on the Tools page.");
    return [];
  }
  const r = await runNuclei({
    targets: [...new Set(urls)].slice(0, 200),
    severities: [...NUCLEI_SEVERITIES],
    tags,
    templates: [],
    automatic: false,
    rateLimit: 50,
    concurrency: 10,
  });
  if (!r.ok) {
    warnings.push(`nuclei (${tags.join(", ")}): ${r.error ?? "failed."}`);
    return [];
  }
  return r.findings;
}
