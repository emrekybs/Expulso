import "server-only";
import fs from "node:fs/promises";
import path from "node:path";
import { runTool } from "../tools.ts";
import type { Finding } from "../types.ts";
import { buildNucleiArgs, nucleiCommandPreview, parseNucleiJsonl, NUCLEI_TIMEOUT_MS, type NucleiRequest } from "../nuclei-core.ts";

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
    const res = await runTool("nuclei", buildNucleiArgs(r, listFile), NUCLEI_TIMEOUT_MS);
    if (!res.ok) return { ok: false, command, findings: [], rawCount: 0, error: res.error };
    const findings = parseNucleiJsonl(res.lines);
    return { ok: true, command, findings, rawCount: res.lines.length };
  } finally {
    await fs.rm(listFile, { force: true });
  }
}
