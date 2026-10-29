import "server-only";
import fs from "node:fs/promises";
import path from "node:path";
import { runTool, toolPath } from "../tools.ts";
import { parseTarget } from "../target.ts";
import { mapLimit } from "../net.ts";
import type { Finding } from "../types.ts";
import { parseSqlmapOutput, sqliCandidates, sqlmapArgs, type SqliRequest } from "../sqli-core.ts";
import { discoverUrls } from "./dalfox-scan.ts";
import { sqlErrorProbe } from "./vuln-scan.ts";

// SQL injection detection. With sqlmap installed, each candidate parameter gets a detection-only sqlmap run.
// Without it, the built-in error-based check runs. Nothing is extracted from the database.

const PER_PARAM_TIMEOUT_MS = 10 * 60 * 1000;

export interface SqliResult {
  engine: "sqlmap" | "built-in";
  discovered: number;
  candidates: { url: string; params: string[] }[];
  findings: Finding[];
  warnings: string[];
  command?: string;
}

export async function runSqli(req: SqliRequest, opts: { discover: boolean }): Promise<SqliResult> {
  const warnings: string[] = [];
  const urls: string[] = [];
  let discovered = 0;
  for (const raw of req.targets) {
    const p = parseTarget(raw);
    if ("error" in p) {
      warnings.push(p.error);
      continue;
    }
    if (p.kind === "url" && p.url) urls.push(p.url);
    else if (p.kind === "domain") {
      if (!opts.discover) warnings.push(`${p.host}: enter a full URL with parameters, or turn on URL discovery.`);
      else {
        const found = await discoverUrls(p.host, warnings);
        discovered += found.length;
        urls.push(...found);
      }
    } else warnings.push(`${p.input}: only domains and URLs are supported on this page.`);
  }

  const candidates = sqliCandidates([...new Set(urls)], req.limit);
  const engine: SqliResult["engine"] = (await toolPath("sqlmap")) ? "sqlmap" : "built-in";
  if (!candidates.length) return { engine, discovered, candidates, findings: [], warnings: [...warnings, "No URL with a database-like parameter was found."] };

  const pairs = candidates.flatMap((c) => c.params.map((param) => ({ url: c.url, param })));

  if (engine === "sqlmap") {
    const outDir = path.join(process.cwd(), "data", "tmp", "sqlmap");
    await fs.mkdir(outDir, { recursive: true });
    const findings: Finding[] = [];
    const commands: string[] = [];
    for (const { url, param } of pairs) {
      const args = sqlmapArgs(req, url, param, outDir);
      commands.push(["sqlmap", ...args].join(" "));
      const r = await runTool("sqlmap", args, PER_PARAM_TIMEOUT_MS);
      if (!r.ok) {
        warnings.push(`${param} on ${url}: ${r.error ?? "sqlmap failed."}`);
        continue;
      }
      findings.push(...parseSqlmapOutput(r.lines, url));
    }
    const seen = new Set<string>();
    const unique = findings.filter((f) => {
      const key = `${f.evidence}|${f.title}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    return { engine, discovered, candidates, findings: unique, warnings, command: commands.slice(0, 3).join("\n") + (commands.length > 3 ? `\n… ${commands.length - 3} more` : "") };
  }

  const results = await mapLimit(pairs, Math.max(1, Math.min(4, req.threads)), ({ url, param }) => sqlErrorProbe(url, param));
  return {
    engine,
    discovered,
    candidates,
    findings: results.filter((f): f is Finding => !!f),
    warnings: [...warnings, "sqlmap is not installed, so the built-in error check ran. It finds only error-based injection. Install sqlmap on the Tools page for a deeper detection run."],
  };
}
