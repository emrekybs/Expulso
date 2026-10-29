import "server-only";
import fs from "node:fs/promises";
import path from "node:path";
import { runTool, toolPath } from "../tools.ts";
import { parseTarget, type ParsedTarget } from "../target.ts";
import { mapLimit } from "../net.ts";
import type { Finding } from "../types.ts";
import { parseDalfoxLines, xssCandidates } from "../dalfox-core.ts";
import { runUrlArchive } from "./url-archive.ts";
import { reflectedXss } from "./vuln-scan.ts";
import { nucleiTagFindings } from "./nuclei-scan.ts";

// XSS testing for URLs with parameters. With Dalfox installed, Dalfox does the testing. Without it, the
// built-in reflection check runs on every candidate parameter. Domains are first expanded to their known
// URLs: gau when installed, otherwise the Wayback and Common Crawl archives.

export const DALFOX_TIMEOUT_MS = 30 * 60 * 1000;

export interface DalfoxRequest {
  targets: string[];
  discover: boolean;
  limit: number;
  concurrency: number;
  /** Nuclei tags run on the same candidate URLs, for example xss. */
  nucleiTags?: string[];
}

export interface DalfoxResult {
  engine: "dalfox" | "built-in";
  discovered: number;
  candidates: { url: string; params: string[] }[];
  findings: Finding[];
  warnings: string[];
  command?: string;
}

/** Known URLs of a domain: gau when installed, otherwise the built-in archives. Shared with the SQL page. */
export async function discoverUrls(domain: string, warnings: string[]): Promise<string[]> {
  if (await toolPath("gau")) {
    const r = await runTool("gau", ["--subs", "--threads", "5", domain], 300000);
    if (r.ok) return r.lines;
    warnings.push(`gau: ${r.error ?? "no output"} Falling back to the built-in archives.`);
  }
  const parsed = parseTarget(domain);
  if ("error" in parsed) return [];
  const archive = await runUrlArchive(parsed as ParsedTarget);
  warnings.push(...(archive.warnings ?? []));
  return archive.data.urls;
}

async function runDalfoxEngines(req: DalfoxRequest): Promise<DalfoxResult> {
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
      if (!req.discover) warnings.push(`${p.host}: enter a full URL with parameters, or turn on URL discovery.`);
      else {
        const found = await discoverUrls(p.host, warnings);
        discovered += found.length;
        urls.push(...found);
      }
    } else warnings.push(`${p.input}: only domains and URLs are supported on this page.`);
  }

  const candidates = xssCandidates([...new Set(urls)], Math.max(1, Math.min(500, req.limit)));
  const engine: DalfoxResult["engine"] = (await toolPath("dalfox")) ? "dalfox" : "built-in";
  if (!candidates.length) return { engine, discovered, candidates, findings: [], warnings: [...warnings, "No URL with an XSS-likely parameter was found."] };

  if (engine === "dalfox") {
    const dir = path.join(process.cwd(), "data", "tmp");
    await fs.mkdir(dir, { recursive: true });
    const list = path.join(dir, `dalfox-${Date.now().toString(36)}.txt`);
    await fs.writeFile(list, candidates.map((c) => c.url).join("\n"));
    try {
      const args = ["file", list, "--silence", "--format", "json", "--worker", String(req.concurrency)];
      const r = await runTool("dalfox", args, DALFOX_TIMEOUT_MS);
      const command = ["dalfox", ...args].join(" ");
      if (!r.ok) return { engine, discovered, candidates, findings: [], warnings: [...warnings, r.error ?? "Dalfox failed."], command };
      return { engine, discovered, candidates, findings: parseDalfoxLines(r.lines), warnings, command };
    } finally {
      await fs.rm(list, { force: true });
    }
  }

  const pairs = candidates.flatMap((c) => c.params.map((param) => ({ url: c.url, param })));
  const results = await mapLimit(pairs, Math.max(1, Math.min(20, req.concurrency)), ({ url, param }) => reflectedXss(url, param));
  return {
    engine,
    discovered,
    candidates,
    findings: results.filter((f): f is Finding => !!f),
    warnings: [...warnings, "Dalfox is not installed, so the built-in reflection check ran. Install Dalfox on the Tools page for payload testing."],
  };
}

export async function runDalfox(req: DalfoxRequest): Promise<DalfoxResult> {
  const result = await runDalfoxEngines(req);
  result.findings.push(...(await nucleiTagFindings(result.candidates.map((c) => c.url), req.nucleiTags ?? [], result.warnings)));
  return result;
}
