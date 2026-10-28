import "server-only";
import fs from "node:fs/promises";
import path from "node:path";
import { runTool, toolPath } from "../tools.ts";

// Optional external engines for the Directories module. When feroxbuster or dirsearch is installed,
// it does the path requests; the built-in engine is the fallback.

export interface EngineRow {
  url: string;
  status: number;
  size: number;
  redirect?: string;
}

/** feroxbuster default line: "200      GET       12l       34w      567c http://host/admin" */
const FEROX_LINE = /^(\d{3})\s+\S+\s+\d+l\s+\d+w\s+(\d+)c\s+(https?:\/\/\S+)/;

export function parseFeroxLines(lines: string[]): EngineRow[] {
  const rows: EngineRow[] = [];
  for (const line of lines) {
    const m = line.match(FEROX_LINE);
    if (m) rows.push({ url: m[3], status: Number(m[1]), size: Number(m[2]) });
  }
  return rows;
}

interface DirsearchResult {
  url?: string;
  status?: number;
  "content-length"?: number;
  redirect?: string;
}

/** dirsearch JSON report: { results: [{ url, status, "content-length", redirect }] } */
export function parseDirsearchJson(text: string): EngineRow[] {
  try {
    const data = JSON.parse(text) as { results?: DirsearchResult[] };
    return (data.results ?? [])
      .filter((r): r is DirsearchResult & { url: string; status: number } => typeof r.url === "string" && typeof r.status === "number")
      .map((r) => ({ url: r.url, status: r.status, size: Number(r["content-length"] ?? 0), redirect: r.redirect || undefined }));
  } catch {
    return [];
  }
}

export type ExternalEngine = "feroxbuster" | "dirsearch";

/** Picks the engine: "auto" prefers feroxbuster, then dirsearch, then the built-in engine. */
export async function pickEngine(requested: string): Promise<{ engine: ExternalEngine | "builtin"; note?: string }> {
  if (requested === "builtin") return { engine: "builtin" };
  if (requested === "feroxbuster" || requested === "dirsearch") {
    if (await toolPath(requested)) return { engine: requested };
    return { engine: "builtin", note: `${requested} is not installed, so the built-in engine was used. Install it on the Tools page.` };
  }
  if (await toolPath("feroxbuster")) return { engine: "feroxbuster" };
  if (await toolPath("dirsearch")) return { engine: "dirsearch" };
  return { engine: "builtin" };
}

export async function runExternalEngine(engine: ExternalEngine, origin: string, words: string[], timeoutMs: number): Promise<{ rows: EngineRow[]; error?: string }> {
  const dir = path.join(process.cwd(), "data", "tmp");
  await fs.mkdir(dir, { recursive: true });
  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const wordlist = path.join(dir, `words-${id}.txt`);
  const report = path.join(dir, `report-${id}.json`);
  await fs.writeFile(wordlist, words.map((w) => w.replace(/^\//, "")).join("\n"));
  try {
    if (engine === "feroxbuster") {
      const r = await runTool("feroxbuster", ["-u", origin, "-w", wordlist, "-n", "--no-state", "-t", "20", "-q", "-C", "404", "--timeout", "7"], timeoutMs);
      return r.ok ? { rows: parseFeroxLines(r.lines) } : { rows: [], error: r.error };
    }
    const r = await runTool("dirsearch", ["-u", origin, "-w", wordlist, "-q", "-t", "20", "--timeout=7", "--format=json", "-o", report], timeoutMs);
    if (!r.ok) return { rows: [], error: r.error };
    const text = await fs.readFile(report, "utf8").catch(() => "");
    return { rows: parseDirsearchJson(text) };
  } finally {
    await fs.rm(wordlist, { force: true });
    await fs.rm(report, { force: true });
  }
}
