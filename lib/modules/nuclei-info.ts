import { UserError } from "../net.ts";
import { runTool, toolPath } from "../tools.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";

/**
 * nuclei is used ONLY for information-gathering templates: technology and panel detection.
 * `-severity info` excludes every vulnerability template, so nothing here tests for a flaw.
 */
export interface NucleiHit {
  templateId: string;
  name: string;
  matchedAt: string;
  tags: string[];
  extracted: string[];
}

export interface NucleiData {
  target: string;
  hits: NucleiHit[];
  tags: string[];
}

interface NucleiLine {
  "template-id"?: string;
  info?: { name?: string; severity?: string; tags?: string | string[] };
  "matched-at"?: string;
  "extracted-results"?: string[];
}

export function parseNucleiJsonl(lines: string[]): NucleiHit[] {
  const out: NucleiHit[] = [];
  for (const line of lines) {
    if (!line.startsWith("{")) continue;
    let j: NucleiLine;
    try {
      j = JSON.parse(line) as NucleiLine;
    } catch {
      continue;
    }
    if (j.info?.severity && j.info.severity !== "info") continue; // defensive: info only
    const tags = Array.isArray(j.info?.tags) ? j.info!.tags : (j.info?.tags ?? "").split(",").map((t) => t.trim()).filter(Boolean);
    out.push({ templateId: j["template-id"] ?? "unknown", name: j.info?.name ?? j["template-id"] ?? "detection", matchedAt: j["matched-at"] ?? "", tags, extracted: j["extracted-results"] ?? [] });
  }
  return out;
}

export async function runNucleiInfo(t: ParsedTarget): Promise<ModuleOutput<NucleiData>> {
  if (t.kind === "cidr") throw new UserError("nuclei info checks need a single domain, URL or IP.");
  if (!(await toolPath("nuclei"))) {
    throw new UserError("nuclei is not installed. Install it with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates", "tool_missing");
  }
  const url = t.url ?? `https://${t.host}`;
  const r = await runTool(
    "nuclei",
    ["-u", url, "-tags", "tech,panel", "-severity", "info", "-jsonl", "-silent", "-nc", "-duc", "-rl", "30", "-timeout", "8", "-retries", "0"],
    180000,
  );
  if (!r.ok) throw new UserError(r.error ?? "nuclei failed.", "tool_failed");
  const hits = parseNucleiJsonl(r.lines);
  const findings: Finding[] = hits
    .filter((h) => h.tags.includes("panel"))
    .map((h) => ({ severity: "info" as const, title: `Login / admin panel detected: ${h.name}`, detail: "Detected by an information-gathering nuclei template. Reachability and access control still need a manual check.", evidence: h.matchedAt, recommendation: "Restrict admin panels to trusted networks and enforce strong authentication." }));
  const tags = [...new Set(hits.flatMap((h) => h.tags))].sort();
  return { summary: `${hits.length} detection(s) from info templates`, findings, data: { target: url, hits, tags } };
}
