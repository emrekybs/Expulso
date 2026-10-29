import "server-only";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { runTool, toolPath } from "./tools.ts";
import { parseTarget } from "./target.ts";
import type { Finding } from "./types.ts";
import { runSubdomains } from "./modules/subdomains.ts";
import { discoverUrls } from "./modules/dalfox-scan.ts";
import { crawlUrlsFor } from "./modules/crawl.ts";
import { runDalfox } from "./modules/dalfox-scan.ts";
import { runSqli } from "./modules/sqli-scan.ts";
import { runNuclei } from "./modules/nuclei-scan.ts";
import { NUCLEI_SEVERITIES } from "./nuclei-core.ts";
import { xssCandidates } from "./dalfox-core.ts";
import { sqliCandidates } from "./sqli-core.ts";
import { parseHttpxJsonl, selectHosts, STAGES, type PipelineRequest, type StageId, type ProbeRow } from "./autopipe-core.ts";
import { activeProxy, proxyAddress, proxyScope } from "./settings.ts";

// Autopipeline: one run per domain. Each stage writes its result to the record and to data/pipelines,
// so a finished stage is never lost, even when a later stage fails.

export const PIPE_DIR = path.join(process.cwd(), "data", "pipelines");
const ID = /^[a-z0-9-]{8,64}$/;

export interface StageResult {
  id: StageId;
  title: string;
  status: "pending" | "running" | "done" | "skipped" | "failed";
  engine?: string;
  summary?: string;
  findings: Finding[];
  warnings: string[];
  startedAt?: string;
  finishedAt?: string;
}

export interface PipelineRecord {
  id: string;
  target: string;
  status: "queued" | "running" | "paused" | "stopped" | "done" | "failed";
  createdAt: string;
  finishedAt?: string;
  request: PipelineRequest;
  stages: StageResult[];
  hosts: ProbeRow[];
  selected: string[];
  candidates: { xss: number; sqli: number };
  error?: string;
}

export function validId(id: string): boolean {
  return ID.test(id);
}

async function save(rec: PipelineRecord) {
  await fsp.mkdir(PIPE_DIR, { recursive: true });
  const file = path.join(PIPE_DIR, `${rec.id}.json`);
  const tmp = `${file}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(rec));
  await fsp.rename(tmp, file);
}

export async function readPipeline(id: string): Promise<PipelineRecord | null> {
  if (!validId(id)) return null;
  try {
    return JSON.parse(await fsp.readFile(path.join(PIPE_DIR, `${id}.json`), "utf8")) as PipelineRecord;
  } catch {
    return null;
  }
}

export async function listPipelines(): Promise<PipelineRecord[]> {
  if (!fs.existsSync(PIPE_DIR)) return [];
  const files = (await fsp.readdir(PIPE_DIR)).filter((f) => f.endsWith(".json"));
  const out: PipelineRecord[] = [];
  for (const f of files) {
    const rec = await readPipeline(f.replace(/\.json$/, ""));
    if (rec) out.push(rec);
  }
  return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 200);
}

function stageRecord(rec: PipelineRecord, id: StageId): StageResult {
  return rec.stages.find((s) => s.id === id)!;
}

interface Control {
  paused: boolean;
  stop: boolean;
}
const controls = new Map<string, Control>();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Pause and stop requests. Stop takes effect when the stage that is running finishes. */
export function controlRun(id: string, action: "pause" | "resume" | "stop"): boolean {
  const c = controls.get(id);
  if (!c) return false;
  if (action === "pause") c.paused = true;
  if (action === "resume") c.paused = false;
  if (action === "stop") {
    c.stop = true;
    c.paused = false;
  }
  return true;
}

/** Waits while paused. Returns false when the run has been stopped. */
async function gate(rec: PipelineRecord): Promise<boolean> {
  const c = controls.get(rec.id);
  if (!c) return true;
  if (c.paused && !c.stop) {
    rec.status = "paused";
    await save(rec);
    while (c.paused && !c.stop) await sleep(1000);
    rec.status = "running";
    await save(rec);
  }
  return !c.stop;
}

async function runStage(rec: PipelineRecord, id: StageId, fn: (s: StageResult) => Promise<void>) {
  const s = stageRecord(rec, id);
  if (!(await gate(rec)) || controls.get(rec.id)?.stop) {
    s.status = "skipped";
    s.summary = "Stopped before this stage.";
    await save(rec);
    return;
  }
  if (!rec.request.stages[id]) {
    s.status = "skipped";
    s.summary = "Turned off for this run.";
    await save(rec);
    return;
  }
  s.status = "running";
  s.startedAt = new Date().toISOString();
  await save(rec);
  try {
    await fn(s);
    if (s.status === "running") s.status = "done";
  } catch (e) {
    s.status = "failed";
    s.summary = `Failed: ${(e as Error).message}`;
    console.error(`[autopipe ${rec.id}] ${id}`, e);
  }
  s.finishedAt = new Date().toISOString();
  await save(rec);
}

async function runDomain(rec: PipelineRecord) {
  const r = rec.request;
  const domain = rec.target;
  const parsed = parseTarget(domain);
  if ("error" in parsed || parsed.kind !== "domain") throw new Error("The autopipeline needs a domain.");

  await runStage(rec, "subdomains", async (s) => {
    const mod = await runSubdomains(parsed, { resolve: true, httpStatus: true, tools: true, dnsBrute: true, bruteSize: "small", screenshots: false });
    const entries = (mod.data as { entries: { host: string; resolved: boolean | null; http?: { status: number; title: string } | null; ips: string[] }[] }).entries;
    rec.hosts = entries
      .filter((e) => e.resolved || e.http)
      .map((e) => ({ host: e.host, status: e.http?.status ?? null, title: e.http?.title ?? "", tech: [], url: `https://${e.host}` }));
    s.engine = (await toolPath("subfinder")) ? "subfinder + built-in" : "built-in";
    s.summary = `${entries.length} subdomain(s), ${rec.hosts.length} resolved`;
    s.warnings.push(...(mod.warnings ?? []));
  });

  await runStage(rec, "probe", async (s) => {
    if (!(await toolPath("httpx"))) {
      s.engine = "built-in status check";
      s.summary = `${rec.hosts.filter((h) => h.status).length} host(s) answered over HTTP`;
      return;
    }
    const dir = path.join(process.cwd(), "data", "tmp");
    await fsp.mkdir(dir, { recursive: true });
    const list = path.join(dir, `httpx-${rec.id}.txt`);
    await fsp.writeFile(list, rec.hosts.map((h) => h.host).join("\n"));
    try {
      const res = await runTool("httpx", ["-l", list, "-json", "-silent", "-status-code", "-title", "-tech-detect", "-rl", "50", "-timeout", "8"], 30 * 60 * 1000);
      s.engine = "httpx";
      if (!res.ok) {
        s.warnings.push(res.error ?? "httpx failed.");
        return;
      }
      const probed = parseHttpxJsonl(res.lines);
      const byHost = new Map(probed.map((p) => [p.host, p]));
      rec.hosts = rec.hosts.map((h) => {
        const p = byHost.get(h.host);
        return p ? { ...h, status: p.status, title: p.title, tech: p.tech, url: p.url } : h;
      });
      s.summary = `${probed.length} live host(s) probed`;
    } finally {
      await fsp.rm(list, { force: true });
    }
  });

  const selected = selectHosts(rec.hosts, r.statusFilter, r.hostLimit);
  rec.selected = selected.map((h) => h.host);
  const selectedUrls = selected.map((h) => h.url);

  await runStage(rec, "nucleiAs", async (s) => {
    if (!selectedUrls.length) {
      s.status = "skipped";
      s.summary = "No host passed the status filter.";
      return;
    }
    if (!(await toolPath("nuclei"))) {
      s.status = "skipped";
      s.summary = "nuclei is not installed. Install it on the Tools page.";
      return;
    }
    const res = await runNuclei({ targets: selectedUrls, severities: [...NUCLEI_SEVERITIES], tags: r.nucleiTags, templates: [], automatic: true, rateLimit: 50, concurrency: 10 });
    s.engine = "nuclei -as";
    if (!res.ok) throw new Error(res.error ?? "nuclei failed.");
    s.findings.push(...res.findings);
    s.summary = `${res.findings.length} finding(s) on ${selectedUrls.length} host(s)`;
  });

  const urlsPerHost = new Map<string, string[]>();
  await runStage(rec, "urlParams", async (s) => {
    if (!selected.length) {
      s.status = "skipped";
      s.summary = "No host passed the status filter.";
      return;
    }
    s.engine = (await toolPath("gau")) ? "gau" : "built-in archives";
    for (const h of selected) {
      const archived = await discoverUrls(h.host, s.warnings);
      const crawled = await crawlUrlsFor(h.host, 10);
      urlsPerHost.set(h.host, [...archived, ...crawled]);
    }
    const all = [...urlsPerHost.values()].flat();
    rec.candidates = {
      xss: xssCandidates([...new Set(all)], r.urlLimit).length,
      sqli: sqliCandidates([...new Set(all)], r.urlLimit).length,
    };
    s.summary = `${all.length} URL(s) found · ${rec.candidates.xss} XSS and ${rec.candidates.sqli} SQL candidate(s)`;
  });

  const all = [...new Set([...urlsPerHost.values()].flat())];
  const xssUrls = xssCandidates(all, r.urlLimit).map((c) => c.url);
  const sqliUrls = sqliCandidates(all, r.urlLimit).map((c) => c.url);

  await runStage(rec, "xss", async (s) => {
    if (!xssUrls.length) {
      s.status = "skipped";
      s.summary = "No XSS candidates.";
      return;
    }
    const res = await runDalfox({ targets: xssUrls, discover: false, limit: r.urlLimit, concurrency: 5 });
    s.engine = res.engine;
    s.findings.push(...res.findings);
    s.warnings.push(...res.warnings);
    s.summary = `${res.findings.length} finding(s) on ${xssUrls.length} candidate(s)`;
  });

  await runStage(rec, "sqli", async (s) => {
    if (!sqliUrls.length) {
      s.status = "skipped";
      s.summary = "No SQL candidates.";
      return;
    }
    const res = await runSqli({ targets: sqliUrls, level: 1, risk: 1, techniques: ["B", "E", "T"], threads: 1, limit: r.urlLimit, nucleiTags: [] }, { discover: false });
    s.engine = res.engine;
    s.findings.push(...res.findings);
    s.warnings.push(...res.warnings);
    s.summary = `${res.findings.length} finding(s) on ${sqliUrls.length} candidate(s)`;
  });
}

/** Creates one record per domain and runs them one after another in the background. */
export async function startPipelines(req: PipelineRequest): Promise<string[]> {
  const ids: string[] = [];
  const records: PipelineRecord[] = [];
  for (const target of req.targets) {
    const rec: PipelineRecord = {
      id: crypto.randomUUID(),
      target,
      status: "queued",
      createdAt: new Date().toISOString(),
      request: { ...req, targets: [target] },
      stages: STAGES.map((s) => ({ id: s.id, title: s.title, status: "pending", findings: [], warnings: [] })),
      hosts: [],
      selected: [],
      candidates: { xss: 0, sqli: 0 },
    };
    ids.push(rec.id);
    records.push(rec);
    await save(rec);
  }
  const proxy = req.proxyMode === "off" ? null : req.proxyMode === "on" ? proxyAddress() : activeProxy();
  void proxyScope.run({ proxy }, async () => {
    for (const rec of records) {
      controls.set(rec.id, { paused: false, stop: false });
      rec.status = "running";
      await save(rec);
      try {
        await runDomain(rec);
        rec.status = controls.get(rec.id)?.stop ? "stopped" : "done";
      } catch (e) {
        rec.status = "failed";
        rec.error = (e as Error).message;
      }
      controls.delete(rec.id);
      rec.finishedAt = new Date().toISOString();
      await save(rec);
    }
  });
  return ids;
}
