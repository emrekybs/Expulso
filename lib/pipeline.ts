import "server-only";
import crypto from "node:crypto";
import { MODULES, getModule, modulesForMode, type ModuleDef, type ModuleId, type ScanMode } from "./modules-config.ts";
import { inScope, parseTarget, type ParsedTarget } from "./target.ts";
import { runModule } from "./run-module.ts";
import { mapLimit } from "./net.ts";
import { SEVERITY_ORDER, type Finding } from "./types.ts";
import { saveRecord } from "./store.ts";
import type { ChildScan, ModuleEntry, ScanCounts, ScanRecord } from "./scan-types.ts";

// Full Scan pipeline, run on the server so it keeps going when the browser tab is closed or the user
// opens another page. Stages:
//   1. Target modules (passive, then active when the mode asks for it).
//   2. Chain: every live subdomain found in stage 1 gets its own module run.
//   3. Port scan of each address the chain finds, once per address.

const ROOT_CONCURRENCY = 6;
const CHILD_CONCURRENCY = 3;
const SCANS_AT_ONCE = 2;
const DEFAULT_CHAIN_LIMIT = 15;

const CHAIN_PASSIVE: ModuleId[] = ["dns", "geoip", "ports-passive", "cloud"];
const CHAIN_ACTIVE: ModuleId[] = ["http", "webtech", "waf", "admin-panels"];

export interface ScanRequest {
  target: string;
  mode: ScanMode;
  options?: Record<string, Record<string, unknown>>;
  /** Optional allow-list of domains. Hosts outside it are never scanned. */
  scope?: string[];
  chainLimit?: number;
}

export type StartResult = { ok: true; record: ScanRecord } | { ok: false; error: string; code: string };

// Simple slot limiter: at most SCANS_AT_ONCE scans run their modules at the same time.
const waiting: (() => void)[] = [];
let active = 0;
function acquire(): Promise<void> {
  if (active < SCANS_AT_ONCE) {
    active++;
    return Promise.resolve();
  }
  return new Promise((resolve) => waiting.push(() => {
    active++;
    resolve();
  }));
}
function release() {
  active--;
  waiting.shift()?.();
}

function optionsFor(def: ModuleDef, options?: Record<string, Record<string, unknown>>): Record<string, unknown> {
  return { ...Object.fromEntries((def.options ?? []).map((o) => [o.key, o.default])), ...(def.fullScanOptions ?? {}), ...(options?.[def.id] ?? {}) };
}

async function runEntry(def: ModuleDef, parsed: ParsedTarget, options?: Record<string, Record<string, unknown>>): Promise<ModuleEntry> {
  const run = await runModule(def.id, parsed, optionsFor(def, options));
  console.log(`[scan] ${def.id} ${parsed.host} ${run.ok ? "OK" : run.code} ${run.durationMs}ms`);
  if (run.ok && run.result) {
    return {
      id: def.id,
      title: def.title,
      tier: def.tier,
      ok: true,
      summary: run.result.summary,
      findings: run.result.findings,
      data: run.result.data,
      warnings: run.result.warnings ?? [],
      sources: run.result.sources ?? [],
      durationMs: run.durationMs,
    };
  }
  return { id: def.id, title: def.title, tier: def.tier, ok: false, error: run.error, code: run.code, durationMs: run.durationMs };
}

/** Live subdomains from the subdomains module: they resolve, or answered over HTTP. */
function liveHosts(modules: ModuleEntry[], root: string, limit: number): { host: string; ips: string[] }[] {
  const sub = modules.find((m) => m.id === "subdomains" && m.ok);
  if (!sub || !sub.ok) return [];
  const entries = ((sub.data as { entries?: { host: string; ips: string[]; resolved?: boolean; http?: { status?: number } | null }[] }).entries ?? [])
    .filter((e) => e.host !== root && (e.http?.status || (e.resolved && e.ips.length)));
  // Hosts that answered over HTTP first, then the rest in list order.
  entries.sort((a, b) => Number(!!b.http?.status) - Number(!!a.http?.status));
  return entries.slice(0, limit).map((e) => ({ host: e.host, ips: e.ips }));
}

function countFindings(findings: (Finding & { module: string })[]): ScanCounts {
  const c: ScanCounts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

function finish(rec: ScanRecord, modules: ModuleEntry[], children: ChildScan[]) {
  const order = (id: string) => MODULES.findIndex((m) => m.id === id);
  rec.modules = [...modules].sort((a, b) => order(a.id) - order(b.id));
  rec.children = children;
  const rootFindings = rec.modules.flatMap((m) => (m.ok ? m.findings.map((f) => ({ ...f, module: m.title })) : []));
  const childFindings = children.flatMap((c) => c.modules.flatMap((m) => (m.ok ? m.findings.map((f) => ({ ...f, module: `${m.title} · ${c.host}` })) : [])));
  rec.findings = [...rootFindings, ...childFindings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  rec.counts = countFindings(rec.findings);
  const all = [...rec.modules, ...children.flatMap((c) => c.modules)];
  rec.modulesRun = all.length;
  rec.modulesOk = all.filter((m) => m.ok).length;
  rec.hosts = children.length;
}

async function execute(rec: ScanRecord, parsed: ParsedTarget, mods: ModuleDef[], req: ScanRequest) {
  await acquire();
  const modules: ModuleEntry[] = [];
  const children: ChildScan[] = [];
  try {
    rec.stage = "Target modules";
    rec.total = mods.length;
    rec.done = 0;
    await mapLimit(mods, ROOT_CONCURRENCY, async (def) => {
      modules.push(await runEntry(def, parsed, req.options));
      rec.done++;
    });
    rec.modules = [...modules];
    const hosts = liveHosts(modules, parsed.host, Math.max(0, Math.min(50, req.chainLimit ?? DEFAULT_CHAIN_LIMIT))).filter((h) => inScope(h.host, req.scope));
    if (hosts.length) {
      const chainMods = [...CHAIN_PASSIVE, ...(req.mode === "passive" ? [] : CHAIN_ACTIVE)].map((id) => getModule(id)!);
      const seenIps = new Set<string>();
      for (const m of modules) {
        if (m.id === "ports-scan" && m.ok) for (const h of (m.data as { hosts?: { ip: string }[] }).hosts ?? []) seenIps.add(h.ip);
      }
      rec.stage = `Chain: ${hosts.length} live subdomain(s)`;
      rec.total = mods.length + hosts.length;

      await mapLimit(hosts, CHILD_CONCURRENCY, async (h) => {
        const childParsed = parseTarget(h.host);
        const child: ChildScan = { host: h.host, ips: h.ips, modules: [] };
        if (!("error" in childParsed)) {
          const runnable = chainMods.filter((def) => def.accepts.includes(childParsed.kind));
          child.modules = await mapLimit(runnable, 3, (def) => runEntry(def, childParsed, req.options));
        }
        if (req.mode !== "passive") {
          const portDef = getModule("ports-scan")!;
          const fresh = h.ips.filter((ip) => !seenIps.has(ip));
          for (const ip of fresh) {
            seenIps.add(ip);
            const ipParsed = parseTarget(ip);
            if (!("error" in ipParsed)) child.modules.push(await runEntry(portDef, ipParsed, req.options));
          }
        }
        children.push(child);
        rec.done++;
      });
    }

    finish(rec, modules, children);
    rec.status = "done";
    rec.stage = "Complete";
  } catch (e) {
    console.error(`[scan ${rec.id}] failed`, e);
    rec.status = "failed";
    rec.error = "The scan stopped unexpectedly. Check the logs.";
    rec.stage = "Failed";
    finish(rec, modules, children);
  } finally {
    rec.finishedAt = new Date().toISOString();
    release();
    await saveRecord(rec);
  }
}

/** Validates the request, stores a running record and starts the pipeline in the background. */
export async function startScan(req: ScanRequest): Promise<StartResult> {
  const parsed = parseTarget(String(req.target ?? ""));
  if ("error" in parsed) return { ok: false, error: parsed.error, code: "invalid_target" };
  if (!inScope(parsed.host, req.scope)) return { ok: false, error: `${parsed.host} is outside the scope you set.`, code: "out_of_scope" };
  const mode: ScanMode = req.mode === "active" || req.mode === "full" ? req.mode : "passive";
  const mods = modulesForMode(mode).filter((m) => m.accepts.includes(parsed.kind));

  const rec: ScanRecord = {
    id: crypto.randomUUID(),
    requestId: crypto.randomUUID().slice(0, 8),
    target: parsed.host,
    kind: parsed.kind,
    mode,
    status: "running",
    startedAt: new Date().toISOString(),
    stage: "Queued",
    done: 0,
    total: mods.length,
    scope: req.scope?.length ? req.scope : undefined,
    chainLimit: req.chainLimit ?? DEFAULT_CHAIN_LIMIT,
    options: req.options,
    modules: [],
    children: [],
    findings: [],
    warnings: [],
  };
  await saveRecord(rec);
  void execute(rec, parsed, mods, { ...req, mode });
  return { ok: true, record: rec };
}
