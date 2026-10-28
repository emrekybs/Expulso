import "server-only";
import fs from "node:fs/promises";
import path from "node:path";
import type { ScanRecord, ScanSummary } from "./scan-types.ts";

// Saved scans live in data/scans: one JSON file per finished scan plus an index of summaries.
// Running scans live in memory until they finish.

export const SCAN_DIR = path.join(process.cwd(), "data", "scans");
const INDEX = path.join(SCAN_DIR, "index.json");
const ID = /^[a-z0-9-]{8,64}$/;

const memory = new Map<string, ScanRecord>();
let chain: Promise<unknown> = Promise.resolve();

/** Serialises file writes so two scans finishing together cannot corrupt the index. */
function serial<T>(fn: () => Promise<T>): Promise<T> {
  const next = chain.then(fn, fn);
  chain = next.catch(() => undefined);
  return next;
}

async function writeAtomic(file: string, data: string) {
  await fs.mkdir(SCAN_DIR, { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, data);
  await fs.rename(tmp, file);
}

async function readIndex(): Promise<ScanSummary[]> {
  try {
    return JSON.parse(await fs.readFile(INDEX, "utf8")) as ScanSummary[];
  } catch {
    return [];
  }
}

export function summaryOf(r: ScanRecord): ScanSummary {
  return {
    id: r.id,
    target: r.target,
    kind: r.kind,
    mode: r.mode,
    status: r.status,
    startedAt: r.startedAt,
    finishedAt: r.finishedAt,
    stage: r.stage,
    done: r.done,
    total: r.total,
    counts: r.counts,
    modulesRun: r.modulesRun,
    modulesOk: r.modulesOk,
    hosts: r.hosts,
    scope: r.scope,
    error: r.error,
  };
}

export function validId(id: string): boolean {
  return ID.test(id);
}

/** Stores the summary at once, and the full record once the scan has finished. */
export async function saveRecord(r: ScanRecord): Promise<void> {
  if (r.status === "running") memory.set(r.id, r);
  else memory.delete(r.id);
  await serial(async () => {
    if (r.status !== "running") await writeAtomic(path.join(SCAN_DIR, `${r.id}.json`), JSON.stringify(r));
    const index = (await readIndex()).filter((s) => s.id !== r.id);
    index.unshift(summaryOf(r));
    await writeAtomic(INDEX, JSON.stringify(index.slice(0, 500)));
  });
}

export async function getRecord(id: string): Promise<ScanRecord | null> {
  if (!validId(id)) return null;
  const live = memory.get(id);
  if (live) return live;
  try {
    return JSON.parse(await fs.readFile(path.join(SCAN_DIR, `${id}.json`), "utf8")) as ScanRecord;
  } catch {
    return null;
  }
}

/** Newest first. A scan still marked running after a restart did not finish: it is marked failed. */
export async function listSummaries(): Promise<ScanSummary[]> {
  const index = await serial(readIndex);
  const out: ScanSummary[] = [];
  for (const s of index) {
    const live = memory.get(s.id);
    if (live) out.push(summaryOf(live));
    else if (s.status === "running") out.push({ ...s, status: "failed", error: "Interrupted: the app restarted before this scan finished.", finishedAt: s.finishedAt ?? new Date().toISOString() });
    else out.push(s);
  }
  return out;
}

export async function deleteRecord(id: string): Promise<"deleted" | "running" | "missing"> {
  if (!validId(id)) return "missing";
  if (memory.has(id)) return "running";
  return serial(async () => {
    const index = await readIndex();
    const existed = index.some((s) => s.id === id);
    await writeAtomic(INDEX, JSON.stringify(index.filter((s) => s.id !== id)));
    await fs.rm(path.join(SCAN_DIR, `${id}.json`), { force: true });
    return existed ? "deleted" : "missing";
  });
}
