import "server-only";
import dns from "node:dns/promises";
import { fetchText, mapLimit } from "../net.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";

// Checks whether storage buckets named after the target exist on AWS S3, Google Cloud Storage and
// Azure Blob. The requests go to the cloud providers, not to the target. Only existence and listing
// access are reported: no object is downloaded, and listed names are capped.

const SUFFIXES = ["", "-dev", "-staging", "-stage", "-prod", "-production", "-test", "-backup", "-backups", "-assets", "-static", "-uploads", "-media", "-files", "-data", "-public", "-private", "-logs", "-cdn", "-images", "-web", "-app", "-api", "-old", "-archive"];
const PREFIXES = ["dev-", "staging-", "prod-", "backup-", "assets-", "static-", "media-"];
const MAX_NAMES = 60;
const KEYS_SHOWN = 20;

export type Provider = "AWS S3" | "Google Cloud Storage" | "Azure Blob";
export type BucketState = "listable" | "private" | "none" | "unknown";

export interface BucketHit {
  provider: Provider;
  name: string;
  state: BucketState;
  url: string;
  keys?: string[];
}

export interface BucketData {
  domain: string;
  names: number;
  checks: number;
  hits: BucketHit[];
}

const VALID = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

/** Bucket name guesses from the registrable domain and the full host name. */
export function bucketNames(host: string): string[] {
  const reg = registrableDomain(host).split(".")[0];
  const bases = [reg, host.replace(/\./g, "-"), reg.replace(/-/g, "")];
  const out = new Set<string>();
  for (const base of bases) for (const s of SUFFIXES) out.add(`${base}${s}`);
  for (const p of PREFIXES) out.add(`${p}${reg}`);
  return [...out].filter((n) => n.length >= 3 && n.length <= 63 && VALID.test(n)).slice(0, MAX_NAMES);
}

/** Azure account names: 3-24 lower-case letters and digits only. */
function azureName(name: string): string | null {
  const n = name.replace(/-/g, "");
  return /^[a-z0-9]{3,24}$/.test(n) ? n : null;
}

function keysOf(xml: string): string[] {
  return [...xml.matchAll(/<Key>([^<]{1,300})<\/Key>/g)].map((m) => m[1]).slice(0, KEYS_SHOWN);
}

async function checkS3(name: string): Promise<BucketHit> {
  const url = `https://${name}.s3.amazonaws.com/?max-keys=${KEYS_SHOWN}`;
  const { status, text } = await fetchText(url, 8000);
  if (status === 200 && text.includes("<ListBucketResult")) return { provider: "AWS S3", name, state: "listable", url, keys: keysOf(text) };
  if (status === 403) return { provider: "AWS S3", name, state: "private", url };
  if (status === 404) return { provider: "AWS S3", name, state: "none", url };
  return { provider: "AWS S3", name, state: "unknown", url };
}

async function checkGcs(name: string): Promise<BucketHit> {
  const url = `https://storage.googleapis.com/${name}?max-keys=${KEYS_SHOWN}`;
  const { status, text } = await fetchText(url, 8000);
  if (status === 200 && text.includes("<ListBucketResult")) return { provider: "Google Cloud Storage", name, state: "listable", url, keys: keysOf(text) };
  if (status === 403) return { provider: "Google Cloud Storage", name, state: "private", url };
  if (status === 404) return { provider: "Google Cloud Storage", name, state: "none", url };
  return { provider: "Google Cloud Storage", name, state: "unknown", url };
}

async function checkAzure(name: string): Promise<BucketHit | null> {
  const account = azureName(name);
  if (!account) return null;
  const host = `${account}.blob.core.windows.net`;
  const url = `https://${host}/?comp=list`;
  try {
    await dns.resolve4(host);
  } catch (e) {
    const code = (e as { code?: string }).code;
    return code === "ENOTFOUND" || code === "ENODATA" ? { provider: "Azure Blob", name: account, state: "none", url } : { provider: "Azure Blob", name: account, state: "unknown", url };
  }
  const { status, text } = await fetchText(url, 8000);
  if (status === 200 && text.includes("EnumerationResults")) return { provider: "Azure Blob", name: account, state: "listable", url, keys: [...text.matchAll(/<Name>([^<]{1,200})<\/Name>/g)].map((m) => m[1]).slice(0, KEYS_SHOWN) };
  return { provider: "Azure Blob", name: account, state: "private", url };
}

export async function runCloudBuckets(t: ParsedTarget): Promise<ModuleOutput<BucketData>> {
  const names = bucketNames(t.host);
  const tasks: ((name: string) => Promise<BucketHit | null>)[] = [checkS3, checkGcs, checkAzure];
  const jobs = names.flatMap((name) => tasks.map((fn) => ({ name, fn })));
  const warnings: string[] = [];

  const results = await mapLimit(jobs, 10, async (job) => {
    try {
      return await job.fn(job.name);
    } catch {
      return null;
    }
  });
  const failed = results.filter((r) => r === null).length;
  if (failed) warnings.push(`${failed} bucket check(s) could not be completed (network or provider error).`);

  const hits = results.filter((r): r is BucketHit => !!r && r.state !== "none" && r.state !== "unknown");
  const listable = hits.filter((h) => h.state === "listable");
  const privateHits = hits.filter((h) => h.state === "private");

  const findings: Finding[] = listable.map((h) => ({
    severity: "high",
    title: `Public bucket listing: ${h.name} (${h.provider})`,
    detail: "Anyone on the internet can list the files in this bucket without signing in. Listing shows file names, which often reveal backups, exports or internal paths.",
    evidence: [h.url, ...(h.keys ?? []).map((k) => `· ${k}`)].join("\n"),
    recommendation: "Turn off public listing and public read access on the bucket, and review the files it exposes.",
  }));
  if (privateHits.length) {
    findings.push({
      severity: "info",
      title: `${privateHits.length} bucket name(s) exist but are private`,
      detail: "These bucket names belong to the target's naming pattern. Access is denied, so their contents are not visible.",
      evidence: privateHits.map((h) => `${h.provider}: ${h.name}`).join("\n"),
    });
  }

  return {
    summary: `${listable.length} public listing(s) · ${privateHits.length} private bucket(s) · ${names.length} names checked`,
    findings,
    data: { domain: t.host, names: names.length, checks: jobs.length, hits },
    warnings,
  };
}
