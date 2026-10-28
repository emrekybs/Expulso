import "server-only";
import { getModule, type ModuleId } from "./modules-config.ts";
import { parseTarget, type ParsedTarget } from "./target.ts";
import { UserError } from "./net.ts";
import type { ModuleOutput } from "./types.ts";

import { runSubdomains } from "./modules/subdomains.ts";
import { runDns } from "./modules/dns.ts";
import { runWhois } from "./modules/whois.ts";
import { runCt } from "./modules/ct.ts";
import { runReverseDns, runReverseIp, runGeoip } from "./modules/network.ts";
import { runCloud } from "./modules/cloud.ts";
import { runRelated } from "./modules/related.ts";
import { runTyposquatting } from "./modules/typosquatting.ts";
import { runDorks } from "./modules/dorks.ts";
import { runOsint } from "./modules/osint.ts";
import { runEmails } from "./modules/emails.ts";
import { runHttp } from "./modules/http.ts";
import { runWaf } from "./modules/waf.ts";
import { runJs } from "./modules/js.ts";
import { runDirs } from "./modules/dirs.ts";
import { runExposure } from "./modules/exposure.ts";
import { runOrigin } from "./modules/origin.ts";

type Opts = Record<string, unknown>;

const RUNNERS: Record<ModuleId, (t: ParsedTarget, o: Opts) => Promise<ModuleOutput>> = {
  subdomains: (t, o) => runSubdomains(t, { resolve: o.resolve !== false, httpStatus: o.httpStatus === true }),
  dns: (t) => runDns(t),
  whois: (t) => runWhois(t),
  ct: (t) => runCt(t),
  "reverse-dns": (t) => runReverseDns(t),
  "reverse-ip": (t) => runReverseIp(t),
  geoip: (t) => runGeoip(t),
  cloud: (t) => runCloud(t),
  related: (t) => runRelated(t),
  typosquatting: (t) => runTyposquatting(t),
  dorks: (t) => runDorks(t),
  osint: (t, o) => runOsint(t, { crawl: Number(o.crawl) || 10, nonStrict: o.nonStrict === true, keywords: String(o.keywords ?? "") }),
  emails: (t) => runEmails(t),
  http: (t) => runHttp(t),
  waf: (t) => runWaf(t),
  js: (t, o) => runJs(t, { maxPages: Number(o.maxPages) || 25, thirdParty: o.thirdParty === true }),
  dirs: (t, o) => runDirs(t, { wordlist: (o.wordlist as "admin" | "common" | "all") || "common", extensions: String(o.extensions ?? ""), recursion: Number(o.recursion) || 0 }),
  exposure: (t) => runExposure(t),
  origin: (t) => runOrigin(t),
};

export interface RunResult {
  ok: boolean;
  result?: ModuleOutput;
  error?: string;
  code?: string;
  skipped?: boolean;
  durationMs: number;
}

/** Runs one module against one already-parsed target. Never throws. */
export async function runModule(moduleId: string, parsed: ParsedTarget, options: Opts = {}): Promise<RunResult> {
  const started = Date.now();
  const def = getModule(moduleId);
  if (!def) return { ok: false, error: "Unknown module.", code: "unknown_module", durationMs: 0 };
  if (!def.accepts.includes(parsed.kind)) {
    return { ok: false, skipped: true, error: `${def.title} does not accept a ${parsed.kind} target.`, code: "not_applicable", durationMs: 0 };
  }
  try {
    const result = await RUNNERS[def.id](parsed, options);
    return { ok: true, result, durationMs: Date.now() - started };
  } catch (e) {
    const isUser = e instanceof UserError;
    if (!isUser) console.error(`[module:${def.id}] ${parsed.host}`, e);
    return {
      ok: false,
      error: isUser ? e.message : "An unexpected error occurred. Check the logs.",
      code: isUser ? e.code : "internal_error",
      durationMs: Date.now() - started,
    };
  }
}

export function parseOrError(target: string): ParsedTarget | { error: string } {
  return parseTarget(target);
}
