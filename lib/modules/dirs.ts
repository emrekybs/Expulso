import { safeFetch, UserError, mapLimit, htmlTitle } from "../net.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";
import { buildWordlist, looksLikeAdmin } from "./wordlists.ts";

export interface DirHit {
  path: string;
  url: string;
  status: number;
  size: number;
  title: string;
  admin: boolean;
  redirect?: string;
}
export interface DirData {
  target: string;
  origin: string;
  tested: number;
  hits: DirHit[];
  admins: DirHit[];
  stats: { found: number; admin: number; s2: number; s3: number; s4: number; s5: number };
}

interface Baseline {
  status: number;
  len: number;
}

async function learnBaseline(origin: string): Promise<Baseline> {
  try {
    const r = await safeFetch(`${origin}/zzq${Math.random().toString(36).slice(2, 12)}/`, { timeoutMs: 8000, maxBytes: 80000, followRedirects: false });
    return { status: r.status, len: r.body.length };
  } catch {
    return { status: 404, len: 0 };
  }
}

export async function runDirs(
  t: ParsedTarget,
  opts: { wordlist?: "admin" | "common" | "all"; extensions?: string; recursion?: number },
): Promise<ModuleOutput<DirData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Directory & Admin Finder needs a domain or URL.");
  const origin = t.url ? new URL(t.url).origin : `https://${t.host}`;
  await safeFetch(origin + "/", { timeoutMs: 10000, maxBytes: 1000, followRedirects: true }).catch(() => {
    throw new UserError("The target did not respond on https. Check the domain or try an http:// URL.", "connect_failed");
  });

  const extensions = (opts.extensions ?? "").split(",").map((e) => e.trim()).filter(Boolean).slice(0, 8);
  const wordlist = buildWordlist(opts.wordlist ?? "common", extensions);
  const recursion = Math.max(0, Math.min(3, Math.floor(opts.recursion ?? 1)));
  const deadline = Date.now() + 50000;
  const warnings: string[] = [];

  const baseline = await learnBaseline(origin);
  const hits: DirHit[] = [];
  const seen = new Set<string>();
  let tested = 0;

  const scanDir = async (dir: string): Promise<string[]> => {
    const newDirs: string[] = [];
    const paths = wordlist.map((p) => (dir === "/" ? p : dir.replace(/\/$/, "") + p));
    await mapLimit(paths, 18, async (path) => {
      if (Date.now() > deadline || seen.has(path)) return;
      seen.add(path);
      tested++;
      try {
        const r = await safeFetch(origin + path, { timeoutMs: 7000, maxBytes: 120000, followRedirects: false });
        const soft = r.status === baseline.status && Math.abs(r.body.length - baseline.len) < 48;
        if (soft || r.status === 404) return;
        if (r.status >= 500 && r.status !== 500) return;
        const title = htmlTitle(r.body);
        const admin = looksLikeAdmin(path, title, r.body);
        const redirect = r.status >= 300 && r.status < 400 ? r.headers.get("location") ?? undefined : undefined;
        hits.push({ path, url: origin + path, status: r.status, size: Number(r.headers.get("content-length")) || r.body.length, title, admin, redirect });
        if (recursion > 0 && (r.status === 200 || r.status === 403) && !path.includes(".") && !redirect) newDirs.push(path.endsWith("/") ? path : path + "/");
      } catch {
        /* skip */
      }
    });
    return newDirs;
  };

  let frontier = ["/"];
  for (let depth = 0; depth <= recursion && frontier.length && Date.now() < deadline; depth++) {
    const next: string[] = [];
    for (const dir of frontier.slice(0, 8)) {
      if (Date.now() > deadline) break;
      next.push(...(await scanDir(dir)));
    }
    frontier = [...new Set(next)].filter((d) => !/\b(logout|signout)\b/i.test(d));
  }
  if (Date.now() >= deadline) warnings.push("Stopped early at the time limit; results may be partial.");

  hits.sort((a, b) => Number(b.admin) - Number(a.admin) || a.path.localeCompare(b.path));
  const admins = hits.filter((h) => h.admin);
  const stats = {
    found: hits.length,
    admin: admins.length,
    s2: hits.filter((h) => h.status >= 200 && h.status < 300).length,
    s3: hits.filter((h) => h.status >= 300 && h.status < 400).length,
    s4: hits.filter((h) => h.status >= 400 && h.status < 500).length,
    s5: hits.filter((h) => h.status >= 500).length,
  };
  const findings: Finding[] = [];
  if (admins.length)
    findings.push({
      severity: "info",
      title: `${admins.length} login / admin panel(s) found`,
      detail: "Administrative interfaces exposed to the internet are a common target for credential attacks.",
      evidence: admins.slice(0, 10).map((a) => `${a.status} ${a.url}`).join("\n"),
      recommendation: "Restrict access to admin panels by IP or VPN and enforce strong authentication.",
    });
  const risky = hits.filter((h) => /\.(sql|bak|old|zip|tar\.gz|tgz|env|git|save)$|\/backup|\/\.git/i.test(h.path) && h.status === 200);
  if (risky.length)
    findings.push({
      severity: "high",
      title: `${risky.length} sensitive file(s) accessible`,
      detail: "Backup, database or source files returned 200 OK and may contain credentials or source code.",
      evidence: risky.slice(0, 8).map((a) => a.url).join("\n"),
      recommendation: "Remove these files from the web root and block access.",
    });

  const data: DirData = { target: t.input, origin, tested, hits, admins, stats };
  return { summary: `${tested} paths tested · ${stats.found} found · ${stats.admin} admin`, findings, data, warnings };
}
