import { fetchJson, UserError } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { doh, resolveA4 } from "../dns-core.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import type { ModuleOutput } from "../types.ts";

export interface RelatedDomain {
  domain: string;
  links: string[]; // e.g. "shared IP 1.2.3.4", "same name server", "same certificate"
}
export interface RelatedData {
  domain: string;
  related: RelatedDomain[];
}

function add(map: Map<string, Set<string>>, domain: string, link: string, base: string) {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!d || d === base || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)) return;
  if (registrableDomain(d) === base) return; // same registrable domain, not "related"
  const set = map.get(d) ?? new Set<string>();
  set.add(link);
  map.set(d, set);
}

export async function runRelated(t: ParsedTarget): Promise<ModuleOutput<RelatedData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Related Domains needs a domain.");
  const base = registrableDomain(t.host);
  const map = new Map<string, Set<string>>();
  const warnings: string[] = [];

  // 1) Shared IP: resolve the domain, reverse-IP each address.
  const ips = (await resolveA4(base).catch(() => [])).slice(0, 3);
  for (const ip of ips) {
    const text = await htQuery("reverseiplookup", ip, 18000).catch((e) => {
      warnings.push(`Reverse IP for ${ip}: ${e instanceof UserError ? e.message : "failed"}`);
      return "";
    });
    text.split("\n").map((l) => l.trim()).filter(Boolean).forEach((d) => add(map, d, `shared IP ${ip}`, base));
  }

  // 2) Same name servers: find other domains served by the same NS (RapidDNS).
  const ns = (await doh(base, "NS").catch(() => null))?.records.map((r) => r.value.toLowerCase()) ?? [];
  // (Public sources for NS->domains are limited without keys; we record NS for context.)

  // 3) Shared certificate names already surface as SANs, which crt.sh groups by org;
  //    we pull other domains that share the exact organisationName is not keyless-reliable,
  //    so we skip to avoid noise.

  const related = [...map.entries()].map(([domain, links]) => ({ domain, links: [...links] })).sort((a, b) => b.links.length - a.links.length || a.domain.localeCompare(b.domain));
  const findings = ns.length ? [] : [];
  return {
    summary: `${related.length} related domain(s)`,
    findings,
    data: { domain: base, related: related.slice(0, 500) },
    warnings: [...warnings, ...(ns.length ? [`Name servers: ${ns.join(", ")}`] : [])],
  };
}

void fetchJson;
