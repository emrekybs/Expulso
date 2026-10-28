import { fetchJson, UserError } from "../net.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import { formatDate } from "../geo-core.ts";
import type { ModuleOutput } from "../types.ts";

export interface CtCert {
  id: number;
  issuer: string;
  commonName: string;
  nameCount: number;
  notBefore: string;
  notAfter: string;
  wildcard: boolean;
}
export interface CtData {
  domain: string;
  total: number;
  certs: CtCert[];
  issuers: { name: string; count: number }[];
  sans: string[];
}

interface CrtRow {
  id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
}

export async function runCt(t: ParsedTarget): Promise<ModuleOutput<CtData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Certificate Transparency needs a domain.");
  const domain = registrableDomain(t.host);
  const rows = await fetchJson<CrtRow[]>(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, 30000);
  if (!Array.isArray(rows) || !rows.length) return { summary: "No certificates found", findings: [], data: { domain, total: 0, certs: [], issuers: [], sans: [] } };

  const sans = new Set<string>();
  const issuerCount = new Map<string, number>();
  const certs: CtCert[] = [];
  const seen = new Set<number>();
  for (const r of rows) {
    r.name_value?.split(/\s+/).forEach((n) => {
      const h = n.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (h && (h === domain || h.endsWith(`.${domain}`))) sans.add(h);
    });
    const issuer = (r.issuer_name?.match(/O\s*=\s*"?([^",]+)/)?.[1] ?? r.issuer_name ?? "Unknown").trim();
    issuerCount.set(issuer, (issuerCount.get(issuer) ?? 0) + 1);
    if (!seen.has(r.id)) {
      seen.add(r.id);
      certs.push({
        id: r.id,
        issuer,
        commonName: r.common_name,
        nameCount: new Set(r.name_value?.split(/\s+/)).size,
        notBefore: r.not_before,
        notAfter: r.not_after,
        wildcard: /(^|\s)\*\./.test(r.name_value ?? ""),
      });
    }
  }
  certs.sort((a, b) => new Date(b.notBefore).getTime() - new Date(a.notBefore).getTime());
  const issuers = [...issuerCount].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  const latest = certs[0];
  return {
    summary: `${certs.length} certificates · ${issuers.length} issuers · ${sans.size} names${latest ? ` · latest ${formatDate(latest.notBefore)}` : ""}`,
    findings: [],
    data: { domain, total: certs.length, certs: certs.slice(0, 200), issuers, sans: [...sans].sort() },
  };
}
