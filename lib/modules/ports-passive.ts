import { fetchWithTimeout, mapLimit, UserError } from "../net.ts";
import { resolveA4 } from "../dns-core.ts";
import { expandCidr, type ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, Severity } from "../types.ts";

/**
 * Passive service data from Shodan InternetDB (keyless). It is a cached index built from
 * earlier internet-wide scans: NO packets are sent to the target by this module.
 */
export interface InternetDbRecord {
  ip: string;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  tags: string[];
  vulns: string[];
}

export interface HostPorts {
  ip: string;
  found: boolean;
  ports: { port: number; label: string; risk: Severity | null }[];
  hostnames: string[];
  cpes: string[];
  tags: string[];
  cves: string[];
}

export interface PortsData {
  target: string;
  hosts: HostPorts[];
  totalPorts: number;
  totalCves: number;
}

const PORT_RISK: Record<number, { label: string; risk: Severity }> = {
  21: { label: "FTP", risk: "medium" },
  22: { label: "SSH", risk: "low" },
  23: { label: "Telnet", risk: "high" },
  25: { label: "SMTP", risk: "low" },
  53: { label: "DNS", risk: "low" },
  80: { label: "HTTP", risk: "low" },
  110: { label: "POP3", risk: "medium" },
  143: { label: "IMAP", risk: "medium" },
  443: { label: "HTTPS", risk: "low" },
  445: { label: "SMB", risk: "high" },
  1433: { label: "MSSQL", risk: "high" },
  1521: { label: "Oracle DB", risk: "high" },
  2049: { label: "NFS", risk: "high" },
  2375: { label: "Docker API (unencrypted)", risk: "high" },
  3306: { label: "MySQL", risk: "high" },
  3389: { label: "RDP", risk: "high" },
  5432: { label: "PostgreSQL", risk: "high" },
  5601: { label: "Kibana", risk: "medium" },
  5900: { label: "VNC", risk: "high" },
  6379: { label: "Redis", risk: "high" },
  9200: { label: "Elasticsearch", risk: "high" },
  11211: { label: "Memcached", risk: "high" },
  27017: { label: "MongoDB", risk: "high" },
  8080: { label: "HTTP (alternate)", risk: "low" },
  8443: { label: "HTTPS (alternate)", risk: "low" },
};

/** Pure parser: turns one InternetDB JSON document into a host summary. */
export function analyzeInternetDb(rec: InternetDbRecord | null, ip: string): HostPorts {
  if (!rec) return { ip, found: false, ports: [], hostnames: [], cpes: [], tags: [], cves: [] };
  const ports = [...new Set(rec.ports ?? [])].sort((a, b) => a - b).map((port) => {
    const p = PORT_RISK[port];
    return { port, label: p?.label ?? "unknown", risk: p?.risk ?? null };
  });
  return {
    ip,
    found: true,
    ports,
    hostnames: rec.hostnames ?? [],
    cpes: rec.cpes ?? [],
    tags: rec.tags ?? [],
    cves: [...new Set(rec.vulns ?? [])].sort(),
  };
}

async function fetchRecord(ip: string): Promise<InternetDbRecord | null> {
  const res = await fetchWithTimeout(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { headers: { "user-agent": "ReconPanel/1.0" } }, 10000);
  if (res.status === 404) return null; // "No information available" = no record for this IP
  if (!res.ok) throw new UserError(`InternetDB returned HTTP ${res.status}.`, "upstream_error");
  return (await res.json()) as InternetDbRecord;
}

export async function runPortsPassive(t: ParsedTarget): Promise<ModuleOutput<PortsData>> {
  let ips: string[];
  if (t.kind === "cidr") ips = expandCidr(t.host).slice(0, 32);
  else if (t.kind === "ip" || /^[\d.]+$/.test(t.host)) ips = [t.host];
  else {
    ips = (await resolveA4(t.host)).slice(0, 8);
    if (!ips.length) throw new UserError(`No A record found for ${t.host}.`);
  }
  const warnings: string[] = [];
  const hosts = await mapLimit(ips, 6, async (ip): Promise<HostPorts> => {
    try {
      return analyzeInternetDb(await fetchRecord(ip), ip);
    } catch (e) {
      warnings.push(`${ip}: ${e instanceof UserError ? e.message : "lookup failed"}`);
      return { ip, found: false, ports: [], hostnames: [], cpes: [], tags: [], cves: [] };
    }
  });

  const findings: Finding[] = [];
  for (const h of hosts) {
    const risky = h.ports.filter((p) => p.risk === "high" || p.risk === "medium");
    if (risky.length) {
      findings.push({
        severity: risky.some((p) => p.risk === "high") ? "high" : "medium",
        title: `Sensitive services listed for ${h.ip}: ${risky.map((p) => `${p.label} (${p.port})`).join(", ")}`,
        detail: "Passive index data shows these services as exposed on this address. Databases, remote administration and file-sharing services should not be reachable from the internet. The data may be a few weeks old.",
        evidence: `${h.ip}: ${h.ports.map((p) => p.port).join(", ")}`,
        recommendation: "Confirm the service is still exposed. Restrict it with a firewall or VPN, and require strong authentication.",
      });
    }
    if (h.cves.length) {
      findings.push({
        severity: "medium",
        title: `${h.cves.length} CVE(s) associated with ${h.ip} in passive data`,
        detail: "InternetDB associates these CVE identifiers with the services seen on this address. The association is based on banner and version data, so verify before acting on it.",
        evidence: h.cves.slice(0, 15).join(", "),
        recommendation: "Check each CVE against the installed software version and patch the affected components.",
      });
    }
  }

  const totalPorts = hosts.reduce((s, h) => s + h.ports.length, 0);
  const totalCves = hosts.reduce((s, h) => s + h.cves.length, 0);
  const found = hosts.filter((h) => h.found).length;
  return {
    summary: found ? `${totalPorts} open port(s) · ${totalCves} CVE(s) across ${found} IP(s) (passive data)` : "No passive service data for these IPs",
    findings,
    data: { target: t.input, hosts, totalPorts, totalCves },
    warnings: warnings.length ? [...warnings, "Passive data is a cached index, not a live scan."] : ["Passive data is a cached index, not a live scan."],
  };
}
