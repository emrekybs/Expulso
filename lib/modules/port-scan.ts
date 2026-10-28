import "server-only";
import net from "node:net";
import dns from "node:dns/promises";
import { UserError, isPrivateIp, mapLimit } from "../net.ts";
import { runTool, toolPath } from "../tools.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput, Severity } from "../types.ts";

// TCP connect scan built into B24-engine: no nmap or naabu needed. A port counts as open only when
// the TCP handshake completes. It does not identify filtered ports or perform SYN or OS detection.

const COMMON = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157];
const WEB = [80, 81, 443, 591, 2082, 2083, 2086, 2087, 3000, 4443, 5000, 5001, 7001, 7443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9001, 9090, 10443];

export const PRESET_LABEL: Record<string, string> = {
  common: "Common ports (about 100)",
  web: "Web ports (about 25)",
  full: "All ports (1-65535)",
  custom: "Custom list",
};

const SPEED: Record<string, { concurrency: number; timeout: number; label: string }> = {
  careful: { concurrency: 50, timeout: 3000, label: "Careful" },
  normal: { concurrency: 200, timeout: 1500, label: "Normal" },
  fast: { concurrency: 500, timeout: 1000, label: "Fast" },
};

const SERVICE: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
  143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
  1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "http-dev", 3306: "mysql", 3389: "rdp", 5000: "http-dev",
  5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5985: "winrm", 6379: "redis", 8000: "http-alt", 8008: "http-alt",
  8080: "http-alt", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9042: "cassandra", 9090: "http-alt",
  9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
};

// Ports that are normally TLS: a plain banner read would be meaningless, so they are only labelled.
const TLS_PORTS = new Set([443, 465, 563, 636, 853, 993, 995, 4443, 7443, 8443, 9443, 10443]);
// Ports where a plain HTTP HEAD request gets a useful answer.
const HTTP_PORTS = new Set([80, 81, 591, 2082, 2086, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090]);

const RISK: Record<number, { severity: Severity; why: string }> = {
  23: { severity: "high", why: "Telnet sends logins and passwords in clear text" },
  2375: { severity: "high", why: "The Docker API without TLS can give full control of the host" },
  6379: { severity: "high", why: "Redis is often exposed without a password" },
  9200: { severity: "high", why: "The Elasticsearch HTTP API is often open without authentication" },
  27017: { severity: "high", why: "MongoDB is often exposed without authentication" },
  11211: { severity: "high", why: "Memcached has no authentication" },
  3389: { severity: "medium", why: "Remote Desktop is reachable from the internet" },
  5900: { severity: "medium", why: "VNC remote desktop is reachable from the internet" },
  445: { severity: "medium", why: "SMB file sharing is reachable from the internet" },
  139: { severity: "medium", why: "NetBIOS is reachable from the internet" },
  1433: { severity: "medium", why: "A SQL Server database port is reachable from the internet" },
  3306: { severity: "medium", why: "A MySQL database port is reachable from the internet" },
  5432: { severity: "medium", why: "A PostgreSQL database port is reachable from the internet" },
  1521: { severity: "medium", why: "An Oracle database port is reachable from the internet" },
  2049: { severity: "medium", why: "An NFS share may be reachable from the internet" },
  5985: { severity: "medium", why: "WinRM management is reachable from the internet" },
  21: { severity: "low", why: "FTP can carry logins in clear text" },
};

const MAX_IPS = 4;
// Keeps one module well under the 300 s cap in module runner. Ports not reached before the budget ends are reported as skipped.
const BUDGET_MS = 200_000;

export interface PortScanOptions {
  preset: string;
  customPorts: string;
  speed: string;
  banners: boolean;
  /** Runs nmap -sV on the open ports when nmap is installed. */
  nmap?: boolean;
}

export interface OpenPort {
  port: number;
  service: string;
  banner: string;
  tls: boolean;
}

export interface PortScanData {
  preset: string;
  portCount: number;
  skipped: number;
  nmap: "used" | "not installed" | "off";
  hosts: { ip: string; open: OpenPort[] }[];
}

export interface NmapService {
  port: number;
  service: string;
  version: string;
}

/**
 * Parses nmap greppable output (-oG): "Host: 1.2.3.4 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9/, 80/open/tcp//http//nginx/".
 * Only open ports are returned.
 */
export function parseNmapGreppable(lines: string[]): NmapService[] {
  const out: NmapService[] = [];
  for (const line of lines) {
    const idx = line.indexOf("Ports:");
    if (idx < 0) continue;
    for (const entry of line.slice(idx + 6).split(/,\s*/)) {
      const m = entry.trim().match(/^(\d+)\/open\/\w+\/\/([^/]*)\/\/([^/]*)\//);
      if (m) out.push({ port: Number(m[1]), service: m[2] || "unknown", version: m[3].trim() });
    }
  }
  return out;
}

/** Parses "80, 443, 8000-8100". Returns the sorted unique ports or a message for the user. */
export function parsePorts(spec: string): { ports: number[] } | { error: string } {
  const out = new Set<number>();
  for (const token of spec.split(/[\s,]+/).filter(Boolean)) {
    const range = token.match(/^(\d{1,5})-(\d{1,5})$/);
    if (range) {
      const a = Number(range[1]);
      const b = Number(range[2]);
      if (a < 1 || b > 65535 || a > b) return { error: `"${token}" is not a valid port range.` };
      for (let p = a; p <= b; p++) out.add(p);
    } else if (/^\d{1,5}$/.test(token)) {
      const p = Number(token);
      if (p < 1 || p > 65535) return { error: `Port ${token} is outside 1-65535.` };
      out.add(p);
    } else {
      return { error: `"${token}" is not a port or a range like 8000-8100.` };
    }
  }
  if (!out.size) return { error: "Enter at least one port." };
  return { ports: [...out].sort((x, y) => x - y) };
}

export function portsForPreset(o: PortScanOptions): number[] {
  if (o.preset === "full") return Array.from({ length: 65535 }, (_, i) => i + 1);
  if (o.preset === "web") return WEB;
  if (o.preset === "custom") {
    const parsed = parsePorts(o.customPorts || "");
    if ("error" in parsed) throw new UserError(parsed.error, "bad_ports");
    return parsed.ports;
  }
  return COMMON;
}

export function probe(ip: string, port: number, timeout: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: ip, port });
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeout, () => done(false));
    socket.once("connect", () => done(true));
    // A permanent listener: a reset that arrives after destroy() must not become an uncaught error.
    socket.on("error", () => done(false));
  });
}

function cleanBanner(raw: string): string {
  return raw
    .replace(/[^\x20-\x7e\r\n]/g, " ")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, 3)
    .join(" | ")
    .slice(0, 200);
}

/** Reads what the service says first. HTTP ports get a HEAD request so the Server header is visible. */
export function grabBanner(ip: string, port: number, timeout: number): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: ip, port });
    let buf = "";
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const done = () => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.destroy();
      resolve(cleanBanner(buf));
    };
    timer = setTimeout(done, timeout);
    socket.once("connect", () => {
      if (HTTP_PORTS.has(port)) socket.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\nUser-Agent: B24-engine\r\n\r\n`);
    });
    socket.on("data", (d: Buffer) => {
      buf += d.toString("latin1");
      if (buf.length > 1024) done();
    });
    socket.on("error", done);
    socket.once("close", done);
  });
}

async function resolveIps(t: ParsedTarget): Promise<string[]> {
  if (t.kind === "ip") return [t.host];
  try {
    return [...new Set(await dns.resolve4(t.host))];
  } catch {
    throw new UserError(`${t.host} has no IPv4 address to scan.`, "no_address");
  }
}

async function nmapServices(ip: string, ports: number[]): Promise<NmapService[] | null> {
  if (!(await toolPath("nmap"))) return null;
  const r = await runTool("nmap", ["-sV", "--version-light", "-Pn", "-n", "-p", ports.join(","), "-oG", "-", ip], 240_000);
  return r.ok ? parseNmapGreppable(r.lines) : [];
}

export async function runPortScan(t: ParsedTarget, o: PortScanOptions): Promise<ModuleOutput<PortScanData>> {
  const ports = portsForPreset(o);
  const speed = SPEED[o.speed] ?? SPEED.normal;
  const warnings: string[] = [];
  const started = Date.now();
  const deadline = started + BUDGET_MS;

  const ips = await resolveIps(t);
  const publicIps = ips.filter((ip) => !isPrivateIp(ip));
  if (!publicIps.length) throw new UserError("Private, loopback and link-local addresses are not scanned.", "private_address");
  if (publicIps.length < ips.length) warnings.push(`Skipped ${ips.length - publicIps.length} private address(es).`);
  if (publicIps.length > MAX_IPS) warnings.push(`Scanning the first ${MAX_IPS} of ${publicIps.length} addresses.`);

  let skipped = 0;
  let nmapState: PortScanData["nmap"] = "off";
  const hosts: PortScanData["hosts"] = [];
  for (const ip of publicIps.slice(0, MAX_IPS)) {
    const openPorts: number[] = [];
    await mapLimit(ports, speed.concurrency, async (port) => {
      if (Date.now() > deadline) {
        skipped++;
        return;
      }
      if (await probe(ip, port, speed.timeout)) openPorts.push(port);
    });
    openPorts.sort((a, b) => a - b);

    let detail: NmapService[] | null = null;
    if (o.nmap && openPorts.length) {
      detail = await nmapServices(ip, openPorts);
      nmapState = detail === null ? "not installed" : "used";
    }
    const byPort = new Map((detail ?? []).map((d) => [d.port, d]));

    const open: OpenPort[] = await mapLimit(openPorts, 20, async (port) => {
      const tls = TLS_PORTS.has(port);
      const n = byPort.get(port);
      const banner = o.banners && !tls && Date.now() < deadline + 30_000 ? await grabBanner(ip, port, 2000) : "";
      const version = n?.version ? ` ${n.version}` : "";
      return { port, service: n?.service ?? SERVICE[port] ?? "unknown", banner: banner || (version ? version.trim() : ""), tls };
    });
    hosts.push({ ip, open });
  }
  if (nmapState === "not installed") warnings.push("nmap is not installed, so service names come from the built-in table. Install it on the Tools page for version detection.");
  if (skipped) warnings.push(`Time budget reached: ${skipped} port(s) were not probed. Use a smaller port list or the fast speed.`);

  const findings: Finding[] = [];
  for (const h of hosts) {
    if (h.open.length) {
      findings.push({
        severity: "info",
        title: `${h.open.length} open port(s) on ${h.ip}`,
        detail: "Ports that accepted a TCP connection from this machine.",
        evidence: h.open.map((p) => `${p.port}/${p.service}${p.banner ? ` — ${p.banner}` : ""}`).join("\n"),
      });
    }
    for (const p of h.open) {
      const risk = RISK[p.port];
      if (!risk) continue;
      findings.push({
        severity: risk.severity,
        title: `Port ${p.port} (${p.service}) is open on ${h.ip}`,
        detail: `${risk.why}. The port answered a TCP connection during this scan.`,
        recommendation: "Close the port at the firewall, or allow it only from known addresses.",
      });
    }
  }

  const total = hosts.reduce((n, h) => n + h.open.length, 0);
  return {
    summary: `${total} open port(s) on ${hosts.length} address(es) · ${PRESET_LABEL[o.preset] ?? o.preset} · ${speed.label.toLowerCase()} speed`,
    findings,
    data: { preset: o.preset, portCount: ports.length, skipped, nmap: nmapState, hosts },
    warnings,
  };
}
