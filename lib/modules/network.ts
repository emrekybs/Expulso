import { mapLimit, UserError } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { ptr, resolveA } from "./dns.ts";
import type { ParsedTarget } from "../target.ts";

/* ----------------------------- Ters DNS ----------------------------- */

export interface ReverseDnsResult {
  target: string;
  entries: { ip: string; hostnames: string[] }[];
}

export function parseHtReverseDns(text: string): ReverseDnsResult["entries"] {
  const map = new Map<string, string[]>();
  for (const line of text.split("\n")) {
    const [ip, host] = line.trim().split(/\s+/);
    if (!ip || !host) continue;
    const list = map.get(ip) ?? [];
    if (!list.includes(host)) list.push(host.replace(/\.$/, ""));
    map.set(ip, list);
  }
  return [...map].map(([ip, hostnames]) => ({ ip, hostnames }));
}

export async function runReverseDns(t: ParsedTarget): Promise<ReverseDnsResult> {
  if (t.kind === "cidr") {
    const text = await htQuery("reversedns", t.host);
    return { target: t.host, entries: parseHtReverseDns(text) };
  }
  const ips = t.kind === "ip" ? [t.host] : (await resolveA(t.host)).slice(0, 10);
  if (!ips.length) throw new UserError(`"${t.host}" için IP adresi bulunamadı.`);
  const entries = await mapLimit(ips, 5, async (ip) => ({ ip, hostnames: await ptr(ip).catch(() => []) }));
  return { target: t.host, entries };
}

/* ----------------------------- Ters IP ----------------------------- */

export interface ReverseIpResult {
  target: string;
  domains: string[];
  limited: boolean;
}

export async function runReverseIp(t: ParsedTarget): Promise<ReverseIpResult> {
  if (t.kind === "cidr") throw new UserError("Ters IP araması için tek bir IP veya alan adı girin.");
  const text = await htQuery("reverseiplookup", t.host);
  const domains = [...new Set(text.split("\n").map((l) => l.trim().toLowerCase()).filter((l) => l && !/\s/.test(l)))].sort();
  // Ücretsiz katman en fazla 500 sonuç döndürür
  return { target: t.host, domains, limited: domains.length >= 500 };
}

/* ----------------------------- Port tarama ----------------------------- */

export type PortState = "open" | "closed" | "filtered" | "open|filtered" | "unfiltered" | "closed|filtered";

export interface PortEntry {
  port: number;
  protocol: string;
  state: PortState;
  service: string;
  version?: string;
  risk: "yüksek" | "orta" | "düşük" | "bilgi";
  note: string;
}

export interface PortScanResult {
  target: string;
  ip?: string;
  hostUp: boolean;
  latency?: string;
  rdns?: string;
  otherAddresses?: string;
  ports: PortEntry[];
  duration?: string;
  scannedAt?: string;
}

export const STATE_TR: Record<string, string> = {
  open: "Açık",
  closed: "Kapalı",
  filtered: "Filtreli",
  "open|filtered": "Açık veya filtreli",
  "closed|filtered": "Kapalı veya filtreli",
  unfiltered: "Filtresiz",
};

const PORT_INFO: Record<number, { name: string; risk: PortEntry["risk"]; note: string }> = {
  21: { name: "FTP", risk: "orta", note: "Kimlik bilgileri şifrelenmeden iletilir; anonim erişim kontrol edilmeli." },
  22: { name: "SSH", risk: "düşük", note: "Uzaktan yönetim. Parola yerine anahtar tabanlı kimlik doğrulama önerilir." },
  23: { name: "Telnet", risk: "yüksek", note: "Şifrelenmemiş uzaktan erişim; internete açık olmamalı." },
  25: { name: "SMTP", risk: "düşük", note: "E-posta sunucusu. Açık röle (open relay) yapılandırması kontrol edilmeli." },
  53: { name: "DNS", risk: "düşük", note: "Açık çözümleyici ise DNS amplifikasyonunda kötüye kullanılabilir." },
  80: { name: "HTTP", risk: "bilgi", note: "Şifrelenmemiş web trafiği; HTTPS'e yönlendirme önerilir." },
  110: { name: "POP3", risk: "orta", note: "Şifrelenmemiş e-posta erişimi." },
  111: { name: "RPCbind", risk: "orta", note: "Servis bilgisi sızdırabilir; dışarıya kapalı olmalı." },
  135: { name: "MS-RPC", risk: "yüksek", note: "Windows RPC; internete açık olmamalı." },
  139: { name: "NetBIOS", risk: "yüksek", note: "Dosya paylaşımı; internete açık olmamalı." },
  143: { name: "IMAP", risk: "orta", note: "Şifrelenmemiş e-posta erişimi; IMAPS (993) tercih edilmeli." },
  443: { name: "HTTPS", risk: "bilgi", note: "Şifreli web trafiği." },
  445: { name: "SMB", risk: "yüksek", note: "Fidye yazılımlarının sık hedefi (ör. EternalBlue); internete açık olmamalı." },
  1433: { name: "MSSQL", risk: "yüksek", note: "Veritabanı servisi internete açık olmamalı." },
  1521: { name: "Oracle DB", risk: "yüksek", note: "Veritabanı servisi internete açık olmamalı." },
  2049: { name: "NFS", risk: "yüksek", note: "Ağ dosya sistemi; internete açık olmamalı." },
  3306: { name: "MySQL", risk: "yüksek", note: "Veritabanı servisi internete açık olmamalı." },
  3389: { name: "RDP", risk: "yüksek", note: "Uzak masaüstü; kaba kuvvet ve fidye yazılımı saldırılarının sık hedefi." },
  5432: { name: "PostgreSQL", risk: "yüksek", note: "Veritabanı servisi internete açık olmamalı." },
  5900: { name: "VNC", risk: "yüksek", note: "Uzak masaüstü; zayıf kimlik doğrulama riski." },
  6379: { name: "Redis", risk: "yüksek", note: "Varsayılan olarak kimlik doğrulamasız; internete açık olmamalı." },
  8080: { name: "HTTP-Alt", risk: "düşük", note: "Alternatif web / yönetim paneli olabilir." },
  8443: { name: "HTTPS-Alt", risk: "düşük", note: "Alternatif HTTPS / yönetim paneli olabilir." },
  9200: { name: "Elasticsearch", risk: "yüksek", note: "Kimlik doğrulamasız veri sızıntılarının sık kaynağı." },
  11211: { name: "Memcached", risk: "yüksek", note: "Amplifikasyon saldırılarında kötüye kullanılabilir." },
  27017: { name: "MongoDB", risk: "yüksek", note: "Kimlik doğrulamasız veri sızıntılarının sık kaynağı." },
};

export function parseNmap(target: string, text: string): PortScanResult {
  const res: PortScanResult = { target, hostUp: !/Host seems down|0 hosts up/i.test(text), ports: [] };
  for (const line of text.split("\n")) {
    let m: RegExpMatchArray | null;
    if ((m = line.match(/^Starting Nmap .* at (.+)$/))) res.scannedAt = m[1].trim();
    else if ((m = line.match(/^Nmap scan report for (\S+)(?: \(([^)]+)\))?/))) {
      res.ip = m[2] ?? m[1];
    } else if ((m = line.match(/^Host is up(?: \(([\d.]+s) latency\))?/))) {
      res.hostUp = true;
      res.latency = m[1];
    } else if ((m = line.match(/^rDNS record for [^:]+:\s*(\S+)/))) res.rdns = m[1];
    else if ((m = line.match(/^Other addresses for \S+ \(not scanned\):\s*(.+)$/))) res.otherAddresses = m[1];
    else if ((m = line.match(/^Nmap done: .* in ([\d.]+) seconds/))) res.duration = `${m[1]} sn`;
    else if ((m = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.+))?$/))) {
      const port = Number(m[1]);
      const info = PORT_INFO[port];
      const state = m[3] as PortState;
      const open = state === "open";
      res.ports.push({
        port,
        protocol: m[2],
        state,
        service: m[4] === "unknown" && info ? info.name.toLowerCase() : m[4],
        version: m[5]?.trim(),
        risk: open ? (info?.risk ?? "orta") : "bilgi",
        note: open ? (info?.note ?? "Bilinmeyen servis; gerekliliği doğrulanmalı.") : state === "filtered" ? "Güvenlik duvarı tarafından filtreleniyor." : "Port kapalı.",
      });
    }
  }
  return res;
}

export async function runPortScan(t: ParsedTarget): Promise<PortScanResult> {
  if (t.kind === "cidr") throw new UserError("Port taraması için tek bir IP veya alan adı girin.");
  const text = await htQuery("nmap", t.host, 55000);
  if (!text) throw new UserError("Tarama sonucu alınamadı.");
  const r = parseNmap(t.host, text);
  if (!r.ports.length && !r.hostUp) throw new UserError("Hedef yanıt vermiyor (host kapalı veya ping'e yanıt vermiyor).");
  return r;
}

/* ----------------------------- Traceroute ----------------------------- */

export interface Hop {
  hop: number;
  host: string;
  loss: number;
  sent: number;
  last: number;
  avg: number;
  best: number;
  worst: number;
  stdev: number;
  timeout: boolean;
}

export interface TracerouteResult {
  target: string;
  source?: string;
  startedAt?: string;
  hops: Hop[];
}

export function parseMtr(target: string, text: string): TracerouteResult {
  const res: TracerouteResult = { target, hops: [] };
  for (const line of text.split("\n")) {
    let m: RegExpMatchArray | null;
    if ((m = line.match(/^Start:\s*(.+)$/))) res.startedAt = m[1].trim();
    else if ((m = line.match(/^HOST:\s*(\S+)/))) res.source = m[1];
    else if ((m = line.match(/^\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%?\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/))) {
      res.hops.push({
        hop: Number(m[1]),
        host: m[2],
        loss: Number(m[3]),
        sent: Number(m[4]),
        last: Number(m[5]),
        avg: Number(m[6]),
        best: Number(m[7]),
        worst: Number(m[8]),
        stdev: Number(m[9]),
        timeout: m[2] === "???",
      });
    } else if ((m = line.match(/^\s*(\d+)\s+(\S+)\s+\(?[^)]*\)?\s+([\d.]+)\s*ms/))) {
      // klasik traceroute biçimi
      const v = Number(m[3]);
      res.hops.push({ hop: Number(m[1]), host: m[2], loss: 0, sent: 1, last: v, avg: v, best: v, worst: v, stdev: 0, timeout: false });
    } else if ((m = line.match(/^\s*(\d+)\s+\*\s+\*\s+\*/))) {
      res.hops.push({ hop: Number(m[1]), host: "???", loss: 100, sent: 3, last: 0, avg: 0, best: 0, worst: 0, stdev: 0, timeout: true });
    }
  }
  return res;
}

export async function runTraceroute(t: ParsedTarget): Promise<TracerouteResult> {
  if (t.kind === "cidr") throw new UserError("Traceroute için tek bir IP veya alan adı girin.");
  const text = await htQuery("mtr", t.host, 55000);
  const r = parseMtr(t.host, text);
  if (!r.hops.length) throw new UserError("Rota bilgisi alınamadı.");
  return r;
}
