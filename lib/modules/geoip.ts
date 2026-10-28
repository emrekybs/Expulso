import { fetchJson, UserError } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { resolveA } from "./dns.ts";
import type { ParsedTarget } from "../target.ts";

export interface GeoEntry {
  ip: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  postal?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  utcOffset?: string;
  asn?: number;
  org?: string;
  isp?: string;
  asDomain?: string;
  continent?: string;
  type?: string;
  source: string;
}

export interface GeoResult {
  target: string;
  resolvedFrom?: string;
  entries: GeoEntry[];
}

interface IpWhoIs {
  success: boolean;
  message?: string;
  ip: string;
  type?: string;
  continent?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  postal?: string;
  latitude?: number;
  longitude?: number;
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };
  timezone?: { id?: string; utc?: string };
}

export function parseHtGeo(ip: string, text: string): GeoEntry {
  const kv: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) kv[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  const num = (v?: string) => (v && !Number.isNaN(Number(v)) ? Number(v) : undefined);
  return {
    ip: kv["ip address"] || ip,
    country: kv.country || undefined,
    region: kv.state || undefined,
    city: kv.city || undefined,
    latitude: num(kv.latitude),
    longitude: num(kv.longitude),
    source: "HackerTarget",
  };
}

async function lookup(ip: string): Promise<GeoEntry> {
  try {
    const j = await fetchJson<IpWhoIs>(`https://ipwho.is/${encodeURIComponent(ip)}`, 10000);
    if (!j.success) {
      if (/reserved|private|invalid/i.test(j.message ?? "")) throw new UserError("Bu IP adresi özel/ayrılmış bir aralıkta; konum bilgisi yok.");
      throw new Error(j.message);
    }
    return {
      ip: j.ip,
      country: j.country,
      countryCode: j.country_code,
      region: j.region,
      city: j.city,
      postal: j.postal,
      latitude: j.latitude,
      longitude: j.longitude,
      timezone: j.timezone?.id,
      utcOffset: j.timezone?.utc,
      asn: j.connection?.asn,
      org: j.connection?.org,
      isp: j.connection?.isp,
      asDomain: j.connection?.domain,
      continent: j.continent,
      type: j.type,
      source: "ipwho.is",
    };
  } catch (e) {
    if (e instanceof UserError) throw e;
    const text = await htQuery("geoip", ip);
    if (!text) throw new UserError("Konum bilgisi bulunamadı.");
    return parseHtGeo(ip, text);
  }
}

export async function runGeoip(t: ParsedTarget): Promise<GeoResult> {
  if (t.kind === "cidr") throw new UserError("GeoIP için tek bir IP adresi veya alan adı girin.");
  if (t.kind === "ip" || /^[\d.]+$/.test(t.host)) return { target: t.host, entries: [await lookup(t.host)] };
  const ips = (await resolveA(t.host)).slice(0, 4);
  if (!ips.length) throw new UserError(`"${t.host}" için A kaydı bulunamadı.`);
  const entries = await Promise.all(ips.map(lookup));
  return { target: t.host, resolvedFrom: t.host, entries };
}
