import { fetchWithTimeout, UserError } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { EVENT_TR, ROLE_TR, translateStatus, translateWhoisKey } from "../i18n.ts";
import type { ParsedTarget } from "../target.ts";

export interface WhoisContact {
  roles: string[];
  name?: string;
  org?: string;
  email?: string;
  phone?: string;
  country?: string;
  address?: string;
}

export interface WhoisResult {
  target: string;
  kind: "domain" | "ip";
  source: "RDAP" | "WHOIS";
  name?: string;
  handle?: string;
  registrar?: string;
  registrarIanaId?: string;
  abuseEmail?: string;
  statuses: { tr: string; raw: string }[];
  events: { label: string; action: string; date: string }[];
  nameservers: string[];
  dnssec?: boolean;
  contacts: WhoisContact[];
  network?: { range?: string; cidr?: string; type?: string; country?: string; parent?: string };
  fields: { key: string; label: string; value: string }[];
}

type Vcard = ["vcard", [string, Record<string, unknown>, string, unknown][]];
interface RdapEntity {
  roles?: string[];
  handle?: string;
  vcardArray?: Vcard;
  publicIds?: { type: string; identifier: string }[];
  entities?: RdapEntity[];
}
interface Rdap {
  ldhName?: string;
  unicodeName?: string;
  handle?: string;
  name?: string;
  type?: string;
  country?: string;
  startAddress?: string;
  endAddress?: string;
  parentHandle?: string;
  cidr0_cidrs?: { v4prefix?: string; v6prefix?: string; length: number }[];
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  nameservers?: { ldhName: string }[];
  secureDNS?: { delegationSigned?: boolean };
  entities?: RdapEntity[];
  links?: { rel: string; href: string; type?: string }[];
}

function vcardField(e: RdapEntity, field: string): string | undefined {
  const row = e.vcardArray?.[1]?.find((r) => r[0] === field);
  if (!row) return undefined;
  const v = row[3];
  if (Array.isArray(v)) return v.filter(Boolean).join(", ") || undefined;
  if (field === "adr") {
    const label = (row[1] as { label?: string })?.label;
    if (label) return label.replace(/\n/g, ", ");
  }
  return v ? String(v).replace(/^tel:/, "") : undefined;
}

function vcardCountry(e: RdapEntity): string | undefined {
  const row = e.vcardArray?.[1]?.find((r) => r[0] === "adr");
  if (!row) return undefined;
  const cc = (row[1] as { cc?: string })?.cc;
  if (cc) return cc;
  const v = row[3];
  if (Array.isArray(v) && v[6]) return String(v[6]);
  return undefined;
}

function flattenEntities(list: RdapEntity[] = []): RdapEntity[] {
  return list.flatMap((e) => [e, ...flattenEntities(e.entities)]);
}

const REDACTED = /redacted|privacy|withheld|not disclosed|data protected/i;

function toContact(e: RdapEntity): WhoisContact | null {
  const c: WhoisContact = {
    roles: (e.roles ?? []).map((r) => ROLE_TR[r] ?? r),
    name: vcardField(e, "fn"),
    org: vcardField(e, "org"),
    email: vcardField(e, "email"),
    phone: vcardField(e, "tel"),
    address: vcardField(e, "adr"),
    country: vcardCountry(e),
  };
  if (!c.name && !c.org && !c.email && !c.country) return null;
  return c;
}

async function rdap(url: string): Promise<Rdap | null> {
  const res = await fetchWithTimeout(url, { headers: { accept: "application/rdap+json, application/json" } }, 12000);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
  return (await res.json()) as Rdap;
}

export function fromRdap(target: string, kind: "domain" | "ip", d: Rdap, extra?: Rdap | null): WhoisResult {
  const ents = flattenEntities([...(d.entities ?? []), ...(extra?.entities ?? [])]);
  const registrar = ents.find((e) => e.roles?.includes("registrar"));
  const abuse = ents.find((e) => e.roles?.includes("abuse"));
  const contacts: WhoisContact[] = [];
  const seen = new Set<string>();
  for (const e of ents) {
    if (e.roles?.includes("registrar")) continue;
    const c = toContact(e);
    if (!c) continue;
    const key = JSON.stringify([c.roles, c.name, c.org, c.email]);
    if (seen.has(key)) continue;
    seen.add(key);
    contacts.push(c);
  }
  const events = [...(d.events ?? []), ...(extra?.events ?? [])]
    .filter((e, i, arr) => arr.findIndex((x) => x.eventAction === e.eventAction) === i)
    .map((e) => ({ action: e.eventAction, label: EVENT_TR[e.eventAction.toLowerCase()] ?? e.eventAction, date: e.eventDate }));
  const statuses = [...new Set([...(d.status ?? []), ...(extra?.status ?? [])])].map((raw) => ({ raw, tr: translateStatus(raw) }));

  const cidr = d.cidr0_cidrs?.map((c) => `${c.v4prefix ?? c.v6prefix}/${c.length}`).join(", ");
  return {
    target,
    kind,
    source: "RDAP",
    name: d.unicodeName ?? d.ldhName ?? d.name,
    handle: d.handle,
    registrar: registrar ? vcardField(registrar, "fn") ?? registrar.handle : undefined,
    registrarIanaId: registrar?.publicIds?.find((p) => /iana/i.test(p.type))?.identifier,
    abuseEmail: abuse ? vcardField(abuse, "email") : undefined,
    statuses,
    events,
    nameservers: (d.nameservers ?? []).map((n) => n.ldhName.toLowerCase()),
    dnssec: d.secureDNS?.delegationSigned,
    contacts: contacts.map((c) => (REDACTED.test(`${c.name} ${c.org}`) ? { ...c, name: c.name ? `${c.name} (gizlenmiş)` : c.name } : c)),
    network:
      kind === "ip"
        ? { range: d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : undefined, cidr, type: d.type, country: d.country, parent: d.parentHandle }
        : undefined,
    fields: [],
  };
}

/** Ham WHOIS metnini anahtar/değer alanlarına ayrıştırır (RDAP olmayan uzantılar, ör. .tr). */
export function parseRawWhois(target: string, kind: "domain" | "ip", raw: string): WhoisResult {
  const fields: WhoisResult["fields"] = [];
  const statuses: WhoisResult["statuses"] = [];
  const nameservers = new Set<string>();
  const events: WhoisResult["events"] = [];
  let registrar: string | undefined;
  let abuseEmail: string | undefined;
  let dnssec: boolean | undefined;

  for (const line of raw.split(/\r?\n/)) {
    if (/^\s*(%|#|>>>|NOTICE|TERMS OF USE|URL of the ICANN|For more information)/i.test(line)) continue;
    const m = line.match(/^\s*\**\s*([A-Za-z][\w /().-]{1,60}?)\s*\.*\s*:\s*(.+?)\s*$/);
    if (!m) continue;
    const key = m[1].replace(/\.+$/, "").trim();
    const value = m[2].replace(/\.$/, "").trim();
    if (!value || /^https?$/i.test(value)) continue;
    const label = translateWhoisKey(key);
    if (label === "Durum") {
      statuses.push({ raw: value, tr: translateStatus(value.split(" ")[0]) });
      continue;
    }
    if (label === "Ad sunucusu") {
      nameservers.add(value.toLowerCase().split(/\s+/)[0]);
      continue;
    }
    if (label === "Kayıt şirketi" && !registrar) registrar = value;
    if (label === "Kötüye kullanım e-postası" && !abuseEmail) abuseEmail = value;
    if (label === "DNSSEC") dnssec = !/unsigned|no|inactive/i.test(value);
    if (label === "Oluşturulma tarihi") events.push({ action: "registration", label: "Kayıt tarihi", date: value });
    if (label === "Bitiş tarihi") events.push({ action: "expiration", label: "Bitiş tarihi", date: value });
    if (label === "Güncellenme tarihi") events.push({ action: "last changed", label: "Son değişiklik", date: value });
    if (fields.some((f) => f.key === key && f.value === value)) continue;
    fields.push({ key, label, value });
  }
  return {
    target,
    kind,
    source: "WHOIS",
    registrar,
    abuseEmail,
    statuses,
    events: events.filter((e, i, a) => a.findIndex((x) => x.action === e.action) === i),
    nameservers: [...nameservers],
    dnssec,
    contacts: [],
    fields: fields.slice(0, 120),
  };
}

export async function runWhois(t: ParsedTarget): Promise<WhoisResult> {
  if (t.kind === "cidr") throw new UserError("WHOIS için tek bir IP adresi veya alan adı girin.");
  const kind = t.kind === "ip" || (t.kind === "url" && /^[\d.:]+$/.test(t.host)) ? "ip" : "domain";
  // Alt alan adı girilirse kayıtlı alan adına indir (basit yaklaşım: son iki etiket, ikinci seviye TLD'ler hariç)
  const target = kind === "domain" ? registrableDomain(t.host) : t.host;

  try {
    const d = await rdap(`https://rdap.org/${kind}/${encodeURIComponent(target)}`);
    if (d) {
      let extra: Rdap | null = null;
      const related = d.links?.find((l) => l.rel === "related" && /rdap/i.test(l.href) && l.href !== `https://rdap.org/${kind}/${target}`);
      if (related) extra = await rdap(related.href).catch(() => null);
      return fromRdap(target, kind, d, extra);
    }
  } catch {
    /* RDAP başarısız: WHOIS'e düş */
  }
  const raw = await htQuery("whois", target);
  if (!raw) throw new UserError("WHOIS kaydı bulunamadı.");
  return parseRawWhois(target, kind, raw);
}

const SECOND_LEVEL = /\.(com|net|org|gov|edu|gen|web|av|dr|bel|pol|k12|tsk|bbs|tv|info|biz|name|tel|co|ac|or|ne|go|mil)\.[a-z]{2}$/i;
export function registrableDomain(host: string): string {
  const parts = host.split(".");
  const keep = SECOND_LEVEL.test(host) ? 3 : 2;
  return parts.slice(-keep).join(".");
}
