import { fetchWithTimeout, UserError } from "../net.ts";
import { htQuery } from "../hackertarget.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import { daysUntil, formatDate, yearsSince } from "../geo-core.ts";
import type { Finding, ModuleOutput } from "../types.ts";

export interface WhoisData {
  target: string;
  kind: "domain" | "ip";
  source: "RDAP" | "WHOIS";
  name?: string;
  handle?: string;
  registrar?: string;
  abuseEmail?: string;
  ageYears?: number;
  expiresInDays?: number;
  statuses: string[];
  events: { label: string; date: string; raw: string }[];
  nameservers: string[];
  dnssec?: boolean;
  contacts: { roles: string[]; name?: string; org?: string; email?: string; country?: string }[];
  network?: { range?: string; cidr?: string; type?: string; country?: string; org?: string };
  fields: { label: string; value: string }[];
}

const ROLE_TR: Record<string, string> = { registrant: "Registrant", registrar: "Registrar", administrative: "Admin", technical: "Technical", abuse: "Abuse", reseller: "Reseller", noc: "NOC" };
const EVENT_TR: Record<string, string> = { registration: "Registered", expiration: "Expires", "last changed": "Last changed", transfer: "Transferred", "last update of rdap database": "RDAP updated" };

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
  cidr0_cidrs?: { v4prefix?: string; v6prefix?: string; length: number }[];
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  nameservers?: { ldhName: string }[];
  secureDNS?: { delegationSigned?: boolean };
  entities?: RdapEntity[];
  links?: { rel: string; href: string }[];
}

function vcard(e: RdapEntity, field: string): string | undefined {
  const row = e.vcardArray?.[1]?.find((r) => r[0] === field);
  if (!row) return undefined;
  const v = row[3];
  if (Array.isArray(v)) return v.filter(Boolean).join(", ") || undefined;
  return v ? String(v).replace(/^tel:/, "") : undefined;
}
function vcardCc(e: RdapEntity): string | undefined {
  const row = e.vcardArray?.[1]?.find((r) => r[0] === "adr");
  const cc = (row?.[1] as { cc?: string } | undefined)?.cc;
  return cc || undefined;
}
function flatten(list: RdapEntity[] = []): RdapEntity[] {
  return list.flatMap((e) => [e, ...flatten(e.entities)]);
}
const REDACTED = /redacted|privacy|withheld|not disclosed|data protected|gdpr/i;

function statusTr(raw: string): string {
  return raw
    .replace(/https?:\/\/\S+/g, "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .trim();
}

export function fromRdap(target: string, kind: "domain" | "ip", d: Rdap, extra?: Rdap | null): WhoisData {
  const ents = flatten([...(d.entities ?? []), ...(extra?.entities ?? [])]);
  const registrar = ents.find((e) => e.roles?.includes("registrar"));
  const abuse = ents.find((e) => e.roles?.includes("abuse"));
  const seen = new Set<string>();
  const contacts: WhoisData["contacts"] = [];
  for (const e of ents) {
    if (e.roles?.includes("registrar")) continue;
    const c = { roles: (e.roles ?? []).map((r) => ROLE_TR[r] ?? r), name: vcard(e, "fn"), org: vcard(e, "org"), email: vcard(e, "email"), country: vcardCc(e) };
    if (!c.name && !c.org && !c.email && !c.country) continue;
    const key = JSON.stringify([c.roles, c.name, c.org, c.email]);
    if (seen.has(key)) continue;
    seen.add(key);
    if (c.name && REDACTED.test(c.name)) c.name = "(redacted)";
    contacts.push(c);
  }
  const events = [...(d.events ?? []), ...(extra?.events ?? [])]
    .filter((e, i, a) => a.findIndex((x) => x.eventAction === e.eventAction) === i)
    .map((e) => ({ raw: e.eventDate, label: EVENT_TR[e.eventAction.toLowerCase()] ?? e.eventAction, date: formatDate(e.eventDate) }));
  const reg = events.find((e) => /register/i.test(e.label))?.raw;
  const exp = events.find((e) => /expir/i.test(e.label))?.raw;
  const cidr = d.cidr0_cidrs?.map((c) => `${c.v4prefix ?? c.v6prefix}/${c.length}`).join(", ");
  return {
    target,
    kind,
    source: "RDAP",
    name: d.unicodeName ?? d.ldhName ?? d.name,
    handle: d.handle,
    registrar: registrar ? vcard(registrar, "fn") ?? registrar.handle : undefined,
    abuseEmail: abuse ? vcard(abuse, "email") : undefined,
    ageYears: yearsSince(reg) ?? undefined,
    expiresInDays: daysUntil(exp) ?? undefined,
    statuses: [...new Set([...(d.status ?? []), ...(extra?.status ?? [])])].map(statusTr),
    events,
    nameservers: (d.nameservers ?? []).map((n) => n.ldhName.toLowerCase()),
    dnssec: d.secureDNS?.delegationSigned,
    contacts,
    network: kind === "ip" ? { range: d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : undefined, cidr, type: d.type, country: d.country, org: registrar ? vcard(registrar, "fn") : vcard(ents[0] ?? {}, "fn") } : undefined,
    fields: [],
  };
}

const KEY_MAP: [RegExp, string][] = [
  [/^(creation date|created|registered|registration time)/i, "Registered"],
  [/^(registry expiry date|expir|paid-till)/i, "Expires"],
  [/^(updated date|last updated|last modified)/i, "Last changed"],
  [/^(registrar|sponsoring registrar)/i, "Registrar"],
  [/^(domain status|status)/i, "Status"],
  [/^(name server|nserver)/i, "Name server"],
  [/^dnssec/i, "DNSSEC"],
  [/^registrar abuse contact email/i, "Abuse email"],
  [/^(netrange|inetnum)/i, "Range"],
  [/^cidr/i, "CIDR"],
  [/^(orgname|org-name|organization|descr)/i, "Organisation"],
  [/^country/i, "Country"],
];

export function parseRawWhois(target: string, kind: "domain" | "ip", raw: string): WhoisData {
  const d: WhoisData = { target, kind, source: "WHOIS", statuses: [], events: [], nameservers: [], contacts: [], fields: [] };
  const seenF = new Set<string>();
  for (const line of raw.split(/\r?\n/)) {
    if (/^\s*(%|#|>>>|NOTICE|TERMS|URL of the ICANN|For more)/i.test(line)) continue;
    const m = line.match(/^\s*([A-Za-z][\w /().-]{1,50}?)\s*:\s*(.+?)\s*$/);
    if (!m) continue;
    const value = m[2].replace(/\.$/, "").trim();
    if (!value || /^https?$/i.test(value)) continue;
    const label = KEY_MAP.find(([re]) => re.test(m[1]))?.[1];
    if (label === "Registered" && !d.events.some((e) => e.label === "Registered")) d.events.push({ label: "Registered", date: formatDate(value), raw: value }), (d.ageYears = yearsSince(value) ?? undefined);
    else if (label === "Expires" && !d.events.some((e) => e.label === "Expires")) d.events.push({ label: "Expires", date: formatDate(value), raw: value }), (d.expiresInDays = daysUntil(value) ?? undefined);
    else if (label === "Last changed" && !d.events.some((e) => e.label === "Last changed")) d.events.push({ label: "Last changed", date: formatDate(value), raw: value });
    else if (label === "Registrar" && !d.registrar) d.registrar = value;
    else if (label === "Status") d.statuses.push(statusTr(value.split(" ")[0]));
    else if (label === "Name server") d.nameservers.push(value.toLowerCase().split(/\s+/)[0]);
    else if (label === "DNSSEC") d.dnssec = !/unsigned|no|inactive/i.test(value);
    else if (label === "Abuse email" && !d.abuseEmail) d.abuseEmail = value;
    const fk = `${m[1]}=${value}`;
    if (!seenF.has(fk)) {
      seenF.add(fk);
      d.fields.push({ label: label ?? m[1].trim(), value });
    }
  }
  d.nameservers = [...new Set(d.nameservers)];
  d.statuses = [...new Set(d.statuses)];
  d.fields = d.fields.slice(0, 100);
  return d;
}

async function rdap(url: string): Promise<Rdap | null> {
  const res = await fetchWithTimeout(url, { headers: { accept: "application/rdap+json, application/json" } }, 12000);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
  return (await res.json()) as Rdap;
}

function buildFindings(d: WhoisData): Finding[] {
  const f: Finding[] = [];
  if (typeof d.expiresInDays === "number" && d.expiresInDays >= 0 && d.expiresInDays < 30)
    f.push({ severity: d.expiresInDays < 7 ? "medium" : "low", title: `Domain expires in ${d.expiresInDays} days`, detail: "A lapsed registration can let someone else take over the domain.", recommendation: "Renew the domain and enable auto-renew." });
  if (typeof d.expiresInDays === "number" && d.expiresInDays < 0)
    f.push({ severity: "high", title: "Domain registration has expired", detail: `Expired ${-d.expiresInDays} days ago; it may enter redemption and then become available to others.`, recommendation: "Renew immediately." });
  if (d.kind === "domain" && d.dnssec === false) f.push({ severity: "low", title: "DNSSEC not enabled", detail: "DNS answers for the domain are not signed.", recommendation: "Enable DNSSEC." });
  if (d.kind === "domain" && !d.statuses.some((s) => /transfer prohibited/i.test(s)))
    f.push({ severity: "low", title: "Transfer lock not set", detail: "clientTransferProhibited is not present, which makes an unauthorised transfer easier.", recommendation: "Enable the registrar transfer lock." });
  return f;
}

export async function runWhois(t: ParsedTarget): Promise<ModuleOutput<WhoisData>> {
  if (t.kind === "cidr") throw new UserError("WHOIS needs a single domain or IP.");
  const kind: "domain" | "ip" = t.kind === "ip" || (t.kind === "url" && /^[\d.:]+$/.test(t.host)) ? "ip" : "domain";
  const target = kind === "domain" ? registrableDomain(t.host) : t.host;
  let data: WhoisData;
  try {
    const d = await rdap(`https://rdap.org/${kind}/${encodeURIComponent(target)}`);
    if (d) {
      const related = d.links?.find((l) => l.rel === "related" && /rdap/i.test(l.href) && !l.href.includes("rdap.org"));
      const extra = related ? await rdap(related.href).catch(() => null) : null;
      data = fromRdap(target, kind, d, extra);
    } else throw new Error("not found");
  } catch {
    const raw = await htQuery("whois", target);
    if (!raw) throw new UserError("No WHOIS record found.");
    data = parseRawWhois(target, kind, raw);
  }
  const summary =
    kind === "domain"
      ? `${data.registrar ?? "unknown registrar"}${data.ageYears != null ? ` · ${data.ageYears}y old` : ""}${data.expiresInDays != null ? ` · expires in ${data.expiresInDays}d` : ""}`
      : `${data.network?.org ?? data.network?.range ?? target}${data.network?.country ? ` · ${data.network.country}` : ""}`;
  return { summary, findings: buildFindings(data), data };
}
