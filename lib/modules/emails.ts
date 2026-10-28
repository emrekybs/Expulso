import { safeFetch, UserError, decodeEntities } from "../net.ts";
import { extractFromHtml } from "./uscrapper-core.ts";
import { registrableDomain, type ParsedTarget } from "../target.ts";
import { runWhois } from "./whois.ts";
import type { ModuleOutput } from "../types.ts";

export interface EmailEntry {
  email: string;
  name?: string;
  type: "found" | "generated" | "role";
  source: string;
}
export interface EmailData {
  domain: string;
  pattern: string | null;
  patternConfidence: number;
  entries: EmailEntry[];
  stats: { found: number; generated: number; role: number };
}

const ROLE_LOCAL = new Set(["info", "contact", "hello", "support", "help", "sales", "hr", "jobs", "career", "careers", "press", "media", "admin", "office", "mail", "marketing", "finance", "billing", "legal", "privacy", "kvkk", "abuse", "security", "noreply", "no-reply", "iletisim", "destek", "bilgi"]);

const START_PATHS = ["/", "/contact", "/contact-us", "/iletisim", "/about", "/about-us", "/hakkimizda", "/team", "/ekibimiz", "/kurumsal", "/careers", "/kariyer", "/impressum", "/legal", "/privacy"];

function turkishAsciiFold(s: string): string {
  return s
    .replace(/ı/g, "i").replace(/İ/g, "i").replace(/ş/g, "s").replace(/Ş/g, "s").replace(/ğ/g, "g").replace(/Ğ/g, "g")
    .replace(/ü/g, "u").replace(/Ü/g, "u").replace(/ö/g, "o").replace(/Ö/g, "o").replace(/ç/g, "c").replace(/Ç/g, "c")
    .normalize("NFD").replace(/[̀-ͯ]/g, "");
}

function detectPattern(local: string, first: string, last: string): string | null {
  const f = first, l = last, fi = first[0], li = last[0];
  const map: [string, string][] = [
    [`${f}.${l}`, "{first}.{last}"],
    [`${f}${l}`, "{first}{last}"],
    [`${fi}${l}`, "{f}{last}"],
    [`${fi}.${l}`, "{f}.{last}"],
    [`${f}${li}`, "{first}{l}"],
    [`${f}_${l}`, "{first}_{last}"],
    [`${f}`, "{first}"],
    [`${l}${f}`, "{last}{first}"],
    [`${l}.${f}`, "{last}.{first}"],
  ];
  for (const [cand, pat] of map) if (cand && cand === local) return pat;
  return null;
}

function applyPattern(pattern: string, first: string, last: string): string {
  return pattern
    .replace("{first}", first)
    .replace("{last}", last)
    .replace("{f}", first[0] ?? "")
    .replace("{l}", last[0] ?? "");
}

/** Pulls "First Last" names from team/staff style markup. */
function extractNames(html: string): { first: string; last: string }[] {
  const text = decodeEntities(html.replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ");
  const out = new Map<string, { first: string; last: string }>();
  for (const m of text.matchAll(/\b([A-ZÇĞİÖŞÜ][a-zçğıöşü]{1,20})\s+([A-ZÇĞİÖŞÜ][a-zçğıöşü]{1,20})\b/g)) {
    const first = turkishAsciiFold(m[1]).toLowerCase();
    const last = turkishAsciiFold(m[2]).toLowerCase();
    if (first.length < 2 || last.length < 2) continue;
    out.set(`${first} ${last}`, { first, last });
    if (out.size > 60) break;
  }
  return [...out.values()];
}

export async function runEmails(t: ParsedTarget): Promise<ModuleOutput<EmailData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Email Harvester needs a domain or URL.");
  const domain = registrableDomain(t.host);
  const origin = t.url ? new URL(t.url).origin : `https://${t.host}`;
  const warnings: string[] = [];
  const byEmail = new Map<string, EmailEntry>();
  const nameSet = new Map<string, { first: string; last: string }>();

  const addEmail = (raw: string, source: string, name?: string) => {
    const email = raw.trim().toLowerCase();
    if (!email.endsWith(`@${domain}`) && !email.endsWith(`.${domain}`)) return;
    if (/\.(png|jpe?g|gif|svg|webp|css|js)$/i.test(email)) return;
    const local = email.split("@")[0];
    const existing = byEmail.get(email);
    const type: EmailEntry["type"] = ROLE_LOCAL.has(local) ? "role" : "found";
    if (!existing) byEmail.set(email, { email, name, type, source });
    else if (name && !existing.name) existing.name = name;
  };

  const deadline = Date.now() + 35000;
  const visited = new Set<string>();
  const queue: { url: string; label: string }[] = [{ url: origin + "/", label: "Homepage" }];
  const CONTACT_RE = /contact|iletisim|i̇letişim|about|hakkimizda|hakkımızda|team|ekip|kadro|management|yonetim|career|kariyer|insan|press|basin|privacy|gizlilik|kvkk|impressum|legal|support|destek|sales|satis/i;
  let discovered = 0;

  while (queue.length && visited.size < 14 && Date.now() < deadline) {
    const { url, label } = queue.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);
    try {
      const res = await safeFetch(url, { timeoutMs: 9000, maxBytes: 1_500_000, followRedirects: true });
      if (res.status !== 200) continue;
      const ex = extractFromHtml(res.body, res.finalUrl, false);
      if (ex.challenge && !warnings.some((w) => w.includes("results are limited"))) {
        warnings.push(`The site returned a ${ex.challenge} page, so the homepage could not be read. Results are limited because the site blocks automated access.`);
      }
      [...ex.emails, ...ex.textEmails].forEach((e) => addEmail(e, label));
      extractNames(res.body).forEach((n) => nameSet.set(`${n.first} ${n.last}`, n));
      // Follow contact-, team- and career-type links found on the page, plus the common fixed paths.
      if (label === "Homepage") {
        for (const link of ex.links) {
          if (discovered >= 10) break;
          const path = new URL(link).pathname;
          if (CONTACT_RE.test(path) && !visited.has(link)) {
            queue.push({ url: link, label: `Page ${path}` });
            discovered++;
          }
        }
        for (const p of START_PATHS) queue.push({ url: origin + p, label: `Page ${p}` });
      }
    } catch (e) {
      if (label === "Homepage") warnings.push(`Homepage: ${e instanceof UserError ? e.message : "fetch failed"}`);
    }
  }

  // WHOIS/RDAP contact emails
  try {
    const w = await runWhois({ ...t, kind: "domain", host: domain });
    if (w.data.abuseEmail) addEmail(w.data.abuseEmail, "WHOIS/RDAP");
    w.data.contacts.forEach((c) => c.email && addEmail(c.email, "WHOIS/RDAP", c.name));
  } catch {
    /* ignore */
  }

  // Detect pattern from found personal emails whose owner name we also have.
  const patternVotes = new Map<string, number>();
  for (const e of byEmail.values()) {
    if (e.type !== "found" || !e.name) continue;
    const parts = turkishAsciiFold(e.name).toLowerCase().split(/\s+/).filter(Boolean);
    if (parts.length < 2) continue;
    const pat = detectPattern(e.email.split("@")[0], parts[0], parts[parts.length - 1]);
    if (pat) patternVotes.set(pat, (patternVotes.get(pat) ?? 0) + 1);
  }
  let pattern: string | null = null;
  let patternConfidence = 0;
  if (patternVotes.size) {
    const sorted = [...patternVotes].sort((a, b) => b[1] - a[1]);
    pattern = sorted[0][0];
    const total = [...patternVotes.values()].reduce((a, b) => a + b, 0);
    patternConfidence = Math.round((sorted[0][1] / total) * 100);
  }

  // Generate addresses for names without an email, if we have a pattern.
  if (pattern) {
    const existingLocals = new Set([...byEmail.keys()].map((e) => e.split("@")[0]));
    for (const { first, last } of nameSet.values()) {
      const local = applyPattern(pattern, first, last);
      const email = `${local}@${domain}`;
      if (!local || existingLocals.has(local) || byEmail.has(email)) continue;
      byEmail.set(email, { email, name: `${cap(first)} ${cap(last)}`, type: "generated", source: `Pattern + name on site` });
    }
  } else if (nameSet.size) {
    warnings.push(`${nameSet.size} name(s) found but the address pattern could not be confirmed, so no addresses were generated.`);
  }

  const entries = [...byEmail.values()].sort((a, b) => order(a.type) - order(b.type) || a.email.localeCompare(b.email));
  const stats = { found: entries.filter((e) => e.type === "found").length, role: entries.filter((e) => e.type === "role").length, generated: entries.filter((e) => e.type === "generated").length };
  return {
    summary: `${entries.length} addresses${pattern ? ` · pattern ${pattern.replace("{first}", "first").replace("{last}", "last").replace("{f}", "f").replace("{l}", "l")}@` : ""}`,
    findings: [],
    data: { domain, pattern, patternConfidence, entries, stats },
    warnings,
  };
}

function order(t: EmailEntry["type"]): number {
  return t === "found" ? 0 : t === "role" ? 1 : 2;
}
function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
