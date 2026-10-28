import { fetchJson, UserError } from "../net.ts";
import type { ParsedTarget } from "../target.ts";

export const RR_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"] as const;
export type RRType = (typeof RR_TYPES)[number] | "PTR";

const TYPE_NUM: Record<number, RRType> = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA" };

export interface DnsRecord {
  type: RRType;
  name: string;
  ttl: number;
  value: string;
  priority?: number;
}

interface DohResponse {
  Status: number;
  Answer?: { name: string; type: number; TTL: number; data: string }[];
}

const RESOLVERS = [
  (n: string, t: string) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
  (n: string, t: string) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`,
];

/** DNS-over-HTTPS sorgusu (Cloudflare, yedek: Google). */
export async function doh(name: string, type: RRType): Promise<{ status: number; records: DnsRecord[] }> {
  let lastErr: unknown;
  for (const r of RESOLVERS) {
    try {
      const j = await fetchJson<DohResponse>(r(name, type), 8000, { accept: "application/dns-json" });
      const records = (j.Answer ?? [])
        .filter((a) => TYPE_NUM[a.type] === type)
        .map((a): DnsRecord => {
          const name = a.name.replace(/\.$/, "");
          if (type === "MX") {
            const [p, ...rest] = a.data.split(" ");
            return { type, name, ttl: a.TTL, priority: Number(p), value: rest.join(" ").replace(/\.$/, "") };
          }
          if (type === "TXT") return { type, name, ttl: a.TTL, value: a.data.replace(/^"|"$/g, "").replace(/"\s*"/g, "") };
          return { type, name, ttl: a.TTL, value: a.data.replace(/\.$/, "") };
        });
      return { status: j.Status, records };
    } catch (e) {
      lastErr = e;
    }
  }
  throw new UserError(`DNS sorgusu başarısız oldu${lastErr instanceof Error ? ` (${lastErr.message})` : ""}.`);
}

export async function resolveA(host: string): Promise<string[]> {
  const r = await doh(host, "A");
  return r.records.map((x) => x.value);
}

export function reverseName(ip: string): string {
  if (ip.includes(":")) {
    const full = expandV6(ip).replace(/:/g, "");
    return [...full].reverse().join(".") + ".ip6.arpa";
  }
  return ip.split(".").reverse().join(".") + ".in-addr.arpa";
}

function expandV6(ip: string): string {
  const [head, tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const mid = Array(8 - h.length - t.length).fill("0");
  return [...h, ...mid, ...t].map((g) => g.padStart(4, "0")).join(":");
}

export async function ptr(ip: string): Promise<string[]> {
  const r = await doh(reverseName(ip), "PTR");
  return r.records.map((x) => x.value);
}

export interface EmailSecurity {
  spf: { record: string | null; policy: string | null; verdict: "iyi" | "orta" | "zayıf" | "yok"; note: string };
  dmarc: { record: string | null; policy: string | null; verdict: "iyi" | "orta" | "zayıf" | "yok"; note: string };
  provider: string | null;
}

export interface DnsResult {
  domain: string;
  nxdomain: boolean;
  records: DnsRecord[];
  counts: Partial<Record<RRType, number>>;
  emailSecurity: EmailSecurity;
  services: { name: string; evidence: string }[];
}

const MX_PROVIDERS: [RegExp, string][] = [
  [/google\.com$|googlemail\.com$/i, "Google Workspace"],
  [/outlook\.com$|protection\.outlook\.com$/i, "Microsoft 365"],
  [/yandex\.(net|ru)$/i, "Yandex 360"],
  [/zoho\.(com|eu)$/i, "Zoho Mail"],
  [/protonmail\.ch$/i, "Proton Mail"],
  [/mimecast\.com$/i, "Mimecast"],
  [/pphosted\.com$/i, "Proofpoint"],
  [/icloud\.com$/i, "iCloud Mail"],
  [/mailgun\.org$/i, "Mailgun"],
  [/amazonaws\.com$/i, "Amazon SES"],
];

const TXT_SERVICES: [RegExp, string][] = [
  [/^google-site-verification=/i, "Google Search Console"],
  [/^MS=/i, "Microsoft 365"],
  [/^facebook-domain-verification=/i, "Facebook / Meta"],
  [/^apple-domain-verification=/i, "Apple"],
  [/^atlassian-domain-verification=/i, "Atlassian"],
  [/^docusign=/i, "DocuSign"],
  [/^adobe-idp-site-verification=/i, "Adobe"],
  [/^stripe-verification=/i, "Stripe"],
  [/^zoom-domain-verification/i, "Zoom"],
  [/^slack-domain-verification/i, "Slack"],
  [/^yandex-verification/i, "Yandex Webmaster"],
  [/^globalsign-domain-verification/i, "GlobalSign"],
  [/^_?github-(pages-)?challenge/i, "GitHub"],
  [/^hubspot/i, "HubSpot"],
  [/^cisco-ci-domain-verification/i, "Cisco Webex"],
  [/^openai-domain-verification/i, "OpenAI"],
  [/^anthropic-domain-verification/i, "Anthropic"],
  [/^brevo-code/i, "Brevo"],
  [/^mailru-verification/i, "Mail.ru"],
  [/^dropbox-domain-verification/i, "Dropbox"],
  [/^notion-domain-verification/i, "Notion"],
];

export function analyzeEmailSecurity(txt: string[], dmarcTxt: string[], mx: DnsRecord[]): EmailSecurity {
  const spfRec = txt.find((t) => /^v=spf1\b/i.test(t)) ?? null;
  let spf: EmailSecurity["spf"];
  if (!spfRec) spf = { record: null, policy: null, verdict: "yok", note: "SPF kaydı yok: alan adı adına sahte e-posta gönderilmesi kolaylaşır." };
  else {
    const all = spfRec.match(/([+~?-])?all\b/i);
    const q = all ? (all[1] ?? "+") : null;
    const map: Record<string, [EmailSecurity["spf"]["verdict"], string, string]> = {
      "-": ["iyi", "Katı (-all)", "Yetkisiz sunuculardan gelen e-postalar reddedilir."],
      "~": ["orta", "Yumuşak (~all)", "Yetkisiz e-postalar işaretlenir ancak reddedilmez."],
      "?": ["zayıf", "Nötr (?all)", "Yetkisiz e-postalar için herhangi bir işlem yapılmaz."],
      "+": ["zayıf", "Herkese izin (+all)", "Tehlikeli: tüm sunucular bu alan adı adına e-posta gönderebilir."],
    };
    const [verdict, policy, note] = q ? map[q] : ["orta" as const, "Belirtilmemiş", "SPF kaydında 'all' mekanizması bulunmuyor."];
    spf = { record: spfRec, policy, verdict, note };
  }

  const dmarcRec = dmarcTxt.find((t) => /^v=DMARC1/i.test(t)) ?? null;
  let dmarc: EmailSecurity["dmarc"];
  if (!dmarcRec) dmarc = { record: null, policy: null, verdict: "yok", note: "DMARC kaydı yok: kimlik sahteciliği (spoofing) girişimlerine karşı koruma eksik." };
  else {
    const p = dmarcRec.match(/\bp=(\w+)/i)?.[1]?.toLowerCase() ?? "none";
    const map: Record<string, [EmailSecurity["dmarc"]["verdict"], string, string]> = {
      reject: ["iyi", "Reddet (reject)", "Doğrulamayı geçemeyen e-postalar reddedilir."],
      quarantine: ["orta", "Karantina (quarantine)", "Doğrulamayı geçemeyen e-postalar spam klasörüne gönderilir."],
      none: ["zayıf", "İzleme (none)", "Yalnızca raporlama yapılır, sahte e-postalar engellenmez."],
    };
    const [verdict, policy, note] = map[p] ?? map.none;
    dmarc = { record: dmarcRec, policy, verdict, note };
  }

  let provider: string | null = null;
  for (const m of mx) {
    const hit = MX_PROVIDERS.find(([re]) => re.test(m.value));
    if (hit) {
      provider = hit[1];
      break;
    }
  }
  return { spf, dmarc, provider };
}

export function detectServices(txt: string[]): { name: string; evidence: string }[] {
  const out = new Map<string, string>();
  for (const t of txt) for (const [re, name] of TXT_SERVICES) if (re.test(t) && !out.has(name)) out.set(name, t);
  return [...out].map(([name, evidence]) => ({ name, evidence }));
}

export async function runDns(t: ParsedTarget): Promise<DnsResult> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("DNS kayıtları için bir alan adı girin. IP adresleri için Ters DNS modülünü kullanın.");
  const domain = t.host;
  const results = await Promise.all(RR_TYPES.map((ty) => doh(domain, ty).catch(() => ({ status: -1, records: [] as DnsRecord[] }))));
  const dmarc = await doh(`_dmarc.${domain}`, "TXT").catch(() => ({ status: -1, records: [] as DnsRecord[] }));
  if (results.every((r) => r.status === -1)) throw new UserError("DNS çözümleyicilerine ulaşılamadı.");
  const nxdomain = results.some((r) => r.status === 3);
  const records = results.flatMap((r) => r.records);
  const counts: DnsResult["counts"] = {};
  for (const r of records) counts[r.type] = (counts[r.type] ?? 0) + 1;
  const txt = records.filter((r) => r.type === "TXT").map((r) => r.value);
  const mx = records.filter((r) => r.type === "MX").sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));
  return {
    domain,
    nxdomain,
    records,
    counts,
    emailSecurity: analyzeEmailSecurity(txt, dmarc.records.map((r) => r.value), mx),
    services: detectServices(txt),
  };
}
