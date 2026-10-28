import { UserError } from "../net.ts";
import { doh, RR_TYPES, type DnsRecord, type RRType } from "../dns-core.ts";
import type { ParsedTarget } from "../target.ts";
import type { Finding, ModuleOutput } from "../types.ts";

export interface MailAuth {
  spf: { record: string | null; policy: string; verdict: Verdict; note: string };
  dmarc: { record: string | null; policy: string; verdict: Verdict; note: string };
  dkim: { selectors: string[]; note: string };
  mtaSts: { present: boolean; note: string };
  dnssec: { signed: boolean; note: string };
  provider: string | null;
}
type Verdict = "good" | "fair" | "weak" | "missing";

export interface DnsData {
  domain: string;
  nxdomain: boolean;
  records: DnsRecord[];
  counts: Partial<Record<RRType, number>>;
  mail: MailAuth;
  services: { name: string; evidence: string }[];
}

const MX_PROVIDERS: [RegExp, string][] = [
  [/google\.com$|googlemail\.com$/i, "Google Workspace"],
  [/outlook\.com$|protection\.outlook\.com$/i, "Microsoft 365"],
  [/yandex\.(net|ru)$/i, "Yandex 360"],
  [/zoho\.(com|eu)$/i, "Zoho Mail"],
  [/protonmail\.ch$|proton\.me$/i, "Proton Mail"],
  [/mimecast\.com$/i, "Mimecast"],
  [/pphosted\.com$/i, "Proofpoint"],
  [/icloud\.com$/i, "iCloud Mail"],
  [/mailgun\.org$/i, "Mailgun"],
  [/amazonaws\.com$/i, "Amazon SES"],
  [/secureserver\.net$/i, "GoDaddy"],
  [/yandex/i, "Yandex"],
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
  [/^notion-domain-verification/i, "Notion"],
  [/^dropbox-domain-verification/i, "Dropbox"],
  [/^mailru-verification/i, "Mail.ru"],
  [/^brevo-code/i, "Brevo"],
  [/^logmein-verification/i, "GoTo / LogMeIn"],
  [/^citrix-verification/i, "Citrix"],
];

const COMMON_DKIM = ["selector1", "selector2", "google", "default", "k1", "k2", "dkim", "mail", "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "zmail", "pic", "scph0819", "sig1"];

export function analyzeMail(txt: string[], dmarcTxt: string[], mx: DnsRecord[], dkimSelectors: string[], dnssec: boolean): MailAuth {
  const spfRec = txt.find((t) => /^v=spf1\b/i.test(t)) ?? null;
  let spf: MailAuth["spf"];
  if (!spfRec) spf = { record: null, policy: "—", verdict: "missing", note: "No SPF record. Anyone can send email claiming to be from this domain more easily." };
  else {
    const all = spfRec.match(/([+~?-])?all\b/i);
    const q = all ? (all[1] ?? "+") : null;
    const map: Record<string, [Verdict, string, string]> = {
      "-": ["good", "-all (hard fail)", "Mail from unauthorised servers is rejected."],
      "~": ["fair", "~all (soft fail)", "Unauthorised mail is marked but usually still delivered."],
      "?": ["weak", "?all (neutral)", "No action is taken on unauthorised mail."],
      "+": ["weak", "+all (pass all)", "Dangerous: any server may send mail as this domain."],
    };
    const [verdict, policy, note] = q ? map[q] : (["fair", "no 'all' mechanism", "The SPF record has no 'all' mechanism."] as [Verdict, string, string]);
    spf = { record: spfRec, policy, verdict, note };
  }

  const dmarcRec = dmarcTxt.find((t) => /^v=DMARC1/i.test(t)) ?? null;
  let dmarc: MailAuth["dmarc"];
  if (!dmarcRec) dmarc = { record: null, policy: "—", verdict: "missing", note: "No DMARC record. Spoofing protection is incomplete." };
  else {
    const p = dmarcRec.match(/\bp=(\w+)/i)?.[1]?.toLowerCase() ?? "none";
    const map: Record<string, [Verdict, string, string]> = {
      reject: ["good", "p=reject", "Mail that fails authentication is rejected."],
      quarantine: ["fair", "p=quarantine", "Mail that fails authentication goes to spam."],
      none: ["weak", "p=none", "Monitoring only; spoofed mail is not blocked."],
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
  return {
    spf,
    dmarc,
    dkim: { selectors: dkimSelectors, note: dkimSelectors.length ? `Found ${dkimSelectors.length} DKIM selector(s) from a list of common names.` : "No common DKIM selectors answered (custom selectors may still exist)." },
    mtaSts: { present: false, note: "" },
    dnssec: { signed: dnssec, note: dnssec ? "DNS answers for this domain are signed." : "DNS answers are not cryptographically signed (DNSSEC off)." },
    provider,
  };
}

export function detectServices(txt: string[]): { name: string; evidence: string }[] {
  const out = new Map<string, string>();
  for (const t of txt) for (const [re, name] of TXT_SERVICES) if (re.test(t) && !out.has(name)) out.set(name, t.length > 80 ? t.slice(0, 77) + "…" : t);
  return [...out].map(([name, evidence]) => ({ name, evidence }));
}

function findings(d: DnsData): Finding[] {
  const f: Finding[] = [];
  if (d.mail.spf.verdict === "missing")
    f.push({ severity: "medium", title: "No SPF record", detail: d.mail.spf.note, recommendation: "Publish an SPF record listing your legitimate senders, ending in -all or ~all." });
  else if (d.mail.spf.verdict === "weak")
    f.push({ severity: "low", title: `Weak SPF policy (${d.mail.spf.policy})`, detail: d.mail.spf.note, evidence: d.mail.spf.record ?? undefined, recommendation: "Use -all once every legitimate sender is listed." });
  if (d.mail.dmarc.verdict === "missing")
    f.push({ severity: "medium", title: "No DMARC record", detail: d.mail.dmarc.note, recommendation: "Publish _dmarc with p=quarantine or p=reject after reviewing reports." });
  else if (d.mail.dmarc.verdict === "weak")
    f.push({ severity: "medium", title: "DMARC policy is p=none", detail: d.mail.dmarc.note, evidence: d.mail.dmarc.record ?? undefined, recommendation: "Move to p=quarantine then p=reject." });
  if (d.counts.MX && !d.mail.dnssec.signed)
    f.push({ severity: "low", title: "DNSSEC not enabled", detail: d.mail.dnssec.note, recommendation: "Enable DNSSEC at your DNS provider and add a DS record at the registrar." });
  return f;
}

export async function runDns(t: ParsedTarget): Promise<ModuleOutput<DnsData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("DNS Records needs a domain. Use Reverse DNS for IP addresses.");
  const domain = t.host;
  const warnings: string[] = [];

  const results = await Promise.all(RR_TYPES.map((ty) => doh(domain, ty).catch((e) => ({ status: -1, records: [] as DnsRecord[], err: e }))));
  if (results.every((r) => (r as { status: number }).status === -1)) throw new UserError("Could not reach any DNS resolver.", "dns_failed");
  const dmarc = await doh(`_dmarc.${domain}`, "TXT").catch(() => ({ status: -1, records: [] as DnsRecord[] }));
  const dsRec = await doh(domain, "SOA").catch(() => null); // SOA presence sanity

  const records = results.flatMap((r) => r.records);
  const nxdomain = results.some((r) => (r as { status: number }).status === 3) && records.length === 0;
  if (nxdomain) throw new UserError(`${domain} does not exist (NXDOMAIN).`, "nxdomain");

  const counts: DnsData["counts"] = {};
  for (const r of records) counts[r.type] = (counts[r.type] ?? 0) + 1;
  const txt = records.filter((r) => r.type === "TXT").map((r) => r.value);
  const mx = records.filter((r) => r.type === "MX").sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0));

  // DKIM selectors (best effort, capped)
  const dkimSelectors: string[] = [];
  await Promise.all(
    COMMON_DKIM.map(async (sel) => {
      const r = await doh(`${sel}._domainkey.${domain}`, "TXT").catch(() => null);
      if (r && r.records.some((x) => /v=DKIM1|k=rsa|p=/i.test(x.value))) dkimSelectors.push(sel);
    }),
  );

  // MTA-STS and DNSSEC
  const [mtaSts, dnssec] = await Promise.all([
    doh(`_mta-sts.${domain}`, "TXT").then((r) => r.records.some((x) => /v=STSv1/i.test(x.value))).catch(() => false),
    doh(domain, "DNSKEY" as RRType).then((r) => r.records.length > 0).catch(() => false),
  ]);

  const mail = analyzeMail(txt, dmarc.records.map((r) => r.value), mx, dkimSelectors.sort(), dnssec);
  mail.mtaSts = { present: mtaSts, note: mtaSts ? "MTA-STS policy published." : "No MTA-STS policy (inbound mail can be downgraded to plaintext)." };
  if (dmarc.status === -1) warnings.push("DMARC lookup failed; DMARC result may be incomplete.");

  const data: DnsData = { domain, nxdomain: false, records, counts, mail, services: detectServices(txt) };
  const summary = `${records.length} records · SPF ${mail.spf.verdict} · DMARC ${mail.dmarc.policy}${mail.provider ? ` · ${mail.provider}` : ""}`;
  void dsRec;
  return { summary, findings: findings(data), data, warnings };
}
