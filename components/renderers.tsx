"use client";
import type { ModuleId } from "@/lib/modules-config";
import type { ModuleOutput } from "@/lib/types";
import { Card, Stat, KeyValue, DataTable, Badge, CopyBtn, type Column } from "./ui";
import { ExportBar } from "./ExportBar";

import type { SubData, SubEntry } from "@/lib/modules/subdomains";
import type { DnsData } from "@/lib/modules/dns";
import type { WhoisData } from "@/lib/modules/whois";
import type { CtData } from "@/lib/modules/ct";
import type { ReverseDnsData, ReverseIpData, GeoData } from "@/lib/modules/network";
import type { CloudData } from "@/lib/modules/cloud";
import type { RelatedData } from "@/lib/modules/related";
import type { TypoData } from "@/lib/modules/typosquatting";
import type { DorkData } from "@/lib/modules/dorks";
import type { OsintData } from "@/lib/modules/osint";
import type { EmailData } from "@/lib/modules/emails";
import type { HttpData } from "@/lib/modules/http";
import type { WafData } from "@/lib/modules/waf";
import type { JsData } from "@/lib/modules/js";
import type { DirData } from "@/lib/modules/dirs";
import type { ExposureData } from "@/lib/modules/exposure";
import type { OriginData } from "@/lib/modules/origin";

function statusBadge(status: number | null | undefined) {
  if (status == null) return <Badge>—</Badge>;
  const k = status >= 500 ? "bad" : status >= 400 ? "warn" : status >= 300 ? "info" : "ok";
  return <Badge kind={k}>{status}</Badge>;
}
function bytes(n?: number) {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/* ============================ Subdomains ============================ */
function Subdomains({ d }: { d: SubData }) {
  const cols: Column<SubEntry>[] = [
    { key: "host", header: "Subdomain", render: (r) => <span className="value">{r.host}{r.takeover && <Badge kind="orange"> takeover</Badge>}</span>, value: (r) => r.host, sortable: true },
    { key: "status", header: "Status", render: (r) => (r.http ? <>{statusBadge(r.http.status)}{r.http.redirect && <div className="small muted">→ {r.http.redirect}</div>}</> : r.resolved === false ? <Badge>unresolved</Badge> : r.resolved ? (r.http === null ? <Badge kind="warn">no response</Badge> : <Badge kind="ok">resolved</Badge>) : <Badge>—</Badge>) },
    { key: "title", header: "Title", render: (r) => <span className="muted">{r.http?.title || "—"}</span> },
    { key: "ip", header: "IP / CNAME", render: (r) => <span className="muted wrap-anywhere">{r.cname ? `CNAME ${r.cname}` : r.ips.join(", ") || "—"}</span> },
    { key: "server", header: "Server", render: (r) => <span className="muted">{r.http?.server || "—"}</span> },
    { key: "sources", header: "Sources", render: (r) => <span className="muted small">{r.sources.join(", ")}</span> },
  ];
  const s = d.stats;
  return (
    <div className="stack">
      <div className="grid grid-4">
        <Stat label="Subdomains" value={s.total} sub={`${s.resolved} resolved`} accent="silver" />
        <Stat label="Live HTTP" value={s.live} sub={`${s.ok200} return 200`} accent="green" />
        <Stat label="Unique IPs" value={new Set(d.entries.flatMap((e) => e.ips)).size} accent="blue" />
        <Stat label="Takeover candidates" value={s.takeover} accent="orange" />
      </div>
      <Card title="Subdomains" count={s.total} actions={<ExportBar baseName={`subdomains_${d.domain}`} rows={d.entries.map((e) => ({ host: e.host, status: e.http?.status ?? "", title: e.http?.title ?? "", ip: e.ips.join(" "), cname: e.cname ?? "", takeover: e.takeover?.service ?? "", sources: e.sources.join(" ") }))} json={d} text={d.entries.map((e) => e.host).join("\n")} />} pad={false}>
        <DataTable rows={d.entries} columns={cols} filterKeys={(r) => `${r.host} ${r.ips.join(" ")} ${r.http?.title ?? ""} ${r.http?.server ?? ""}`} />
      </Card>
    </div>
  );
}

/* ============================ DNS ============================ */
function Dns({ d }: { d: DnsData }) {
  const m = d.mail;
  const mailCard = (name: string, verdict: string, value: string | null, note: string) => (
    <Card title={name} actions={<Badge kind={verdict === "good" ? "ok" : verdict === "fair" ? "warn" : verdict === "missing" ? "bad" : "info"}>{verdict}</Badge>} key={name}>
      {value ? <div className="hl" style={{ marginBottom: 8 }}>{value}</div> : null}
      <div className="muted small">{note}</div>
    </Card>
  );
  const cols: Column<{ type: string; name: string; value: string; ttl: number; priority?: number }>[] = [
    { key: "type", header: "Type", render: (r) => <Badge kind="info">{r.type}</Badge> },
    { key: "name", header: "Name", render: (r) => <span className="muted">{r.name}</span> },
    { key: "value", header: "Value", render: (r) => <span className="value wrap-anywhere">{r.priority != null ? `${r.priority} ` : ""}{r.value}</span> },
    { key: "ttl", header: "TTL", num: true, render: (r) => <span className="muted">{r.ttl}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-3">
        {mailCard("SPF", m.spf.verdict, m.spf.record, `${m.spf.policy} — ${m.spf.note}`)}
        {mailCard("DMARC", m.dmarc.verdict, m.dmarc.record, `${m.dmarc.policy} — ${m.dmarc.note}`)}
        <Card title="DKIM / MTA-STS / DNSSEC">
          <KeyValue rows={[["DKIM selectors", m.dkim.selectors.join(", ") || "none found"], ["MTA-STS", m.mtaSts.present ? "present" : "not set"], ["DNSSEC", m.dnssec.signed ? "signed" : "unsigned"], ["Mail provider", m.provider ?? "—"]]} />
        </Card>
      </div>
      <Card title="Records" count={d.records.length} actions={<ExportBar baseName={`dns_${d.domain}`} rows={d.records.map((r) => ({ type: r.type, name: r.name, value: r.value, ttl: r.ttl, priority: r.priority ?? "" }))} json={d} />} pad={false}>
        <DataTable rows={d.records} columns={cols} filterKeys={(r) => `${r.type} ${r.value}`} />
      </Card>
      {d.services.length > 0 && (
        <Card title="Services identified from TXT records" count={d.services.length} pad={false}>
          {d.services.map((s, i) => (
            <div key={i} className="list-item">
              <b style={{ width: 220, flexShrink: 0 }}>{s.name}</b>
              <span className="muted small wrap-anywhere">{s.evidence}</span>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}

/* ============================ WHOIS ============================ */
function Whois({ d }: { d: WhoisData }) {
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Card title={d.kind === "domain" ? "Registration" : "Network"} actions={<Badge kind="info">{d.source}</Badge>}>
          {d.kind === "domain" ? (
            <KeyValue rows={[["Domain", d.name], ["Registrar", d.registrar], ["Age", d.ageYears != null ? `${d.ageYears} years` : null], ["Expires in", d.expiresInDays != null ? `${d.expiresInDays} days` : null], ["DNSSEC", d.dnssec == null ? null : d.dnssec ? "signed" : "unsigned"], ["Abuse email", d.abuseEmail]]} />
          ) : (
            <KeyValue rows={[["Range", d.network?.range], ["CIDR", d.network?.cidr], ["Type", d.network?.type], ["Organisation", d.network?.org], ["Country", d.network?.country], ["Abuse email", d.abuseEmail]]} />
          )}
        </Card>
        <Card title="Dates & status">
          <KeyValue rows={[...d.events.map((e) => [e.label, e.date] as [string, React.ReactNode]), ["Status", d.statuses.length ? <span style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>{d.statuses.map((s, i) => <Badge key={i}>{s}</Badge>)}</span> : null], ["Name servers", d.nameservers.length ? d.nameservers.join(", ") : null]]} />
        </Card>
      </div>
      {d.contacts.length > 0 && (
        <Card title="Contacts" count={d.contacts.length} pad={false}>
          {d.contacts.map((c, i) => (
            <div key={i} className="list-item">
              <div className="li-main">
                <div className="value">{c.name || c.org || "(no name)"} {c.roles.map((r) => <Badge key={r}>{r}</Badge>)}</div>
                <div className="muted small">{[c.org, c.email, c.country].filter(Boolean).join(" · ")}</div>
              </div>
            </div>
          ))}
        </Card>
      )}
      {d.fields.length > 0 && (
        <Card title="Raw fields" count={d.fields.length}>
          <KeyValue rows={d.fields.map((f) => [f.label, <span key={f.label} className="wrap-anywhere">{f.value}</span>] as [string, React.ReactNode])} />
        </Card>
      )}
    </div>
  );
}

/* ============================ Certificate Transparency ============================ */
function Ct({ d }: { d: CtData }) {
  const cols: Column<CtData["certs"][number]>[] = [
    { key: "commonName", header: "Common name", render: (r) => <span className="value">{r.commonName}{r.wildcard && <Badge kind="info"> wildcard</Badge>}</span> },
    { key: "issuer", header: "Issuer", render: (r) => <span className="muted">{r.issuer}</span> },
    { key: "nameCount", header: "Names", num: true, render: (r) => r.nameCount },
    { key: "notBefore", header: "Issued", render: (r) => <span className="muted small">{r.notBefore.slice(0, 10)}</span>, value: (r) => r.notBefore, sortable: true },
    { key: "notAfter", header: "Expires", render: (r) => <span className="muted small">{r.notAfter.slice(0, 10)}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-3">
        <Stat label="Certificates" value={d.total} accent="silver" />
        <Stat label="Issuers" value={d.issuers.length} sub={d.issuers[0]?.name} accent="blue" />
        <Stat label="Unique names (SANs)" value={d.sans.length} accent="green" />
      </div>
      <Card title="Names on certificates" count={d.sans.length} actions={<CopyBtn text={d.sans.join("\n")} label="Copy names" />} pad={false}>
        <div className="card-body" style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {d.sans.slice(0, 300).map((s) => <span key={s} className="chip">{s}</span>)}
        </div>
      </Card>
      <Card title="Certificates" count={d.total} actions={<ExportBar baseName={`ct_${d.domain}`} rows={d.certs} json={d} />} pad={false}>
        <DataTable rows={d.certs} columns={cols} filterKeys={(r) => `${r.commonName} ${r.issuer}`} />
      </Card>
    </div>
  );
}

/* ============================ Reverse DNS ============================ */
function ReverseDns({ d }: { d: ReverseDnsData }) {
  const cols: Column<ReverseDnsData["entries"][number]>[] = [
    { key: "ip", header: "IP", render: (r) => <span className="value">{r.ip}</span> },
    { key: "hostnames", header: "PTR hostnames", render: (r) => <span className="wrap-anywhere">{r.hostnames.join(", ") || <span className="muted">—</span>}</span> },
  ];
  return (
    <Card title="Reverse DNS" count={d.entries.length} actions={<ExportBar baseName="reverse_dns" rows={d.entries.map((e) => ({ ip: e.ip, hostnames: e.hostnames.join(" ") }))} json={d} />} pad={false}>
      <DataTable rows={d.entries} columns={cols} filterKeys={(r) => `${r.ip} ${r.hostnames.join(" ")}`} />
    </Card>
  );
}

/* ============================ Reverse IP ============================ */
function ReverseIp({ d }: { d: ReverseIpData }) {
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Stat label="Domains found" value={d.total} accent="blue" />
        <Stat label="IP addresses" value={d.byIp.length} accent="silver" />
      </div>
      {d.byIp.map((g) => (
        <Card key={g.ip} title={g.ip} count={g.domains.length} actions={<CopyBtn text={g.domains.join("\n")} />} pad={false}>
          <div className="card-body" style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {g.domains.length ? g.domains.map((dom) => <span key={dom} className="chip">{dom}</span>) : <span className="muted">No domains found.</span>}
          </div>
        </Card>
      ))}
    </div>
  );
}

/* ============================ GeoIP & ASN ============================ */
function Geo({ d }: { d: GeoData }) {
  const first = d.entries[0];
  return (
    <div className="stack">
      {first?.latitude != null && first.longitude != null && (
        <Card title={`${[first.city, first.region, first.country].filter(Boolean).join(", ")}`} pad={false}>
          <iframe className="map-embed" title="map" loading="lazy" src={`https://www.openstreetmap.org/export/embed.html?bbox=${first.longitude - 0.1}%2C${first.latitude - 0.1}%2C${first.longitude + 0.1}%2C${first.latitude + 0.1}&layer=mapnik&marker=${first.latitude}%2C${first.longitude}`} />
        </Card>
      )}
      <div className="grid grid-2">
        {d.entries.map((e) => (
          <Card key={e.ip} title={e.ip}>
            <KeyValue rows={[["Country", [e.city, e.region, e.country].filter(Boolean).join(", ")], ["ASN", e.asn ? `AS${e.asn}` : null], ["Organisation", e.org], ["ISP", e.isp]]} />
          </Card>
        ))}
      </div>
      {d.asns.map((a) => (
        <Card key={a.asn} title={`AS${a.asn}${a.holder ? ` · ${a.holder}` : ""}`} count={`${a.prefixCount ?? a.prefixes.length} prefixes`} actions={<CopyBtn text={a.prefixes.join("\n")} label="Copy prefixes" />} pad={false}>
          <div className="card-body" style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {a.prefixes.slice(0, 200).map((p) => <span key={p} className="chip mono">{p}</span>)}
          </div>
        </Card>
      ))}
    </div>
  );
}

/* ============================ Cloud ============================ */
function Cloud({ d }: { d: CloudData }) {
  const cols: Column<CloudData["hits"][number]>[] = [
    { key: "ip", header: "IP", render: (r) => <span className="value">{r.ip}</span> },
    { key: "provider", header: "Provider", render: (r) => <Badge kind={r.provider.includes("Unknown") ? undefined : "info"}>{r.provider}</Badge> },
    { key: "detail", header: "Detail", render: (r) => <span className="muted">{r.detail || "—"}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Stat label="Providers" value={d.providers.join(", ")} accent="blue" />
        <Stat label="IP addresses" value={d.hits.length} accent="silver" />
      </div>
      <Card title="IP to provider" count={d.hits.length} actions={<ExportBar baseName="cloud_mapping" rows={d.hits} json={d} />} pad={false}>
        <DataTable rows={d.hits} columns={cols} filterKeys={(r) => `${r.ip} ${r.provider} ${r.detail ?? ""}`} />
      </Card>
    </div>
  );
}

/* ============================ Related ============================ */
function Related({ d }: { d: RelatedData }) {
  const cols: Column<RelatedData["related"][number]>[] = [
    { key: "domain", header: "Domain", render: (r) => <span className="value">{r.domain}</span>, value: (r) => r.domain, sortable: true },
    { key: "links", header: "Linked by", render: (r) => <span className="muted">{r.links.join(", ")}</span> },
  ];
  return (
    <Card title="Related domains" count={d.related.length} actions={<ExportBar baseName={`related_${d.domain}`} rows={d.related.map((r) => ({ domain: r.domain, links: r.links.join(" ") }))} json={d} text={d.related.map((r) => r.domain).join("\n")} />} pad={false}>
      <DataTable rows={d.related} columns={cols} filterKeys={(r) => `${r.domain} ${r.links.join(" ")}`} empty="No related domains found from passive sources." />
    </Card>
  );
}

/* ============================ Typosquatting ============================ */
function Typo({ d }: { d: TypoData }) {
  const cols: Column<TypoData["entries"][number]>[] = [
    { key: "domain", header: "Domain", render: (r) => <span className="value">{r.domain}</span>, value: (r) => r.domain, sortable: true },
    { key: "kind", header: "Technique", render: (r) => <Badge>{r.kind}</Badge> },
    { key: "hasMx", header: "Email", render: (r) => (r.hasMx ? <Badge kind="orange">MX</Badge> : <span className="muted">—</span>) },
    { key: "ip", header: "IP", render: (r) => <span className="muted">{r.ip || "—"}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-3">
        <Stat label="Permutations checked" value={d.checked} accent="silver" />
        <Stat label="Registered" value={d.entries.length} accent="blue" />
        <Stat label="Can receive email" value={d.entries.filter((e) => e.hasMx).length} accent="orange" />
      </div>
      <Card title="Registered lookalikes" count={d.entries.length} actions={<ExportBar baseName={`typosquatting_${d.base}`} rows={d.entries} json={d} />} pad={false}>
        <DataTable rows={d.entries} columns={cols} filterKeys={(r) => `${r.domain} ${r.kind}`} />
      </Card>
    </div>
  );
}

/* ============================ Dorks ============================ */
function Dorks({ d }: { d: DorkData }) {
  return (
    <div className="stack">
      {d.categories.map((c) => (
        <Card key={c.name} title={c.name} count={c.dorks.length} pad={false}>
          {c.dorks.map((dk, i) => (
            <div key={i} className="list-item">
              <div className="li-main">
                <div className="hl">{dk.query}</div>
                <div className="muted small" style={{ marginTop: 4 }}>{dk.note}</div>
              </div>
              <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                <a className="btn btn-sm" href={dk.google} target="_blank" rel="noreferrer noopener">Google</a>
                <a className="btn btn-sm" href={dk.bing} target="_blank" rel="noreferrer noopener">Bing</a>
                <a className="btn btn-sm" href={dk.duckduckgo} target="_blank" rel="noreferrer noopener">DDG</a>
                <CopyBtn text={dk.query} label="" />
              </div>
            </div>
          ))}
        </Card>
      ))}
    </div>
  );
}

/* ============================ OSINT ============================ */
function Osint({ d }: { d: OsintData }) {
  if (d.mode === "keywords") {
    return (
      <Card title="Keyword matches" count={d.keywordMatches.filter((k) => k.urls.length).length} pad={false}>
        {d.keywordMatches.map((k) => (
          <div key={k.keyword} className="list-item">
            <b style={{ width: 160 }}>{k.keyword}</b>
            <span className="muted small wrap-anywhere">{k.urls.length ? k.urls.join(", ") : "no matches"}</span>
          </div>
        ))}
      </Card>
    );
  }
  const Group = ({ title, items }: { title: string; items: { value: string; sources: string[]; label?: string }[] }) =>
    items.length ? (
      <Card title={title} count={items.length} pad={false}>
        {items.map((it, i) => (
          <div key={i} className="list-item">
            {it.label && <span className="badge orange" style={{ width: 90, flexShrink: 0, justifyContent: "center" }}>{it.label}</span>}
            <div className="li-main">
              <div className="value wrap-anywhere">{it.value}</div>
              <div className="muted small">{it.sources.length} page(s)</div>
            </div>
          </div>
        ))}
      </Card>
    ) : null;
  return (
    <div className="stack">
      <div className="grid grid-4">
        <Stat label="Emails" value={d.stats.emails} accent="blue" />
        <Stat label="Social links" value={d.stats.social} accent="orange" />
        <Stat label="Phone numbers" value={d.stats.phones} accent="green" />
        <Stat label="Pages crawled" value={d.stats.pages} accent="silver" />
      </div>
      <Group title="Email addresses" items={d.emails} />
      <Group title="Social media links" items={d.social.map((s) => ({ ...s, label: s.label }))} />
      <Group title="Phone numbers" items={d.phones} />
      <Group title="Page authors" items={d.authors} />
      <Group title="Geolocations" items={d.geolocations} />
      <Group title="Usernames" items={d.usernames} />
    </div>
  );
}

/* ============================ Email Harvester ============================ */
function Emails({ d }: { d: EmailData }) {
  const cols: Column<EmailData["entries"][number]>[] = [
    { key: "email", header: "Email", render: (r) => <span className="value wrap-anywhere">{r.email}</span>, value: (r) => r.email, sortable: true },
    { key: "name", header: "Name / role", render: (r) => <span className="muted">{r.name || "—"}</span> },
    { key: "type", header: "Type", render: (r) => <Badge kind={r.type === "found" ? "ok" : r.type === "generated" ? "orange" : undefined}>{r.type}</Badge> },
    { key: "source", header: "Source", render: (r) => <span className="muted small">{r.source}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-4">
        <Stat label="Addresses" value={d.entries.length} accent="green" />
        <Stat label="Pattern" value={d.pattern ? `${d.pattern.replace("{first}", "first").replace("{last}", "last").replace("{f}", "f").replace("{l}", "l")}@` : "—"} sub={d.pattern ? `${d.patternConfidence}% confidence` : undefined} accent="blue" />
        <Stat label="Generated" value={d.stats.generated} accent="orange" />
        <Stat label="Role mailboxes" value={d.stats.role} accent="silver" />
      </div>
      <Card title="Addresses" count={d.entries.length} actions={<ExportBar baseName={`emails_${d.domain}`} rows={d.entries} json={d} text={d.entries.map((e) => e.email).join("\n")} />} pad={false}>
        <DataTable rows={d.entries} columns={cols} filterKeys={(r) => `${r.email} ${r.name ?? ""}`} />
      </Card>
      <p className="muted small">Generated addresses are inferred from the detected pattern and names on the site; they are not verified to exist. Use for authorized security awareness and recon only.</p>
    </div>
  );
}

/* ============================ HTTP Fingerprint ============================ */
function Http({ d }: { d: HttpData }) {
  const Scheme = ({ s }: { s: HttpData["https"] }) => (
    <Card title={s.scheme.toUpperCase()} actions={s.status ? statusBadge(s.status) : <Badge kind="bad">down</Badge>}>
      {s.error ? (
        <div className="muted">{s.error}</div>
      ) : (
        <KeyValue rows={[["Title", s.title || "—"], ["Server", s.server], ["Final URL", s.finalUrl], ["Size", bytes(s.contentLength)], ["Redirects", s.redirectChain.length ? s.redirectChain.map((r) => `${r.status} ${r.url}`).join(" → ") : null], ["Technologies", s.tech.length ? <span style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>{s.tech.map((t) => <Badge key={t}>{t}</Badge>)}</span> : null], ["WAF/CDN", s.waf.length ? s.waf.map((w) => w.name).join(", ") : null]]} />
      )}
    </Card>
  );
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Scheme s={d.https} />
        <Scheme s={d.http} />
      </div>
      {d.tls && (
        <Card title="TLS certificate" actions={<Badge kind={d.tls.authorized ? "ok" : "bad"}>{d.tls.authorized ? "trusted" : "not trusted"}</Badge>}>
          <KeyValue rows={[["Protocol", d.tls.protocol], ["Issuer", d.tls.issuer], ["Subject", d.tls.subject], ["Valid to", d.tls.validTo?.slice(0, 10)], ["Days left", d.tls.daysLeft], ["SANs", d.tls.san?.length ? `${d.tls.san.length} names` : null]]} />
        </Card>
      )}
      {d.headers.length > 0 && (
        <Card title="Response headers" count={d.headers.length}>
          <KeyValue rows={d.headers.map((h) => [h.name, <span key={h.name} className="wrap-anywhere mono small">{h.value}</span>] as [string, React.ReactNode])} />
        </Card>
      )}
    </div>
  );
}

/* ============================ WAF ============================ */
function Waf({ d }: { d: WafData }) {
  return (
    <div className="stack">
      <Card title="Detection" actions={d.primary ? <Badge kind="ok">{d.primary.confidence} confidence</Badge> : <Badge>none</Badge>}>
        {d.primary ? (
          <>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <span style={{ fontSize: 22, fontWeight: 700 }}>{d.primary.name}</span>
              <Badge kind="orange">{d.primary.kind}</Badge>
            </div>
            <KeyValue rows={d.primary.evidence.map((e) => [e.kind, <span key={e.value} className="mono small wrap-anywhere">{e.value}</span>] as [string, React.ReactNode])} />
          </>
        ) : (
          <div className="muted">No WAF or CDN signature matched. Server responded with HTTP {d.status}.</div>
        )}
      </Card>
      {d.matches.length > 1 && (
        <Card title="Other matches" count={d.matches.length - 1} pad={false}>
          {d.matches.slice(1).map((m) => (
            <div key={m.name} className="list-item">
              <b style={{ width: 200 }}>{m.name}</b>
              <Badge>{m.kind}</Badge>
              <span className="muted small wrap-anywhere" style={{ marginLeft: 8 }}>{m.evidence.map((e) => e.value).join(" · ")}</span>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}

/* ============================ JS Crawler ============================ */
function Js({ d }: { d: JsData }) {
  const fileCols: Column<JsData["files"][number]>[] = [
    { key: "url", header: "JS file", render: (r) => <span className="value wrap-anywhere">{r.url}{r.map && <Badge kind="info"> .map</Badge>}</span> },
    { key: "origin", header: "Origin", render: (r) => <Badge kind={r.origin === "first-party" ? "info" : undefined}>{r.origin}</Badge> },
    { key: "status", header: "Status", render: (r) => statusBadge(r.status) },
    { key: "size", header: "Size", num: true, render: (r) => bytes(r.size) },
    { key: "endpoints", header: "Endpoints", num: true, render: (r) => r.endpoints, value: (r) => r.endpoints, sortable: true },
    { key: "foundOn", header: "Found on", render: (r) => <span className="muted small">{r.foundOn}</span> },
  ];
  const epCols: Column<JsData["endpoints"][number]>[] = [
    { key: "value", header: "Endpoint", render: (r) => <span className="value wrap-anywhere">{r.value}</span> },
    { key: "type", header: "Type", render: (r) => <Badge>{r.type}</Badge> },
    { key: "file", header: "Found in", render: (r) => <span className="muted small">{r.file}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-4">
        <Stat label="Pages crawled" value={d.pages} accent="silver" />
        <Stat label="JS files" value={d.stats.files} sub={`${d.stats.firstParty} first-party`} accent="blue" />
        <Stat label="Endpoints" value={d.stats.endpoints} accent="green" />
        <Stat label="Possible secrets" value={d.stats.secrets} accent="orange" />
      </div>
      {d.secrets.length > 0 && (
        <Card title="Possible secrets" count={d.secrets.length} pad={false}>
          {d.secrets.map((s, i) => (
            <div key={i} className="check-row" style={{ gridTemplateColumns: "170px minmax(0,1fr) auto" }}>
              <b>{s.kind}</b>
              <div><div className="hl">{s.masked}</div><div className="muted small" style={{ marginTop: 4 }}>{s.file}</div></div>
              <Badge kind={s.confidence.startsWith("Low") ? undefined : "orange"}>{s.confidence}</Badge>
            </div>
          ))}
          <div className="card-body muted small">Matches are pattern-based and need manual verification; many public keys (map, analytics) are meant to be exposed.</div>
        </Card>
      )}
      <Card title="Endpoints in JS" count={d.endpoints.length} actions={<ExportBar baseName="js_endpoints" rows={d.endpoints} json={d.endpoints} text={d.endpoints.map((e) => e.value).join("\n")} />} pad={false}>
        <DataTable rows={d.endpoints} columns={epCols} filterKeys={(r) => `${r.value} ${r.type} ${r.file}`} />
      </Card>
      <Card title="JS files" count={d.files.length} actions={<ExportBar baseName="js_files" rows={d.files} json={d.files} text={d.files.map((f) => f.url).join("\n")} />} pad={false}>
        <DataTable rows={d.files} columns={fileCols} filterKeys={(r) => r.url} />
      </Card>
    </div>
  );
}

/* ============================ Directory & Admin Finder ============================ */
function Dirs({ d }: { d: DirData }) {
  const cols: Column<DirData["hits"][number]>[] = [
    { key: "path", header: "Path", render: (r) => <span className="value wrap-anywhere">{r.path}{r.admin && <Badge kind="orange"> admin</Badge>}</span> },
    { key: "status", header: "Status", render: (r) => statusBadge(r.status) },
    { key: "size", header: "Size", num: true, render: (r) => bytes(r.size) },
    { key: "title", header: "Title / redirect", render: (r) => <span className="muted">{r.redirect ? `→ ${r.redirect}` : r.title || "—"}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-4">
        <Stat label="Paths tested" value={d.tested} accent="silver" />
        <Stat label="Found" value={d.stats.found} sub={`${d.stats.s2} ok · ${d.stats.s3} redirect · ${d.stats.s4} 4xx`} accent="blue" />
        <Stat label="Admin / login" value={d.stats.admin} accent="orange" />
        <Stat label="Server errors" value={d.stats.s5} accent="silver" />
      </div>
      {d.admins.length > 0 && (
        <Card title="Login / admin panels" count={d.admins.length} actions={<CopyBtn text={d.admins.map((a) => a.url).join("\n")} />} pad={false}>
          {d.admins.map((a) => (
            <div key={a.url} className="list-item">
              {statusBadge(a.status)}
              <a className="value-link wrap-anywhere" href={a.url} target="_blank" rel="noreferrer noopener">{a.url}</a>
              <span className="muted small" style={{ marginLeft: "auto" }}>{a.title}</span>
            </div>
          ))}
        </Card>
      )}
      <Card title="All paths" count={d.hits.length} actions={<ExportBar baseName="directories" rows={d.hits} json={d} text={d.hits.map((h) => h.url).join("\n")} />} pad={false}>
        <DataTable rows={d.hits} columns={cols} filterKeys={(r) => `${r.path} ${r.title}`} />
      </Card>
    </div>
  );
}

/* ============================ Exposure ============================ */
function Exposure({ d }: { d: ExposureData }) {
  const color = d.grade.startsWith("A") ? "var(--ok)" : d.grade === "B" ? "var(--brand-blue)" : d.grade === "C" ? "var(--warn)" : "var(--bad)";
  const byCat = new Map<string, ExposureData["checks"]>();
  for (const c of d.checks) byCat.set(c.category, [...(byCat.get(c.category) ?? []), c]);
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Card>
          <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
            <div className="grade-badge" style={{ border: `8px solid ${color}` }}>
              <div><div style={{ fontSize: 32, fontWeight: 800, color }}>{d.grade}</div><div className="muted small">{d.score}/100</div></div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, marginBottom: 8 }}>Security posture</div>
              <KeyValue rows={[["Failed", d.checks.filter((c) => c.status === "fail").length], ["Warnings", d.checks.filter((c) => c.status === "warn").length], ["Passed", d.checks.filter((c) => c.status === "pass").length]]} />
            </div>
          </div>
        </Card>
        <Card title="Technologies" count={d.technologies.length}>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>{d.technologies.length ? d.technologies.map((t) => <span key={t} className="chip">{t}</span>) : <span className="muted">None detected.</span>}</div>
        </Card>
      </div>
      {[...byCat.entries()].map(([cat, checks]) => (
        <Card key={cat} title={cat} count={checks.length} pad={false}>
          {checks.map((c, i) => (
            <div key={i} className="check-row">
              <Badge kind={c.status === "fail" ? "bad" : c.status === "warn" ? "warn" : c.status === "pass" ? "ok" : "info"}>{c.status === "pass" ? "✓" : c.status === "info" ? "i" : "!"}</Badge>
              <div>
                <div className="cr-title">{c.title}</div>
                <div className="cr-detail">{c.detail}</div>
                {c.evidence && <div className="cr-value wrap-anywhere">{c.evidence}</div>}
                {c.recommendation && <div className="cr-rec"><b>Fix:</b> {c.recommendation}</div>}
              </div>
              <span />
            </div>
          ))}
        </Card>
      ))}
      {d.robots && d.robots.disallow.length > 0 && (
        <Card title="robots.txt — disallowed paths" count={d.robots.disallow.length} pad={false}>
          <div className="card-body" style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>{d.robots.disallow.map((p) => <span key={p} className="chip mono">{p}</span>)}</div>
        </Card>
      )}
    </div>
  );
}

/* ============================ Origin IP Finder ============================ */
function Origin({ d }: { d: OriginData }) {
  const vk: Record<string, "ok" | "orange" | "warn" | "info" | "bad" | undefined> = { confirmed: "ok", likely: "orange", possible: "warn", "no-match": undefined, unreachable: undefined, cdn: "info" };
  const cols: Column<OriginData["candidates"][number]>[] = [
    { key: "ip", header: "IP", render: (r) => <span className="value mono">{r.ip}</span> },
    { key: "verdict", header: "Verdict", render: (r) => <Badge kind={vk[r.verdict]}>{r.verdict}</Badge> },
    { key: "detail", header: "Detail", render: (r) => <span className="muted small">{r.detail}</span> },
    { key: "sources", header: "Seen in", render: (r) => <span className="muted small wrap-anywhere">{r.sources.slice(0, 3).join(", ")}{r.sources.length > 3 ? "…" : ""}</span> },
  ];
  return (
    <div className="stack">
      <div className="grid grid-3">
        <Stat label="Fronted by" value={d.frontedBy ?? "No CDN detected"} accent={d.frontedBy ? "orange" : "silver"} />
        <Stat label="Candidate IPs" value={d.candidates.length} accent="silver" />
        <Stat label="Confirmed / likely origin" value={d.confirmed.length} accent={d.confirmed.length ? "green" : "silver"} />
      </div>
      {d.confirmed.length > 0 && (
        <Card title="Likely origin IPs" count={d.confirmed.length} actions={<CopyBtn text={d.confirmed.map((c) => c.ip).join("\n")} />} pad={false}>
          {d.confirmed.map((c) => (
            <div key={c.ip} className="list-item">
              <Badge kind={c.verdict === "confirmed" ? "ok" : "orange"}>{c.verdict}</Badge>
              <span className="value mono">{c.ip}</span>
              <span className="muted small" style={{ marginLeft: 8 }}>{c.detail}</span>
            </div>
          ))}
        </Card>
      )}
      <Card title="All candidates" count={d.candidates.length} actions={<ExportBar baseName={`origin_${d.domain}`} rows={d.candidates.map((c) => ({ ip: c.ip, verdict: c.verdict, sources: c.sources.join(" "), detail: c.detail }))} json={d} />} pad={false}>
        <DataTable rows={d.candidates} columns={cols} filterKeys={(r) => `${r.ip} ${r.verdict} ${r.sources.join(" ")}`} empty="No candidate IPs found in public records." />
      </Card>
    </div>
  );
}

/* ============================ Dispatch ============================ */
export function renderModule(id: ModuleId, output: ModuleOutput): React.ReactNode {
  const data = output.data as never;
  switch (id) {
    case "subdomains": return <Subdomains d={data} />;
    case "dns": return <Dns d={data} />;
    case "whois": return <Whois d={data} />;
    case "ct": return <Ct d={data} />;
    case "reverse-dns": return <ReverseDns d={data} />;
    case "reverse-ip": return <ReverseIp d={data} />;
    case "geoip": return <Geo d={data} />;
    case "cloud": return <Cloud d={data} />;
    case "related": return <Related d={data} />;
    case "typosquatting": return <Typo d={data} />;
    case "dorks": return <Dorks d={data} />;
    case "osint": return <Osint d={data} />;
    case "emails": return <Emails d={data} />;
    case "http": return <Http d={data} />;
    case "waf": return <Waf d={data} />;
    case "js": return <Js d={data} />;
    case "dirs": return <Dirs d={data} />;
    case "exposure": return <Exposure d={data} />;
    case "origin": return <Origin d={data} />;
    default: return <pre className="hl">{JSON.stringify(output.data, null, 2)}</pre>;
  }
}
