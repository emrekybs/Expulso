// Asset inventory: groups what the modules discovered into the 11 asset categories.
// Pure functions, so the Assets page, the Full Scan page and the report can share them.

export const ASSET_CATEGORIES = [
  { key: "subdomain", label: "Subdomain", hint: "Alt alan adları" },
  { key: "ip", label: "IP Address", hint: "IP varlıkları" },
  { key: "port", label: "Open Port", hint: "Açık portlar" },
  { key: "webapp", label: "Web App", hint: "Web uygulamaları" },
  { key: "path", label: "Directory / Path", hint: "Dizin ve yol keşfi" },
  { key: "admin", label: "Admin Panel", hint: "Yönetim panelleri" },
  { key: "api", label: "API Endpoint", hint: "API yüzeyi" },
  { key: "exposed", label: "Exposed Service", hint: "Dışarıya açık servisler" },
  { key: "cloud", label: "Cloud Asset", hint: "Bulut varlıkları" },
  { key: "sensitive", label: "Sensitive File", hint: "Hassas dosya izleri" },
  { key: "cert", label: "SSL / Certificate", hint: "Sertifikalar" },
] as const;

export type AssetKey = (typeof ASSET_CATEGORIES)[number]["key"];

export interface Asset {
  label: string;
  detail?: string;
  source: string;
  url?: string;
}

export type Inventory = Record<AssetKey, Asset[]>;

export interface InvModule {
  id: string;
  title?: string;
  ok: boolean;
  data?: unknown;
}

type Obj = Record<string, unknown>;
const get = (o: unknown, k: string): unknown => (o && typeof o === "object" ? (o as Obj)[k] : undefined);
const arr = (v: unknown): Obj[] => (Array.isArray(v) ? (v as Obj[]) : []);
const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

const RISKY_PORTS = new Set([21, 23, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5601, 5900, 6379, 9200, 11211, 27017]);
const SENSITIVE_PATH = /\/\.git|\.env|\.sql|\.bak|\.old|\.zip|\.tar|\.gz|\.save|\.swp|config\.php|wp-config|backup|\.DS_Store/i;
const CLOUD_CNAME = /amazonaws\.com|cloudfront\.net|azurewebsites\.net|cloudapp\.net|blob\.core\.windows\.net|googleapis\.com|appspot\.com|herokuapp\.com|netlify|vercel\.app|github\.io|s3[.-]/i;

export interface InvChild {
  host: string;
  modules: InvModule[];
}

export function buildInventory(modules: InvModule[], children: InvChild[] = []): Inventory {
  const inv: Inventory = { subdomain: [], ip: [], port: [], webapp: [], path: [], admin: [], api: [], exposed: [], cloud: [], sensitive: [], cert: [] };
  const seenIp = new Set<string>();
  const seenPort = new Set<string>();
  const addIp = (ip: string, detail: string | undefined, source: string) => {
    if (!ip || seenIp.has(ip)) return;
    seenIp.add(ip);
    inv.ip.push({ label: ip, detail, source });
  };
  const addPort = (label: string, detail: string, source: string) => {
    if (seenPort.has(label)) return;
    seenPort.add(label);
    inv.port.push({ label, detail, source });
  };

  const all: InvModule[] = [...modules, ...children.flatMap((c) => c.modules.map((m) => ({ ...m, title: `${m.title} · ${c.host}` })))];
  for (const m of all) {
    if (!m.ok) continue;
    const src = m.title ?? m.id;
    const d = m.data;

    if (m.id === "subdomains") {
      for (const e of arr(get(d, "entries"))) {
        const host = str(get(e, "host"));
        const http = get(e, "http");
        const status = get(http, "status");
        const detail = [status != null ? String(status) : "", str(get(http, "title"))].filter(Boolean).join(" · ") || (get(e, "resolved") ? "resolved" : "unresolved");
        inv.subdomain.push({ label: host, detail, source: src, url: `https://${host}` });
        for (const ip of (get(e, "ips") as string[] | undefined) ?? []) addIp(ip, `from ${host}`, src);
        const cname = str(get(e, "cname"));
        if (cname && CLOUD_CNAME.test(cname)) inv.cloud.push({ label: cname, detail: `CNAME of ${host}`, source: src });
        if (get(e, "takeover")) inv.sensitive.push({ label: `${host} → ${cname}`, detail: "possible subdomain takeover", source: src });
      }
    }

    if (m.id === "geoip") {
      for (const e of arr(get(d, "entries"))) {
        const where = [str(get(e, "org")), str(get(e, "country"))].filter(Boolean).join(" · ");
        addIp(str(get(e, "ip")), where || undefined, src);
      }
    }

    if (m.id === "ports-passive") {
      for (const h of arr(get(d, "hosts"))) {
        const ip = str(get(h, "ip"));
        addIp(ip, undefined, src);
        for (const p of arr(get(h, "ports"))) {
          const port = Number(get(p, "port"));
          const label = `${ip}:${port}`;
          inv.port.push({ label, detail: str(get(p, "label")), source: src });
          if (RISKY_PORTS.has(port)) inv.exposed.push({ label, detail: `${str(get(p, "label"))} (passive data)`, source: src });
        }
        for (const cve of (get(h, "cves") as string[] | undefined) ?? []) inv.exposed.push({ label: `${ip} · ${cve}`, detail: "CVE in passive data", source: src });
      }
    }

    if (m.id === "webtech") {
      for (const t of arr(get(d, "technologies"))) {
        const version = str(get(t, "version"));
        inv.webapp.push({ label: `${str(get(t, "name"))}${version ? ` ${version}` : ""}`, detail: str(get(t, "cat")), source: src });
      }
      for (const c of arr(get(d, "cves"))) {
        for (const id of arr(get(c, "ids"))) inv.sensitive.push({ label: `${str(get(c, "tech"))} ${str(get(c, "version"))} · ${str(get(id, "id"))}`, detail: "known vulnerability (library)", source: src });
      }
    }

    if (m.id === "dirs") {
      for (const h of arr(get(d, "hits"))) {
        const path = str(get(h, "path"));
        inv.path.push({ label: path, detail: `${str(get(h, "status"))}${get(h, "title") ? ` · ${str(get(h, "title"))}` : ""}`, source: src, url: str(get(h, "url")) });
        if (SENSITIVE_PATH.test(path) && Number(get(h, "status")) === 200) inv.sensitive.push({ label: path, detail: "reachable", source: src, url: str(get(h, "url")) });
      }
    }

    if (m.id === "admin-panels") {
      for (const p of arr(get(d, "panels"))) {
        inv.admin.push({ label: str(get(p, "url")), detail: [str(get(p, "product")), get(p, "loginForm") ? "login form" : "", `HTTP ${str(get(p, "status"))}`].filter(Boolean).join(" · "), source: src, url: str(get(p, "url")) });
      }
    }

    if (m.id === "js") {
      for (const e of arr(get(d, "endpoints"))) {
        const type = str(get(e, "type"));
        if (["API", "GraphQL", "WebSocket", "Full URL"].includes(type)) inv.api.push({ label: str(get(e, "value")), detail: `${type} · ${str(get(e, "file"))}`, source: src });
      }
      for (const s of arr(get(d, "secrets"))) inv.sensitive.push({ label: str(get(s, "kind")), detail: `${str(get(s, "masked"))} · ${str(get(s, "file"))}`, source: src });
    }

    if (m.id === "cloud") {
      for (const h of arr(get(d, "hits"))) {
        const provider = str(get(h, "provider"));
        if (provider.startsWith("Unknown")) continue;
        inv.cloud.push({ label: `${provider}: ${str(get(h, "ip"))}`, detail: str(get(h, "detail")) || undefined, source: src });
      }
    }

    if (m.id === "exposure") {
      for (const c of arr(get(d, "checks"))) {
        if (str(get(c, "category")) === "Exposed files" && str(get(c, "status")) === "fail") inv.sensitive.push({ label: str(get(c, "evidence")) || str(get(c, "title")), detail: str(get(c, "title")), source: src, url: str(get(c, "evidence")) });
      }
    }

    if (m.id === "ports-scan") {
      for (const h of arr(get(d, "hosts"))) {
        const ip = str(get(h, "ip"));
        addIp(ip, undefined, src);
        for (const p of arr(get(h, "open"))) {
          const port = Number(get(p, "port"));
          const banner = str(get(p, "banner"));
          const detail = [str(get(p, "service")), banner].filter(Boolean).join(" · ");
          addPort(`${ip}:${port}`, detail, src);
          if (RISKY_PORTS.has(port)) inv.exposed.push({ label: `${ip}:${port}`, detail: `${str(get(p, "service"))} (open to a TCP connection)`, source: src });
        }
      }
    }

    if (m.id === "url-archive") {
      for (const u of ((get(d, "api") as string[] | undefined) ?? []).slice(0, 200)) inv.api.push({ label: u, detail: "archived", source: src, url: u });
      for (const u of ((get(d, "sensitive") as string[] | undefined) ?? []).slice(0, 200)) inv.sensitive.push({ label: u, detail: "archived · check the live site", source: src, url: u });
      for (const u of ((get(d, "admin") as string[] | undefined) ?? []).slice(0, 100)) inv.admin.push({ label: u, detail: "archived", source: src, url: u });
    }

    if (m.id === "cloud-buckets") {
      for (const h of arr(get(d, "hits"))) {
        const label = `${str(get(h, "provider"))}: ${str(get(h, "name"))}`;
        if (str(get(h, "state")) === "listable") inv.sensitive.push({ label, detail: "public listing: anyone can list the files", source: src, url: str(get(h, "url")) });
        else if (str(get(h, "state")) === "private") inv.cloud.push({ label, detail: "exists, access denied", source: src, url: str(get(h, "url")) });
      }
    }

    if (m.id === "asn-ranges") {
      for (const a of arr(get(d, "asns"))) {
        const v4 = Number(get(a, "ipv4Prefixes")) || 0;
        const addresses = Number(get(a, "addresses")) || 0;
        inv.ip.push({ label: `AS${str(get(a, "asn"))} ${str(get(a, "name"))}`, detail: `${v4} IPv4 prefix(es) · ${addresses.toLocaleString("en-US")} addresses`, source: src });
      }
    }

    if (m.id === "ct") {
      for (const c of arr(get(d, "certs"))) {
        inv.cert.push({ label: str(get(c, "commonName")), detail: `${str(get(c, "issuer"))} · expires ${str(get(c, "notAfter")).slice(0, 10)}`, source: src });
      }
    }

    if (m.id === "http") {
      const tls = get(d, "tls");
      if (tls) inv.cert.push({ label: str(get(tls, "subject")) || "live certificate", detail: `${str(get(tls, "issuer"))} · ${str(get(tls, "protocol"))}`, source: src });
    }
  }
  return inv;
}

export function inventoryCounts(inv: Inventory): Record<AssetKey, number> {
  const out = {} as Record<AssetKey, number>;
  for (const c of ASSET_CATEGORIES) out[c.key] = inv[c.key].length;
  return out;
}
