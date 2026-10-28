// Module catalogue used by the sidebar, module pages, Full Scan and the API route.
import type { TargetKind } from "./target.ts";

export type ModuleId =
  | "subdomains"
  | "dns"
  | "whois"
  | "ct"
  | "reverse-dns"
  | "reverse-ip"
  | "geoip"
  | "cloud"
  | "related"
  | "typosquatting"
  | "dorks"
  | "osint"
  | "emails"
  | "http"
  | "waf"
  | "js"
  | "dirs"
  | "exposure"
  | "origin"
  | "webtech"
  | "ports-passive";

/** passive: nothing is sent to the target. light: a few normal page loads. active: many requests to the target. */
export type Tier = "passive" | "light" | "active";
export type Group = "Recon" | "OSINT" | "Active";

export interface OptionDef {
  key: string;
  label: string;
  type: "boolean" | "number" | "text" | "select";
  default: boolean | number | string;
  help?: string;
  min?: number;
  max?: number;
  choices?: { value: string; label: string }[];
}

export interface ModuleDef {
  id: ModuleId;
  title: string;
  group: Group;
  tier: Tier;
  description: string;
  accepts: TargetKind[];
  sources: string[];
  /** Max targets per bulk run. */
  bulkLimit: number;
  options?: OptionDef[];
  /** Full Scan default options (overrides `options` defaults). */
  fullScanOptions?: Record<string, unknown>;
}

const ALL: TargetKind[] = ["domain", "url", "ip", "cidr"];
const NAMES: TargetKind[] = ["domain", "url"];
const HOSTS: TargetKind[] = ["domain", "url", "ip"];

export const MODULES: ModuleDef[] = [
  {
    id: "subdomains",
    title: "Subdomain Enumeration",
    group: "Recon",
    tier: "passive",
    description:
      "Merges passive sources (the ones subfinder and assetfinder use), de-duplicates, resolves every name over DNS and optionally checks the HTTP status of each live host.",
    accepts: NAMES,
    sources: ["crt.sh", "CertSpotter", "HackerTarget", "AlienVault OTX", "Anubis", "RapidDNS", "urlscan.io", "ThreatMiner", "Wayback Machine", "Sonar"],
    bulkLimit: 20,
    options: [
      { key: "resolve", label: "Resolve DNS", type: "boolean", default: true },
      { key: "httpStatus", label: "HTTP status per host (light: one request per host)", type: "boolean", default: true },
    ],
  },
  {
    id: "dns",
    title: "DNS Records",
    group: "Recon",
    tier: "passive",
    description: "A, AAAA, CNAME, MX, NS, TXT, SOA, CAA and SRV records, plus SPF, DMARC, DKIM, MTA-STS, DNSSEC and services identified from TXT records.",
    accepts: NAMES,
    sources: ["Cloudflare DoH", "Google DoH"],
    bulkLimit: 50,
  },
  {
    id: "whois",
    title: "WHOIS / RDAP",
    group: "Recon",
    tier: "passive",
    description: "Registrar, registration and expiry dates, domain age, statuses, name servers, DNSSEC and contacts. For IPs: network range, owner and abuse contact.",
    accepts: HOSTS,
    sources: ["RDAP (registries)", "HackerTarget WHOIS"],
    bulkLimit: 50,
  },
  {
    id: "ct",
    title: "Certificate Transparency",
    group: "Recon",
    tier: "passive",
    description: "Every certificate logged for the domain: issuers over time, validity, wildcard usage and all names (SANs) found on them.",
    accepts: NAMES,
    sources: ["crt.sh"],
    bulkLimit: 20,
  },
  {
    id: "reverse-dns",
    title: "Reverse DNS",
    group: "Recon",
    tier: "passive",
    description: "PTR records for every IP a domain resolves to, a single IP, or a whole range up to /24.",
    accepts: ALL,
    sources: ["Cloudflare DoH", "Google DoH"],
    bulkLimit: 50,
  },
  {
    id: "reverse-ip",
    title: "Reverse IP",
    group: "Recon",
    tier: "passive",
    description: "Other domains hosted on the same IP addresses (shared hosting and infrastructure overlap).",
    accepts: HOSTS,
    sources: ["HackerTarget", "RapidDNS"],
    bulkLimit: 20,
  },
  {
    id: "geoip",
    title: "GeoIP & ASN",
    group: "Recon",
    tier: "passive",
    description: "Country, city, ASN, organisation and ISP for each IP, plus the prefixes announced by that ASN.",
    accepts: ALL,
    sources: ["ipwho.is", "RIPEstat"],
    bulkLimit: 50,
  },
  {
    id: "ports-passive",
    title: "Exposed Services (passive)",
    group: "Recon",
    tier: "passive",
    description: "Open ports, service banners, hostnames and known CVEs for the target's IPs from Shodan InternetDB's cached index. Nothing is sent to the target.",
    accepts: HOSTS,
    sources: ["Shodan InternetDB (keyless, cached)", "DNS"],
    bulkLimit: 20,
  },
  {
    id: "cloud",
    title: "Cloud & CDN Mapping",
    group: "Recon",
    tier: "passive",
    description: "Which cloud or CDN each IP belongs to, from the IP ranges the providers publish, with region and service where available.",
    accepts: ALL,
    sources: ["AWS ip-ranges", "Google Cloud ranges", "Cloudflare ranges", "Fastly ranges", "RIPEstat"],
    bulkLimit: 50,
  },
  {
    id: "related",
    title: "Related Domains",
    group: "Recon",
    tier: "passive",
    description: "Domains linked to the target by shared certificates, shared IP addresses or shared name servers.",
    accepts: NAMES,
    sources: ["crt.sh", "HackerTarget", "RapidDNS"],
    bulkLimit: 10,
  },
  {
    id: "typosquatting",
    title: "Typosquatting",
    group: "Recon",
    tier: "passive",
    description: "Generates lookalike domains (omission, swap, homoglyph, TLD change…) and checks which are registered and which can receive email.",
    accepts: NAMES,
    sources: ["Cloudflare DoH", "Google DoH"],
    bulkLimit: 10,
  },
  {
    id: "dorks",
    title: "Google Dorks",
    group: "OSINT",
    tier: "passive",
    description: "Ready-made search engine queries grouped by category. Nothing is fetched; you open the links yourself.",
    accepts: NAMES,
    sources: ["Generated locally"],
    bulkLimit: 50,
  },
  {
    id: "osint",
    title: "OSINT Harvester",
    group: "OSINT",
    tier: "light",
    description: "Emails, phone numbers, social profiles, page authors, geo tags and usernames from the site's own pages (Uscrapper logic).",
    accepts: NAMES,
    sources: ["Target website"],
    bulkLimit: 10,
    options: [
      { key: "crawl", label: "Pages to crawl", type: "number", default: 10, min: 1, max: 30 },
      { key: "nonStrict", label: "Non-strict usernames", type: "boolean", default: false },
      { key: "keywords", label: "Keywords (comma separated, optional)", type: "text", default: "" },
    ],
  },
  {
    id: "emails",
    title: "Email Harvester",
    group: "OSINT",
    tier: "light",
    description: "Corporate, role and staff addresses for the domain from its website, WHOIS/RDAP and structured data; detects the address pattern and suggests addresses for people named on the site.",
    accepts: NAMES,
    sources: ["Target website", "RDAP"],
    bulkLimit: 10,
  },
  {
    id: "http",
    title: "HTTP Fingerprint",
    group: "Active",
    tier: "light",
    description: "Status, title, server, technologies, redirect chain, TLS certificate and security headers for http and https (httpx-style).",
    accepts: HOSTS,
    sources: ["Target website"],
    bulkLimit: 30,
  },
  {
    id: "webtech",
    title: "Web Technologies",
    group: "Active",
    tier: "light",
    description: "Detects CMS, frameworks, web servers, CDNs, analytics, chat and JavaScript libraries (about 130 signatures) with versions where visible. Flags outdated versions and checks npm libraries against OSV.dev for known CVEs.",
    accepts: NAMES,
    sources: ["Target homepage (one request)", "OSV.dev (keyless) for library CVEs"],
    bulkLimit: 30,
  },
  {
    id: "waf",
    title: "WAF / CDN Detection",
    group: "Active",
    tier: "light",
    description: "Loads the homepage once and matches headers, cookies, CNAMEs and IP ranges against known WAF and CDN signatures. No payloads are sent.",
    accepts: HOSTS,
    sources: ["Target website", "Provider IP ranges"],
    bulkLimit: 30,
  },
  {
    id: "js",
    title: "JS Crawler",
    group: "Active",
    tier: "active",
    description: "Crawls the site within scope, collects every JavaScript file (script tags, imports, chunks, source maps) and extracts endpoints and strings that look like keys or tokens.",
    accepts: NAMES,
    sources: ["Target website"],
    bulkLimit: 5,
    options: [
      { key: "maxPages", label: "Max pages", type: "number", default: 25, min: 1, max: 60 },
      { key: "thirdParty", label: "Include third-party JS", type: "boolean", default: false },
    ],
    fullScanOptions: { maxPages: 15 },
  },
  {
    id: "dirs",
    title: "Directory & Admin Finder",
    group: "Active",
    tier: "active",
    description: "Content discovery over a built-in wordlist (dirsearch / feroxbuster style) with soft-404 filtering and recursion; login and admin panels are listed separately.",
    accepts: NAMES,
    sources: ["Target website"],
    bulkLimit: 5,
    options: [
      {
        key: "wordlist",
        label: "Wordlist",
        type: "select",
        default: "common",
        choices: [
          { value: "admin", label: "Admin & login panels" },
          { value: "common", label: "Common paths" },
          { value: "all", label: "Common + admin + backups" },
        ],
      },
      { key: "extensions", label: "Extensions (comma separated)", type: "text", default: "" },
      { key: "recursion", label: "Recursion depth", type: "number", default: 1, min: 0, max: 3 },
    ],
    fullScanOptions: { wordlist: "admin", recursion: 0 },
  },
  {
    id: "origin",
    title: "Origin IP Finder",
    group: "Active",
    tier: "active",
    description:
      "Finds the real server IP behind a CDN or WAF (such as Cloudflare). Collects candidate IPs from DNS records, mail servers, SPF and certificates, then connects to each one with the real Host header and compares the response to the live site.",
    accepts: NAMES,
    sources: ["DNS", "crt.sh", "Provider IP ranges", "Direct connection to candidate IPs"],
    bulkLimit: 10,
  },
  {
    id: "exposure",
    title: "Exposure & Misconfig",
    group: "Active",
    tier: "active",
    description: "Checks for exposed files (.git, .env, backups), debug and status pages, API docs, directory listing, CORS, cookie flags, TLS and security headers. Each finding comes with an explanation.",
    accepts: HOSTS,
    sources: ["Target website"],
    bulkLimit: 10,
  },
];

export const GROUPS: Group[] = ["Recon", "OSINT", "Active"];

export function getModule(id: string): ModuleDef | undefined {
  return MODULES.find((m) => m.id === id);
}

export type ScanMode = "passive" | "active" | "full";

export const MODE_LABEL: Record<ScanMode, string> = {
  passive: "Passive only",
  active: "Active only",
  full: "Full (passive + active)",
};

export function modulesForMode(mode: ScanMode): ModuleDef[] {
  if (mode === "passive") return MODULES.filter((m) => m.tier === "passive");
  if (mode === "active") return MODULES.filter((m) => m.tier !== "passive");
  return MODULES;
}

export const TIER_LABEL: Record<Tier, string> = { passive: "Passive", light: "Light", active: "Active" };
