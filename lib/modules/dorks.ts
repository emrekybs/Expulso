import { registrableDomain, type ParsedTarget } from "../target.ts";
import { UserError } from "../net.ts";
import type { ModuleOutput } from "../types.ts";

export interface Dork {
  query: string;
  note: string;
  google: string;
  bing: string;
  duckduckgo: string;
}
export interface DorkCategory {
  name: string;
  dorks: Dork[];
}
export interface DorkData {
  domain: string;
  categories: DorkCategory[];
  total: number;
}

const CATEGORIES: { name: string; items: [string, string][] }[] = [
  {
    name: "Exposed files",
    items: [
      ["site:{d} ext:env | ext:sql | ext:log | ext:bak | ext:old | ext:ini | ext:conf", "Configuration, database and backup files"],
      ["site:{d} ext:xml | ext:json | ext:yml | ext:yaml", "Config and data files"],
      ["site:{d} intext:\"BEGIN RSA PRIVATE KEY\" | intext:\"api_key\" | intext:\"secret\"", "Keys and secrets in indexed pages"],
    ],
  },
  {
    name: "Documents",
    items: [
      ["site:{d} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx", "Public documents (may carry metadata)"],
      ["site:{d} ext:csv | ext:txt intext:password", "Spreadsheets and text with sensitive terms"],
    ],
  },
  {
    name: "Login & admin",
    items: [
      ["site:{d} inurl:login | inurl:signin | inurl:admin | inurl:dashboard | inurl:portal", "Authentication and admin entry points"],
      ["site:{d} intitle:\"login\" | intitle:\"admin\" | intitle:\"dashboard\"", "Login and admin pages by title"],
    ],
  },
  {
    name: "Directory listing",
    items: [["site:{d} intitle:\"index of\" | intitle:\"directory listing\"", "Open directory listings"]],
  },
  {
    name: "Errors & debug",
    items: [
      ["site:{d} intext:\"sql syntax near\" | intext:\"stack trace\" | intext:\"Warning: \" | intext:\"Fatal error\"", "Error messages that leak internals"],
      ["site:{d} inurl:phpinfo | intitle:\"phpinfo()\"", "phpinfo pages"],
    ],
  },
  {
    name: "Config & infrastructure",
    items: [
      ["site:{d} inurl:wp-content | inurl:wp-admin | inurl:wp-json", "WordPress paths"],
      ["site:{d} inurl:.git | inurl:.svn | inurl:.well-known", "Source control and well-known paths"],
      ["site:{d} inurl:api | inurl:swagger | inurl:graphql", "API and documentation endpoints"],
    ],
  },
  {
    name: "Subdomains",
    items: [["site:*.{d} -www", "Indexed subdomains other than www"]],
  },
  {
    name: "Mentions elsewhere",
    items: [
      ["\"{d}\" site:pastebin.com | site:gist.github.com | site:github.com", "The domain mentioned in code and paste sites"],
      ["\"{d}\" site:trello.com | site:s3.amazonaws.com | site:blob.core.windows.net", "The domain in public boards and cloud storage"],
      ["\"@{d}\" site:linkedin.com", "Email addresses / staff on LinkedIn"],
    ],
  },
];

function links(query: string) {
  const q = encodeURIComponent(query);
  return { google: `https://www.google.com/search?q=${q}`, bing: `https://www.bing.com/search?q=${q}`, duckduckgo: `https://duckduckgo.com/?q=${q}` };
}

export async function runDorks(t: ParsedTarget): Promise<ModuleOutput<DorkData>> {
  if (t.kind === "ip" || t.kind === "cidr") throw new UserError("Google Dorks needs a domain.");
  const domain = registrableDomain(t.host);
  let total = 0;
  const categories: DorkCategory[] = CATEGORIES.map((c) => ({
    name: c.name,
    dorks: c.items.map(([q, note]) => {
      const query = q.replace(/\{d\}/g, domain);
      total++;
      return { query, note, ...links(query) };
    }),
  }));
  return { summary: `${total} dork links in ${categories.length} categories`, findings: [], data: { domain, categories, total } };
}
