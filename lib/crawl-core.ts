// Pure crawling and API-discovery logic. The network is passed in, so this is unit tested without a target.
import * as cheerio from "cheerio";

export interface FormInfo {
  action: string;
  method: string;
  fields: string[];
}

/** True when the URL belongs to the host or one of its subdomains. */
export function sameSite(url: string, host: string): boolean {
  try {
    const h = new URL(url).hostname.toLowerCase();
    return h === host || h.endsWith(`.${host}`);
  } catch {
    return false;
  }
}

/** Links, script sources and form actions of an HTML page, resolved against the page URL. */
export function extractLinks(html: string, pageUrl: string): { links: string[]; forms: FormInfo[] } {
  const $ = cheerio.load(html);
  const links = new Set<string>();
  const add = (raw: string | undefined) => {
    if (!raw || /^(javascript|mailto|tel|data):/i.test(raw.trim())) return;
    try {
      const u = new URL(raw.trim(), pageUrl);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      u.hash = "";
      links.add(u.toString());
    } catch {
      /* not a URL */
    }
  };
  $("a[href], area[href], link[href][rel=stylesheet] ").each((_, el) => add($(el).attr("href")));
  $("script[src], iframe[src], img[src]").each((_, el) => add($(el).attr("src")));
  const forms: FormInfo[] = [];
  $("form").each((_, el) => {
    const action = $(el).attr("action") ?? pageUrl;
    const method = ($(el).attr("method") ?? "GET").toUpperCase();
    const fields = $(el)
      .find("input[name], select[name], textarea[name]")
      .map((__, f) => $(f).attr("name") ?? "")
      .get()
      .filter(Boolean);
    let resolved = pageUrl;
    try {
      resolved = new URL(action, pageUrl).toString();
    } catch {
      /* keep page URL */
    }
    forms.push({ action: resolved, method, fields: [...new Set(fields)] });
    if (method === "GET" && fields.length) {
      const u = new URL(resolved);
      for (const f of fields) if (!u.searchParams.has(f)) u.searchParams.set(f, "test");
      links.add(u.toString());
    }
  });
  return { links: [...links], forms };
}

/**
 * Breadth-first crawl over the same site. fetchHtml returns the HTML of a page, or null when the page is not
 * HTML or cannot be fetched. Stops after maxPages pages.
 */
export async function crawlGraph(
  seed: string,
  host: string,
  maxPages: number,
  fetchHtml: (url: string) => Promise<{ html: string; url: string } | null>,
): Promise<{ visited: string[]; urls: string[]; forms: FormInfo[] }> {
  const visited: string[] = [];
  const seen = new Set<string>([seed]);
  const queue = [seed];
  const urls = new Set<string>();
  const forms: FormInfo[] = [];
  while (queue.length && visited.length < maxPages) {
    const url = queue.shift()!;
    const page = await fetchHtml(url);
    if (!page) continue;
    visited.push(page.url);
    const found = extractLinks(page.html, page.url);
    forms.push(...found.forms);
    for (const link of found.links) {
      if (!sameSite(link, host)) continue;
      urls.add(link);
      if (!seen.has(link) && !/\.(css|js|mjs|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip)(\?|$)/i.test(link)) {
        seen.add(link);
        queue.push(link);
      }
    }
  }
  return { visited, urls: [...urls], forms };
}

export interface ApiEndpoint {
  method: string;
  path: string;
  queryParams: string[];
}

const METHODS = ["get", "post", "put", "patch", "delete"];

/** Endpoints of an OpenAPI 2 or 3 document. */
export function parseOpenApi(doc: unknown): ApiEndpoint[] {
  const paths = (doc as { paths?: Record<string, Record<string, { parameters?: { name?: string; in?: string }[] }>> })?.paths ?? {};
  const out: ApiEndpoint[] = [];
  for (const [path, ops] of Object.entries(paths)) {
    for (const method of METHODS) {
      const op = ops?.[method];
      if (!op) continue;
      const queryParams = (op.parameters ?? []).filter((p) => p.in === "query" && p.name).map((p) => p.name!);
      out.push({ method: method.toUpperCase(), path, queryParams });
    }
  }
  return out;
}

export function isOpenApiDocument(doc: unknown): boolean {
  const d = doc as { openapi?: unknown; swagger?: unknown; paths?: unknown } | null;
  return !!d && typeof d === "object" && (typeof d.openapi === "string" || typeof d.swagger === "string") && typeof d.paths === "object";
}

export const GRAPHQL_PROBE = JSON.stringify({ query: "{ __typename }" });
export const GRAPHQL_INTROSPECTION = JSON.stringify({ query: "{ __schema { queryType { name } types { name } } }" });

/** A GraphQL endpoint answers with data or GraphQL-style errors. */
export function looksLikeGraphql(text: string): boolean {
  try {
    const j = JSON.parse(text) as { data?: unknown; errors?: unknown };
    return "data" in j || Array.isArray(j.errors);
  } catch {
    return false;
  }
}

/** Introspection is enabled when the schema comes back. */
export function introspectionEnabled(text: string): boolean {
  return /"__schema"/.test(text) && /"types"/.test(text);
}

export const API_DOC_PATHS = ["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/openapi.json", "/api/swagger.json", "/docs/openapi.json"];
export const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/query"];
