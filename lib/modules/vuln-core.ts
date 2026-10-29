// Pure detection helpers for the built-in vulnerability checks. No network access here, so they are unit tested.

export const MARKER_PREFIX = "b24x";

export type ReflectionContext = "html-text" | "attribute" | "script" | "none";

/** A unique token for one request, so reflections can be matched to that request only. */
export function makeMarker(seed: string): string {
  return `${MARKER_PREFIX}${seed.replace(/[^a-z0-9]/gi, "").slice(0, 12)}`;
}

/** Where the marker appears in the body and whether the dangerous characters survived unencoded. */
export function reflectionContext(body: string, marker: string): { context: ReflectionContext; unencoded: boolean } {
  const idx = body.indexOf(marker);
  if (idx < 0) return { context: "none", unencoded: false };
  const probe = `${marker}"'<>`;
  // Canary with dangerous characters: if the raw form appears, the characters were not encoded.
  const raw = body.includes(probe);
  const before = body.slice(Math.max(0, idx - 300), idx);
  const scriptOpen = before.lastIndexOf("<script");
  const scriptClose = before.lastIndexOf("</script");
  if (scriptOpen > scriptClose) return { context: "script", unencoded: raw };
  const tagOpen = before.lastIndexOf("<");
  const tagClose = before.lastIndexOf(">");
  if (tagOpen > tagClose) return { context: "attribute", unencoded: raw };
  return { context: "html-text", unencoded: raw };
}

const SQL_ERRORS: RegExp[] = [
  /You have an error in your SQL syntax/i,
  /Warning: mysql_/i,
  /MySqlException|com\.mysql\.jdbc/i,
  /PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string/i,
  /ORA-\d{5}/,
  /Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string/i,
  /SQLite(Exception| error)|near ".*": syntax error/i,
];

/** Returns the database error text when the body contains one. */
export function sqlErrorSignature(body: string): string | null {
  for (const re of SQL_ERRORS) {
    const m = body.match(re);
    if (m) return m[0].slice(0, 120);
  }
  return null;
}

/** True when the injected header name appears as a real response header. */
export function crlfReflected(headers: Headers, headerName: string): boolean {
  return headers.has(headerName.toLowerCase());
}

const REDIRECT_PARAMS = /^(url|uri|next|redirect|redirect_uri|return|returnurl|return_to|dest|destination|continue|goto|target|out|to|link)$/i;

export function isRedirectParam(name: string): boolean {
  return REDIRECT_PARAMS.test(name);
}

/** Returns the same URL with one query parameter replaced. */
export function withParam(url: string, name: string, value: string): string {
  const u = new URL(url);
  u.searchParams.set(name, value);
  return u.toString();
}

/** Parameters worth testing from a URL, or none when the URL has no query. */
export function queryParams(url: string): string[] {
  try {
    return [...new Set(new URL(url).searchParams.keys())];
  } catch {
    return [];
  }
}

/** Security headers missing from a response. */
export function missingSecurityHeaders(headers: Headers, https: boolean): string[] {
  const missing: string[] = [];
  if (https && !headers.has("strict-transport-security")) missing.push("Strict-Transport-Security");
  if (!headers.has("content-security-policy") && !/frame-ancestors/i.test(headers.get("content-security-policy") ?? "")) missing.push("Content-Security-Policy");
  if (!headers.has("x-frame-options") && !/frame-ancestors/i.test(headers.get("content-security-policy") ?? "")) missing.push("X-Frame-Options");
  if (!/nosniff/i.test(headers.get("x-content-type-options") ?? "")) missing.push("X-Content-Type-Options");
  return missing;
}

/** Set-Cookie headers that lack a protection flag. Returns the cookie name and the missing flags. */
export function cookieFlagProblems(setCookie: string[]): { name: string; missing: string[] }[] {
  return setCookie.map((raw) => {
    const name = raw.split("=")[0].trim();
    const missing: string[] = [];
    if (!/;\s*secure/i.test(raw)) missing.push("Secure");
    if (!/;\s*httponly/i.test(raw)) missing.push("HttpOnly");
    if (!/;\s*samesite=/i.test(raw)) missing.push("SameSite");
    return { name, missing };
  }).filter((c) => c.missing.length > 0);
}
