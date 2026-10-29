// Built-in knowledge base for vulnerability findings. Plain text written by us, so every finding has the
// same explanation, impact and fix without any external service.

export type VulnKind = "xss-reflected" | "sqli-error" | "crlf-injection" | "open-redirect" | "cors-misconfig" | "missing-headers" | "cookie-flags" | "exposed-file" | "cloud-bucket";

export interface VulnInfo {
  title: string;
  /** What the weakness is. */
  what: string;
  /** Why it matters for this target. */
  why: string;
  impact: string;
  fix: string;
  cwe: string;
  references: string[];
}

export const VULN_KB: Record<VulnKind, VulnInfo> = {
  "xss-reflected": {
    title: "Reflected cross-site scripting (XSS)",
    what: "User input is sent back in the response without proper encoding, so the browser may run it as script or markup.",
    why: "The application echoes a parameter value into the page. The value was not encoded for the context it lands in (HTML text, attribute or script).",
    impact: "An attacker can run JavaScript in a victim's browser through a crafted link: steal session cookies, act as the user, or show fake content.",
    fix: "Encode output for its context (HTML entity encoding in text, attribute encoding in attributes, JSON escaping in scripts). Set a strict Content-Security-Policy. Validate input where a format is expected.",
    cwe: "CWE-79",
    references: ["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
  },
  "sqli-error": {
    title: "Possible SQL injection (database error)",
    what: "Input is placed into a database query without parameterisation. A quote character breaks the query and the database error reaches the response.",
    why: "The response changed with a single quote and contained a database error message that the normal response did not contain.",
    impact: "An attacker can read or change database contents, bypass logins, and in some setups reach the server. Impact depends on database privileges.",
    fix: "Use parameterised queries or prepared statements. Never build SQL by joining strings. Show generic error pages to users and log details server-side.",
    cwe: "CWE-89",
    references: ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
  },
  "crlf-injection": {
    title: "CRLF injection (HTTP header injection)",
    what: "Input containing carriage return and line feed characters is copied into an HTTP response header.",
    why: "A test header name injected through the parameter appeared as a real response header.",
    impact: "An attacker can set cookies, cache-poison responses or split the response to inject content.",
    fix: "Reject or strip CR and LF characters from any value placed in a header. Use the framework's header API, which blocks this by default.",
    cwe: "CWE-113",
    references: ["https://owasp.org/www-community/vulnerabilities/CRLF_Injection", "https://cwe.mitre.org/data/definitions/113.html"],
  },
  "open-redirect": {
    title: "Open redirect",
    what: "A redirect target taken from a parameter is used without checking it belongs to the site.",
    why: "A redirect parameter sent the browser to an external address supplied by us.",
    impact: "Attackers use the trusted domain in phishing links to send victims to malicious sites.",
    fix: "Allow only relative paths or a fixed list of destinations. Reject absolute URLs that point elsewhere.",
    cwe: "CWE-601",
    references: ["https://cwe.mitre.org/data/definitions/601.html"],
  },
  "cors-misconfig": {
    title: "CORS trusts any origin",
    what: "The server reflects an arbitrary Origin header into Access-Control-Allow-Origin, with credentials allowed.",
    why: "A request with a made-up origin received that origin back together with Access-Control-Allow-Credentials: true.",
    impact: "A malicious site can read authenticated responses from the application in a visitor's browser.",
    fix: "Allow a fixed list of trusted origins. Never reflect the request Origin unchecked, and do not combine a wildcard with credentials.",
    cwe: "CWE-942",
    references: ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
  },
  "missing-headers": {
    title: "Missing security headers",
    what: "The response lacks headers that protect the browser (HSTS, CSP, clickjacking and content-type protection).",
    why: "The homepage response was checked for the standard protective headers.",
    impact: "Without them, browsers apply weaker defaults: pages can be framed by other sites, and content can be sniffed as a different type.",
    fix: "Send Strict-Transport-Security, Content-Security-Policy, X-Frame-Options (or frame-ancestors) and X-Content-Type-Options: nosniff.",
    cwe: "CWE-693",
    references: ["https://owasp.org/www-project-secure-headers/"],
  },
  "cookie-flags": {
    title: "Cookie without protection flags",
    what: "A cookie is set without Secure, HttpOnly or SameSite.",
    why: "The Set-Cookie header of the response lacks one or more of these flags.",
    impact: "Scripts can read the cookie (no HttpOnly), it can be sent over plain HTTP (no Secure), or sent from other sites (no SameSite).",
    fix: "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session and auth cookies.",
    cwe: "CWE-614",
    references: ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
  },
  "exposed-file": {
    title: "Sensitive file reachable on the web",
    what: "A file that should not be public (configuration, backup, version-control data) returns its content.",
    why: "A known sensitive path answered with HTTP 200 and content that looks like the file.",
    impact: "Credentials, source code, database dumps or internal settings can be downloaded by anyone.",
    fix: "Remove the file from the web root, block the path in the web server, and rotate any secret it contained.",
    cwe: "CWE-538",
    references: ["https://cwe.mitre.org/data/definitions/538.html"],
  },
  "cloud-bucket": {
    title: "Publicly listable cloud storage bucket",
    what: "A storage bucket allows anyone to list its contents without signing in.",
    why: "The bucket answered a listing request from the public internet with object names.",
    impact: "Anyone can see file names and often download the files, which may include backups, exports or user data.",
    fix: "Disable public listing and public read access. Grant access only to specific identities, and review the listed objects.",
    cwe: "CWE-284",
    references: ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
  },
};
