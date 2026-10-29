// Panel settings shared by the server and the Settings page. Pure: no file or network access here.

export interface BurpSettings {
  /** Route target-facing traffic through the proxy. */
  enabled: boolean;
  /** Proxy address. Burp's default listener is http://127.0.0.1:8080. */
  url: string;
  /** Burp uses its own certificate authority. Accept it for proxied requests unless it is installed. */
  ignoreTls: boolean;
}

export interface SessionSettings {
  /** Send these credentials with every target-facing request. */
  enabled: boolean;
  cookie: string;
  authorization: string;
  /** One "Name: value" per line. */
  headers: string;
}

export interface PanelSettings {
  burp: BurpSettings;
  session: SessionSettings;
}

export const DEFAULT_SETTINGS: PanelSettings = {
  burp: { enabled: false, url: "http://127.0.0.1:8080", ignoreTls: true },
  session: { enabled: false, cookie: "", authorization: "", headers: "" },
};

const TOKEN = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding", "proxy-authorization"]);

/** Header name and value pairs from the session settings. Validates names and rejects line breaks. */
export function sessionHeaders(s: SessionSettings): { headers: Record<string, string> } | { error: string } {
  const out: Record<string, string> = {};
  const add = (name: string, value: string) => {
    if (/[\r\n]/.test(value)) return "Header values cannot contain line breaks.";
    if (!TOKEN.test(name)) return `"${name}" is not a valid header name.`;
    if (FORBIDDEN_HEADERS.has(name.toLowerCase())) return `The ${name} header cannot be set here.`;
    out[name] = value;
    return null;
  };
  if (s.cookie.trim()) {
    const err = add("Cookie", s.cookie.trim());
    if (err) return { error: err };
  }
  if (s.authorization.trim()) {
    const err = add("Authorization", s.authorization.trim());
    if (err) return { error: err };
  }
  for (const line of s.headers.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)) {
    const m = line.match(/^([^:]+):\s*(.*)$/);
    if (!m) return { error: `"${line}" is not in the form Name: value.` };
    const err = add(m[1].trim(), m[2]);
    if (err) return { error: err };
  }
  return { headers: out };
}

/** Returns a normalised proxy URL, or a message for the user. Only http and https proxies are accepted. */
export function validateProxyUrl(raw: string): { url: string } | { error: string } {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return { error: "Enter a full address such as http://127.0.0.1:8080." };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { error: "Only http:// and https:// proxies are supported (Burp uses http://)." };
  if (!u.port) return { error: "Include the port, for example :8080." };
  return { url: `${u.protocol}//${u.host}` };
}

export function mergeSettings(input: unknown): { settings: PanelSettings } | { error: string } {
  const src = (input as { burp?: Partial<BurpSettings>; session?: Partial<SessionSettings> } | null) ?? {};
  const b = src.burp ?? {};
  const url = validateProxyUrl(String(b.url ?? DEFAULT_SETTINGS.burp.url));
  if ("error" in url) return { error: url.error };
  const ss = src.session ?? {};
  const session: SessionSettings = {
    enabled: ss.enabled === true,
    cookie: String(ss.cookie ?? "").slice(0, 8000),
    authorization: String(ss.authorization ?? "").slice(0, 2000),
    headers: String(ss.headers ?? "").slice(0, 8000),
  };
  const check = sessionHeaders(session);
  if ("error" in check) return { error: check.error };
  return {
    settings: {
      burp: {
        enabled: b.enabled === true,
        url: url.url,
        ignoreTls: b.ignoreTls !== false,
      },
      session,
    },
  };
}

/** Cookie pairs for a browser context. */
export function cookiePairs(cookie: string): { name: string; value: string }[] {
  return cookie
    .split(";")
    .map((p) => p.trim())
    .filter((p) => p.includes("="))
    .map((p) => {
      const i = p.indexOf("=");
      return { name: p.slice(0, i).trim(), value: p.slice(i + 1).trim() };
    })
    .filter((c) => c.name && TOKEN.test(c.name));
}
