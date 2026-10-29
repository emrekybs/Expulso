// Panel settings shared by the server and the Settings page. Pure: no file or network access here.

export interface BurpSettings {
  /** Route target-facing traffic through the proxy. */
  enabled: boolean;
  /** Proxy address. Burp's default listener is http://127.0.0.1:8080. */
  url: string;
  /** Burp uses its own certificate authority. Accept it for proxied requests unless it is installed. */
  ignoreTls: boolean;
}

export interface PanelSettings {
  burp: BurpSettings;
}

export const DEFAULT_SETTINGS: PanelSettings = {
  burp: { enabled: false, url: "http://127.0.0.1:8080", ignoreTls: true },
};

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
  const b = (input as { burp?: Partial<BurpSettings> } | null)?.burp ?? {};
  const url = validateProxyUrl(String(b.url ?? DEFAULT_SETTINGS.burp.url));
  if ("error" in url) return { error: url.error };
  return {
    settings: {
      burp: {
        enabled: b.enabled === true,
        url: url.url,
        ignoreTls: b.ignoreTls !== false,
      },
    },
  };
}
