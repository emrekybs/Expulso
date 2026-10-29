import "server-only";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { DEFAULT_SETTINGS, mergeSettings, sessionHeaders, cookiePairs, type PanelSettings } from "./settings-core.ts";

// Settings are stored in data/settings.json, next to the scan results.
export const SETTINGS_FILE = path.join(process.cwd(), "data", "settings.json");

// Requests read the settings often, so the file is parsed again only when it changes.
let cache: { mtime: number; value: PanelSettings } | null = null;

export function readSettings(): PanelSettings {
  try {
    const mtime = fs.statSync(SETTINGS_FILE).mtimeMs;
    if (cache && cache.mtime === mtime) return cache.value;
    const raw = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8")) as unknown;
    const merged = mergeSettings(raw);
    const value = "settings" in merged ? merged.settings : DEFAULT_SETTINGS;
    cache = { mtime, value };
    return value;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function writeSettings(s: PanelSettings): Promise<void> {
  await fsp.mkdir(path.dirname(SETTINGS_FILE), { recursive: true });
  const tmp = `${SETTINGS_FILE}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(s, null, 2));
  await fsp.rename(tmp, SETTINGS_FILE);
  cache = null;
}

/** A run can override the global proxy switch for everything it starts (see the autopipeline). */
export const proxyScope = new AsyncLocalStorage<{ proxy: { url: string; ignoreTls: boolean } | null }>();

/** The proxy the target-facing tools should use right now, or null when the proxy is off. */
export function activeProxy(): { url: string; ignoreTls: boolean } | null {
  const scoped = proxyScope.getStore();
  if (scoped) return scoped.proxy;
  const b = readSettings().burp;
  return b.enabled ? { url: b.url, ignoreTls: b.ignoreTls } : null;
}

/** The proxy a run would use when forced on, even if the global switch is off. */
export function proxyAddress(): { url: string; ignoreTls: boolean } {
  const b = readSettings().burp;
  return { url: b.url, ignoreTls: b.ignoreTls };
}

/** Headers of the saved login session, or none when the session is switched off. */
export function activeSessionHeaders(): Record<string, string> {
  const ss = readSettings().session;
  if (!ss.enabled) return {};
  const r = sessionHeaders(ss);
  return "headers" in r ? r.headers : {};
}

/** Cookies of the saved login session, for browser contexts. */
export function activeSessionCookies(): { name: string; value: string }[] {
  const ss = readSettings().session;
  return ss.enabled ? cookiePairs(ss.cookie) : [];
}
