import "server-only";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { AsyncLocalStorage } from "node:async_hooks";
import { DEFAULT_SETTINGS, mergeSettings, type PanelSettings } from "./settings-core.ts";

// Settings are stored in data/settings.json, next to the scan results.
export const SETTINGS_FILE = path.join(process.cwd(), "data", "settings.json");

export function readSettings(): PanelSettings {
  try {
    const raw = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8")) as unknown;
    const merged = mergeSettings(raw);
    return "settings" in merged ? merged.settings : DEFAULT_SETTINGS;
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export async function writeSettings(s: PanelSettings): Promise<void> {
  await fsp.mkdir(path.dirname(SETTINGS_FILE), { recursive: true });
  const tmp = `${SETTINGS_FILE}.${process.pid}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(s, null, 2));
  await fsp.rename(tmp, SETTINGS_FILE);
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
