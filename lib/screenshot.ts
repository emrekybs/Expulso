import "server-only";
import fs from "node:fs/promises";
import path from "node:path";
import net from "node:net";
import { UserError, mapLimit } from "./net.ts";
import { activeProxy } from "./settings.ts";

export const SHOT_DIR = path.join(process.cwd(), "data", "screenshots");

export interface ShotResult {
  host: string;
  file?: string;
  title?: string;
  error?: string;
}

export function shotFileName(host: string, scheme: "https" | "http"): string {
  return `${host.replace(/[^a-z0-9.-]/gi, "_")}_${scheme}.png`;
}

/**
 * Takes a viewport screenshot of each host with a local Chromium (Playwright).
 * Requires `npx playwright install chromium` once. Set CHROMIUM_PATH to use another binary.
 */
export async function captureScreenshots(targets: { host: string; scheme: "https" | "http" }[], opts: { concurrency?: number } = {}): Promise<ShotResult[]> {
  if (!targets.length) return [];
  let pw: typeof import("playwright");
  try {
    pw = await import("playwright");
  } catch {
    throw new UserError("Playwright is not available. Run: npm install && npx playwright install chromium", "tool_missing");
  }
  await fs.mkdir(SHOT_DIR, { recursive: true });
  let browser;
  try {
    const proxy = activeProxy();
    browser = await pw.chromium.launch({
      executablePath: process.env.CHROMIUM_PATH || undefined,
      args: process.env.CHROMIUM_NO_SANDBOX === "1" ? ["--no-sandbox"] : [],
      proxy: proxy ? { server: proxy.url } : undefined,
    });
  } catch (e) {
    throw new UserError(`Chromium could not start. Run: npx playwright install chromium (${(e as Error).message.split("\n")[0]})`, "tool_missing");
  }
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 800 }, userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36" });
    // Never let the browser reach private or loopback addresses through a redirect or a script.
    await context.route("**/*", (route) => {
      try {
        const u = new URL(route.request().url());
        const h = u.hostname.replace(/^\[|\]$/g, "");
        const blocked = h === "localhost" || h.endsWith(".internal") || (net.isIP(h) > 0 && isPrivateLiteral(h));
        return blocked ? route.abort() : route.continue();
      } catch {
        return route.abort();
      }
    });
    return await mapLimit(targets, opts.concurrency ?? 3, async (t): Promise<ShotResult> => {
      const page = await context.newPage();
      try {
        await page.goto(`${t.scheme}://${t.host}/`, { waitUntil: "domcontentloaded", timeout: 15000 });
        await page.waitForTimeout(700);
        const title = (await page.title()).slice(0, 160);
        const file = shotFileName(t.host, t.scheme);
        await page.screenshot({ path: path.join(SHOT_DIR, file), type: "png" });
        return { host: t.host, file, title };
      } catch (e) {
        return { host: t.host, error: (e as Error).message.split("\n")[0].slice(0, 160) };
      } finally {
        await page.close().catch(() => {});
      }
    });
  } finally {
    await browser.close().catch(() => {});
  }
}

function isPrivateLiteral(ip: string): boolean {
  return ip === "127.0.0.1" || ip.startsWith("10.") || ip.startsWith("192.168.") || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || ip.startsWith("169.254.") || ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd");
}
