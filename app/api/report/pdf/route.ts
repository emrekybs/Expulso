import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_HTML = 20 * 1024 * 1024;

// Renders a report page to PDF with the local Chromium. The page may contain text from scanned sites,
// so every request the browser makes is blocked except the page itself.
export async function POST(req: Request) {
  let body: { html?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  const html = typeof body.html === "string" ? body.html : "";
  if (!html || html.length > MAX_HTML) return NextResponse.json({ ok: false, error: "Report is empty or too large." }, { status: 400 });

  let pw: typeof import("playwright");
  try {
    pw = await import("playwright");
  } catch {
    return NextResponse.json({ ok: false, error: "Playwright is not installed. Run: npm install" }, { status: 503 });
  }

  let browser;
  try {
    browser = await pw.chromium.launch({
      executablePath: process.env.CHROMIUM_PATH || undefined,
      args: process.env.CHROMIUM_NO_SANDBOX === "1" ? ["--no-sandbox"] : [],
    });
  } catch {
    return NextResponse.json({ ok: false, error: "Chromium is not installed. Install it on the Tools page or run: npx playwright install chromium" }, { status: 503 });
  }
  try {
    const page = await browser.newPage();
    await page.route("**/*", (route) => {
      const url = route.request().url();
      return url.startsWith("about:") || url.startsWith("data:") ? route.continue() : route.abort();
    });
    await page.setContent(html, { waitUntil: "load", timeout: 30000 });
    const pdf = await page.pdf({ format: "A4", printBackground: true, margin: { top: "14mm", bottom: "14mm", left: "12mm", right: "12mm" } });
    return new Response(new Uint8Array(pdf), {
      headers: { "content-type": "application/pdf", "content-disposition": "attachment; filename=\"b24-report.pdf\"" },
    });
  } catch (e) {
    return NextResponse.json({ ok: false, error: `PDF could not be created: ${(e as Error).message.split("\n")[0]}` }, { status: 500 });
  } finally {
    await browser.close().catch(() => undefined);
  }
}
