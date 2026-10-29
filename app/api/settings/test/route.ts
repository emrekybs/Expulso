import { NextResponse } from "next/server";
import { fetchWithTimeout } from "@/lib/net";
import { readSettings } from "@/lib/settings";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Sends one request through the proxy so the user can confirm Burp (or another proxy) is receiving traffic.
export async function POST() {
  const s = readSettings().burp;
  if (!s.enabled) return NextResponse.json({ ok: false, error: "Turn the proxy on first." }, { status: 400 });
  try {
    const res = await fetchWithTimeout("https://example.com/", { headers: { "user-agent": "B24-engine proxy test" } }, 15000, true);
    return NextResponse.json({ ok: true, status: res.status, message: `The proxy at ${s.url} forwarded the request (HTTP ${res.status}). Check Burp's Proxy → HTTP history.` });
  } catch (e) {
    return NextResponse.json({ ok: false, error: `The proxy at ${s.url} did not forward the request: ${(e as Error).message}. Is Burp running with its listener on this address?` }, { status: 502 });
  }
}
