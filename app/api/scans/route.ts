import { NextResponse } from "next/server";
import { startScan, type ScanRequest } from "@/lib/pipeline";
import { listSummaries, summaryOf } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ ok: true, scans: await listSummaries() });
}

// Starts a scan and returns at once. The client follows progress with GET /api/scans/[id].
export async function POST(req: Request) {
  let body: { target?: unknown; mode?: unknown; options?: unknown; scope?: unknown; chainLimit?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body.", code: "bad_request" }, { status: 400 });
  }
  const scope = Array.isArray(body.scope)
    ? body.scope.map((s) => String(s).trim().toLowerCase().replace(/^\*\./, "")).filter(Boolean).slice(0, 200)
    : [];
  const request: ScanRequest = {
    target: String(body.target ?? ""),
    mode: body.mode === "active" || body.mode === "full" ? body.mode : "passive",
    options: body.options && typeof body.options === "object" ? (body.options as ScanRequest["options"]) : undefined,
    scope,
    chainLimit: typeof body.chainLimit === "number" ? body.chainLimit : undefined,
  };
  const result = await startScan(request);
  if (!result.ok) return NextResponse.json({ ok: false, error: result.error, code: result.code }, { status: 400 });
  return NextResponse.json({ ok: true, id: result.record.id, scan: summaryOf(result.record) }, { status: 202 });
}
