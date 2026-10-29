import { NextResponse } from "next/server";
import { runDalfox } from "@/lib/modules/dalfox-scan";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  if (body.authorized !== true) return NextResponse.json({ ok: false, error: "Confirm that you are authorised to test these targets." }, { status: 400 });
  const targets = String(body.targets ?? "").split(/\s+/).filter(Boolean);
  if (!targets.length) return NextResponse.json({ ok: false, error: "Enter at least one URL or domain." }, { status: 400 });
  if (targets.length > 50) return NextResponse.json({ ok: false, error: "Up to 50 targets per run." }, { status: 400 });

  const result = await runDalfox({
    targets,
    discover: body.discover !== false,
    limit: Number(body.limit) || 50,
    concurrency: Number(body.concurrency) || 5,
  });
  return NextResponse.json({ ok: true, ...result });
}
