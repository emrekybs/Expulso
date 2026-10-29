import { NextResponse } from "next/server";
import { validateSqli, type SqliRequest } from "@/lib/sqli-core";
import { runSqli } from "@/lib/modules/sqli-scan";

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
  if (targets.length > 20) return NextResponse.json({ ok: false, error: "Up to 20 targets per run." }, { status: 400 });

  const request: SqliRequest = {
    targets,
    level: Number(body.level) || 1,
    risk: Number(body.risk) || 1,
    techniques: Array.isArray(body.techniques) ? body.techniques.map(String) : ["B", "E", "T"],
    threads: Number(body.threads) || 1,
    limit: Number(body.limit) || 20,
    nucleiTags: Array.isArray(body.nucleiTags) ? body.nucleiTags.map(String) : [],
  };
  const problem = validateSqli(request);
  if (problem) return NextResponse.json({ ok: false, error: problem }, { status: 400 });

  const result = await runSqli(request, { discover: body.discover !== false });
  return NextResponse.json({ ok: true, ...result });
}
