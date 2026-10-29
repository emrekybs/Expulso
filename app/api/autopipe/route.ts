import { NextResponse } from "next/server";
import { parsePipelineBody } from "@/lib/autopipe-request";
import { startPipelines, listPipelines } from "@/lib/autopipe";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ ok: true, runs: await listPipelines() });
}

export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  const parsed = parsePipelineBody(body);
  if ("error" in parsed) return NextResponse.json({ ok: false, error: parsed.error }, { status: 400 });
  const ids = await startPipelines(parsed.request);
  return NextResponse.json({ ok: true, ids }, { status: 202 });
}
