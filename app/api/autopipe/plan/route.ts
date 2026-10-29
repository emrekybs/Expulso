import { NextResponse } from "next/server";
import { parsePipelineBody } from "@/lib/autopipe-request";
import { planLines } from "@/lib/autopipe-core";
import { toolStatuses } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Shows what a run will do before anything is sent: stages, engines and the tools that are missing.
export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  const parsed = parsePipelineBody({ ...body, authorized: true });
  if ("error" in parsed) return NextResponse.json({ ok: false, error: parsed.error }, { status: 400 });
  const installed = Object.fromEntries((await toolStatuses()).map((t) => [t.name, t.installed]));
  return NextResponse.json({ ok: true, steps: planLines(parsed.request, installed), targets: parsed.request.targets });
}
