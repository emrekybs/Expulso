import { NextResponse } from "next/server";
import { controlRun } from "@/lib/autopipe";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Pause, resume or stop a running autopipeline. Stop applies when the running stage finishes.
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  let body: { action?: unknown };
  try {
    body = (await req.json()) as { action?: unknown };
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  const action = body.action;
  if (action !== "pause" && action !== "resume" && action !== "stop") return NextResponse.json({ ok: false, error: "Unknown action." }, { status: 400 });
  if (!controlRun(id, action)) return NextResponse.json({ ok: false, error: "This run is not active." }, { status: 409 });
  return NextResponse.json({ ok: true });
}
