import { NextResponse } from "next/server";
import { readPipeline } from "@/lib/autopipe";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const rec = await readPipeline(id);
  if (!rec) return NextResponse.json({ ok: false, error: "Run not found." }, { status: 404 });
  return NextResponse.json({ ok: true, run: rec });
}
