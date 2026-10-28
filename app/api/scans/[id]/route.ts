import { NextResponse } from "next/server";
import { deleteRecord, getRecord } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const record = await getRecord(id);
  if (!record) return NextResponse.json({ ok: false, error: "Scan not found." }, { status: 404 });
  return NextResponse.json({ ok: true, scan: record });
}

export async function DELETE(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const result = await deleteRecord(id);
  if (result === "running") return NextResponse.json({ ok: false, error: "This scan is still running." }, { status: 409 });
  if (result === "missing") return NextResponse.json({ ok: false, error: "Scan not found." }, { status: 404 });
  return NextResponse.json({ ok: true });
}
