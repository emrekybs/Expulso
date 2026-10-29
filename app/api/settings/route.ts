import { NextResponse } from "next/server";
import { mergeSettings } from "@/lib/settings-core";
import { readSettings, writeSettings } from "@/lib/settings";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ ok: true, settings: readSettings() });
}

export async function PUT(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  const merged = mergeSettings(body);
  if ("error" in merged) return NextResponse.json({ ok: false, error: merged.error }, { status: 400 });
  await writeSettings(merged.settings);
  return NextResponse.json({ ok: true, settings: merged.settings });
}
