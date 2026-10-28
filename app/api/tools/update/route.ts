import { NextResponse } from "next/server";
import { runChromiumInstall, runToolUpdate } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Only names from the fixed catalogue in lib/tools.ts reach a command. The request body never becomes part of one.
export async function POST(req: Request) {
  let body: { name?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  const name = String(body.name ?? "");
  const result = name === "chromium" ? await runChromiumInstall() : await runToolUpdate(name);
  return NextResponse.json(result, { status: result.ok ? 200 : 422 });
}
