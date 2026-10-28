import { NextResponse } from "next/server";
import fs from "node:fs";
import { toolStatuses } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  let chromium: { path: string | null; ok: boolean } = { path: null, ok: false };
  try {
    const pw = await import("playwright");
    const exe = process.env.CHROMIUM_PATH || pw.chromium.executablePath();
    chromium = { path: exe, ok: fs.existsSync(exe) };
  } catch {
    chromium = { path: null, ok: false };
  }
  return NextResponse.json({
    tools: await toolStatuses(),
    chromium: { ...chromium, install: "npx playwright install chromium" },
  });
}
