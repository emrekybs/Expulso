import fs from "node:fs/promises";
import path from "node:path";
import { SHOT_DIR } from "@/lib/screenshot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: Request, ctx: { params: Promise<{ file: string }> }) {
  const { file } = await ctx.params;
  // Only plain PNG file names from the screenshot folder; no path segments.
  if (!/^[a-z0-9._-]+\.png$/i.test(file)) return new Response("Not found", { status: 404 });
  try {
    const data = await fs.readFile(path.join(SHOT_DIR, file));
    return new Response(new Uint8Array(data), { headers: { "content-type": "image/png", "cache-control": "no-cache" } });
  } catch {
    return new Response("Not found", { status: 404 });
  }
}
