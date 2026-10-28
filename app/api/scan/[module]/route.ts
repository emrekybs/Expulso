import { NextResponse } from "next/server";
import crypto from "node:crypto";
import { getModule } from "@/lib/modules-config";
import { parseTarget } from "@/lib/target";
import { runModule } from "@/lib/run-module";
import type { ScanResponse } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function POST(req: Request, ctx: { params: Promise<{ module: string }> }) {
  const requestId = crypto.randomUUID().slice(0, 8);
  const { module } = await ctx.params;
  const def = getModule(module);
  if (!def) return json({ ok: false, error: "Unknown module.", code: "unknown_module", requestId }, 404);

  let body: { target?: unknown; options?: Record<string, unknown> };
  try {
    body = await req.json();
  } catch {
    return json({ ok: false, error: "Invalid request body.", code: "bad_request", requestId }, 400);
  }
  const parsed = parseTarget(String(body.target ?? ""));
  if ("error" in parsed) return json({ ok: false, error: parsed.error, code: "invalid_target", requestId }, 400);
  if (!def.accepts.includes(parsed.kind))
    return json({ ok: false, error: `${def.title} does not accept a ${parsed.kind} target.`, code: "not_applicable", requestId, skipped: true }, 400);

  const scannedAt = new Date().toISOString();
  const run = await runModule(def.id, parsed, body.options ?? {});
  if (!run.ok || !run.result) {
    console.log(`[scan ${requestId}] ${def.id} ${parsed.host} FAILED (${run.code}) in ${run.durationMs}ms: ${run.error}`);
    return json({ ok: false, error: run.error ?? "Failed.", code: run.code ?? "error", requestId, skipped: run.skipped }, run.code === "internal_error" ? 500 : 422);
  }
  console.log(`[scan ${requestId}] ${def.id} ${parsed.host} OK in ${run.durationMs}ms`);
  return json({ ok: true, result: run.result, meta: { module: def.id, target: parsed.host, kind: parsed.kind, durationMs: run.durationMs, scannedAt, requestId } });
}

function json(payload: ScanResponse, status = 200) {
  return NextResponse.json(payload, { status });
}
