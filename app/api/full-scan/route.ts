import { NextResponse } from "next/server";
import crypto from "node:crypto";
import { modulesForMode, type ScanMode, getModule } from "@/lib/modules-config";
import { parseTarget } from "@/lib/target";
import { runModule } from "@/lib/run-module";
import { SEVERITY_ORDER, type Finding } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

// Runs the modules for ONE target and one mode. The client drives multiple targets,
// so each HTTP request stays inside the serverless time limit.
export async function POST(req: Request) {
  const requestId = crypto.randomUUID().slice(0, 8);
  let body: { target?: unknown; mode?: unknown; options?: Record<string, Record<string, unknown>> };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body.", requestId }, { status: 400 });
  }
  const mode: ScanMode = body.mode === "active" || body.mode === "full" ? (body.mode as ScanMode) : "passive";
  const parsed = parseTarget(String(body.target ?? ""));
  if ("error" in parsed) return NextResponse.json({ ok: false, error: parsed.error, requestId }, { status: 400 });

  const mods = modulesForMode(mode).filter((m) => m.accepts.includes(parsed.kind));
  const scannedAt = new Date().toISOString();

  const modules = await Promise.all(
    mods.map(async (def) => {
      const opts = { ...Object.fromEntries((def.options ?? []).map((o) => [o.key, o.default])), ...(def.fullScanOptions ?? {}), ...(body.options?.[def.id] ?? {}) };
      const run = await runModule(def.id, parsed, opts);
      console.log(`[full ${requestId}] ${def.id} ${parsed.host} ${run.ok ? "OK" : run.code} ${run.durationMs}ms`);
      if (run.ok && run.result) {
        return {
          id: def.id,
          title: def.title,
          tier: def.tier,
          ok: true as const,
          summary: run.result.summary,
          findings: run.result.findings,
          data: run.result.data,
          warnings: run.result.warnings ?? [],
          sources: run.result.sources ?? [],
          durationMs: run.durationMs,
        };
      }
      return { id: def.id, title: def.title, tier: def.tier, ok: false as const, error: run.error, code: run.code, durationMs: run.durationMs };
    }),
  );

  const findings: (Finding & { module: string })[] = modules
    .filter((m) => m.ok)
    .flatMap((m) => (m as { findings: Finding[]; title: string }).findings.map((f) => ({ ...f, module: (m as { title: string }).title })))
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;

  return NextResponse.json({
    ok: true,
    meta: { target: parsed.host, kind: parsed.kind, mode, scannedAt, requestId, moduleCount: modules.length },
    findings,
    counts,
    modules,
  });
}

void getModule;
