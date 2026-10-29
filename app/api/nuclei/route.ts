import { NextResponse } from "next/server";
import { normaliseTargets, validateNuclei, type NucleiRequest } from "@/lib/nuclei-core";
import { runNuclei } from "@/lib/modules/nuclei-scan";
import { toolPath } from "@/lib/tools";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => String(x)) : []);

export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }
  // The user must confirm they are allowed to test these targets before any request is sent.
  if (body.authorized !== true) return NextResponse.json({ ok: false, error: "Confirm that you are authorised to test these targets." }, { status: 400 });

  const targets = normaliseTargets(String(body.targets ?? "").split(/[\s,]+/));
  if (targets.error) return NextResponse.json({ ok: false, error: targets.error }, { status: 400 });

  const request: NucleiRequest = {
    targets: targets.targets,
    severities: strings(body.severities),
    tags: strings(body.tags),
    templates: strings(body.templates),
    automatic: body.automatic === true,
    rateLimit: Number(body.rateLimit) || 50,
    concurrency: Number(body.concurrency) || 10,
  };
  const problem = validateNuclei(request);
  if (problem) return NextResponse.json({ ok: false, error: problem }, { status: 400 });

  if (!(await toolPath("nuclei"))) {
    return NextResponse.json({ ok: false, code: "tool_missing", error: "nuclei is not installed. Install it on the Tools page." }, { status: 503 });
  }
  const result = await runNuclei(request);
  if (!result.ok) return NextResponse.json({ ok: false, command: result.command, error: result.error }, { status: 500 });
  return NextResponse.json({ ok: true, command: result.command, rawCount: result.rawCount, findings: result.findings, targets: request.targets.length });
}
