import { ALL_STAGES_ON, validatePipeline, type PipelineRequest, type StageId, type StatusFilter } from "./autopipe-core.ts";

/** Reads the request body into a PipelineRequest. Returns an error message when it is not valid. */
export function parsePipelineBody(body: Record<string, unknown>): { request: PipelineRequest } | { error: string } {
  const targets = String(body.targets ?? "").split(/[\s,]+/).map((t) => t.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "")).filter(Boolean);
  const stagesIn = (body.stages ?? {}) as Partial<Record<StageId, boolean>>;
  const stages = { ...ALL_STAGES_ON };
  for (const k of Object.keys(ALL_STAGES_ON) as StageId[]) if (typeof stagesIn[k] === "boolean") stages[k] = stagesIn[k]!;
  const request: PipelineRequest = {
    targets: [...new Set(targets)],
    stages,
    statusFilter: (body.statusFilter as StatusFilter) ?? "2xx",
    hostLimit: Number(body.hostLimit) || 30,
    nucleiTags: Array.isArray(body.nucleiTags) ? body.nucleiTags.map(String) : [],
    urlLimit: Number(body.urlLimit) || 30,
    authorized: body.authorized === true,
  };
  const problem = validatePipeline(request);
  return problem ? { error: problem } : { request };
}
