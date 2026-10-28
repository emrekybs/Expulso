import { NextResponse } from "next/server";
import { getModule, type ModuleId } from "@/lib/modules-config";
import { parseTarget, type ParsedTarget } from "@/lib/target";
import { UserError } from "@/lib/net";
import { runUscrapper } from "@/lib/modules/uscrapper";
import { runSubdomains } from "@/lib/modules/subdomains";
import { runDns } from "@/lib/modules/dns";
import { runWhois } from "@/lib/modules/whois";
import { runGeoip } from "@/lib/modules/geoip";
import { runReverseDns, runReverseIp, runPortScan, runTraceroute } from "@/lib/modules/network";
import { runSecurity } from "@/lib/modules/security";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

type Options = Record<string, unknown>;

const RUNNERS: Record<ModuleId, (t: ParsedTarget, o: Options) => Promise<unknown>> = {
  uscrapper: (t, o) =>
    runUscrapper(t, {
      crawl: Number(o.crawl) || 0,
      threads: Number(o.threads) || 4,
      nonStrict: o.nonStrict === true,
      keywords: Array.isArray(o.keywords) ? o.keywords.map(String) : [],
    }),
  subdomain: (t, o) => runSubdomains(t, { resolve: o.resolve !== false }),
  dns: (t) => runDns(t),
  whois: (t) => runWhois(t),
  "reverse-ip": (t) => runReverseIp(t),
  geoip: (t) => runGeoip(t),
  "reverse-dns": (t) => runReverseDns(t),
  traceroute: (t) => runTraceroute(t),
  "port-scan": (t) => runPortScan(t),
  security: (t) => runSecurity(t),
};

export async function POST(req: Request, ctx: { params: Promise<{ module: string }> }) {
  const { module } = await ctx.params;
  const def = getModule(module);
  if (!def) return NextResponse.json({ ok: false, error: "Bilinmeyen modül." }, { status: 404 });

  let body: { target?: unknown; options?: Options };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Geçersiz istek gövdesi." }, { status: 400 });
  }
  const parsed = parseTarget(String(body.target ?? ""));
  if ("error" in parsed) return NextResponse.json({ ok: false, error: parsed.error }, { status: 400 });
  if (!def.accepts.includes(parsed.kind)) {
    return NextResponse.json({ ok: false, error: `${def.short} modülü bu hedef türünü desteklemiyor.` }, { status: 400 });
  }

  const started = Date.now();
  try {
    const data = await RUNNERS[def.id](parsed, body.options ?? {});
    return NextResponse.json({
      ok: true,
      data,
      meta: { module: def.id, target: parsed.host, kind: parsed.kind, durationMs: Date.now() - started, scannedAt: new Date().toISOString() },
    });
  } catch (e) {
    const message = e instanceof UserError ? e.message : "Beklenmeyen bir hata oluştu. Lütfen daha sonra tekrar deneyin.";
    if (!(e instanceof UserError)) console.error(`[${def.id}]`, e);
    return NextResponse.json({ ok: false, error: message }, { status: e instanceof UserError ? 422 : 500 });
  }
}
