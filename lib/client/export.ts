"use client";

export function download(filename: string, content: string, mime = "text/plain") {
  try {
    const blob = new Blob([content], { type: `${mime};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch {
    /* ignore */
  }
}

export function toCsv(rows: readonly object[], columns?: string[]): string {
  if (!rows.length) return "";
  const recs = rows as readonly Record<string, unknown>[];
  const cols = columns ?? [...new Set(recs.flatMap((r) => Object.keys(r)))];
  const esc = (v: unknown) => {
    const s = v == null ? "" : Array.isArray(v) ? v.join("; ") : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(","), ...recs.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function slug(s: string): string {
  return s.replace(/[^a-z0-9.-]+/gi, "_").slice(0, 60);
}

export function stamp(): string {
  return new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
}
