"use client";
import { download, toCsv, slug, stamp } from "@/lib/client/export";
import { CopyBtn } from "./ui";

export function ExportBar({ baseName, rows, json, text }: { baseName: string; rows?: readonly object[]; json?: unknown; text?: string }) {
  const name = `${slug(baseName)}_${stamp()}`;
  return (
    <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
      {text != null && <CopyBtn text={text} label="Copy" />}
      {text != null && (
        <button type="button" className="btn btn-sm" onClick={() => download(`${name}.txt`, text)}>
          TXT
        </button>
      )}
      {rows && rows.length > 0 && (
        <button type="button" className="btn btn-sm" onClick={() => download(`${name}.csv`, toCsv(rows), "text/csv")}>
          CSV
        </button>
      )}
      {json != null && (
        <button type="button" className="btn btn-sm" onClick={() => download(`${name}.json`, JSON.stringify(json, null, 2), "application/json")}>
          JSON
        </button>
      )}
    </span>
  );
}
