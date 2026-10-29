"use client";
import { NUCLEI_TAG_GROUPS } from "@/lib/nuclei-core";

/** Grouped nuclei tag chips. Selection is shared by the Nuclei, SQL and XSS pages. */
export default function NucleiTagPicker({ selected, onChange }: { selected: string[]; onChange: (tags: string[]) => void }) {
  const toggle = (t: string) => onChange(selected.includes(t) ? selected.filter((x) => x !== t) : [...selected, t]);
  return (
    <div className="stack" style={{ gap: 10 }}>
      {NUCLEI_TAG_GROUPS.map((g) => (
        <div key={g.label}>
          <div className="muted small" style={{ marginBottom: 6 }}>{g.label}</div>
          <div className="chips">
            {g.tags.map((t) => (
              <button key={t} type="button" className={`chip${selected.includes(t) ? " on" : ""}`} onClick={() => toggle(t)}>
                {t}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
