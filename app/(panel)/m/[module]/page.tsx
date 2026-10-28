import { notFound } from "next/navigation";
import { getModule } from "@/lib/modules-config";
import Shell from "@/components/Shell";
import ModuleRunner from "@/components/ModuleRunner";
import { moduleIcon } from "@/components/icons";

export function generateStaticParams() {
  return [];
}

export default async function ModulePage({ params }: { params: Promise<{ module: string }> }) {
  const { module } = await params;
  const def = getModule(module);
  if (!def) notFound();

  return (
    <Shell crumb={<><span>{def.group}</span> / <b>{def.title}</b></>}>
      <div className="page-head">
        <div className="page-icon">{moduleIcon(def.id, 22)}</div>
        <div>
          <h1>{def.title}</h1>
          <p>{def.description}</p>
          <div className="chips">
            <span className={`tier ${def.tier}`}>{def.tier === "passive" ? "Passive" : def.tier === "light" ? "Light" : "Active"}</span>
            <span className="chip">Accepts: {def.accepts.join(", ")}</span>
            <span className="chip">Sources: {def.sources.join(", ")}</span>
          </div>
        </div>
      </div>
      <ModuleRunner def={def} />
    </Shell>
  );
}
