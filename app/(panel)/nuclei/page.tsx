import Shell from "@/components/Shell";
import NucleiView from "@/components/NucleiView";

export default function Page() {
  return (
    <Shell crumb={<><span>Vulnerability</span> / <b>Nuclei</b></>}>
      <NucleiView />
    </Shell>
  );
}
