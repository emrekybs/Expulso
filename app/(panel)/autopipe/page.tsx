import Shell from "@/components/Shell";
import AutopipeView from "@/components/AutopipeView";

export default function Page() {
  return (
    <Shell crumb={<b>Autopipeline</b>}>
      <AutopipeView />
    </Shell>
  );
}
