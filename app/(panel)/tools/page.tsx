import Shell from "@/components/Shell";
import ToolsView from "@/components/ToolsView";

export default function Page() {
  return (
    <Shell crumb={<b>Tools</b>}>
      <ToolsView />
    </Shell>
  );
}
