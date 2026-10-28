import Shell from "@/components/Shell";
import LogsView from "@/components/LogsView";

export default function Page() {
  return (
    <Shell crumb={<b>Logs</b>}>
      <LogsView />
    </Shell>
  );
}
