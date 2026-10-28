import Shell from "@/components/Shell";
import HistoryView from "@/components/HistoryView";

export default function Page() {
  return (
    <Shell crumb={<b>History</b>}>
      <HistoryView />
    </Shell>
  );
}
