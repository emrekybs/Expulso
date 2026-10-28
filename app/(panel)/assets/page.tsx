import Shell from "@/components/Shell";
import AssetsView from "@/components/AssetsView";

export default function Page() {
  return (
    <Shell crumb={<b>Asset Inventory</b>}>
      <AssetsView />
    </Shell>
  );
}
