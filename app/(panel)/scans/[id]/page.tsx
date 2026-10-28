import Shell from "@/components/Shell";
import ScanDetailView from "@/components/ScanDetailView";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <Shell crumb={<><span>History</span> / <b>Scan</b></>}>
      <ScanDetailView id={id} />
    </Shell>
  );
}
