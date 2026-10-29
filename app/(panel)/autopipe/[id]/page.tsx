import Shell from "@/components/Shell";
import AutopipeRunView from "@/components/AutopipeRunView";

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <Shell crumb={<><span>Autopipeline</span> / <b>Run</b></>}>
      <AutopipeRunView id={id} />
    </Shell>
  );
}
