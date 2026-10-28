import Shell from "@/components/Shell";
import Overview from "@/components/Overview";

export default function Page() {
  return (
    <Shell crumb={<b>Overview</b>}>
      <Overview />
    </Shell>
  );
}
