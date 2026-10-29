import Shell from "@/components/Shell";
import SqliView from "@/components/SqliView";

export default function Page() {
  return (
    <Shell crumb={<><span>Vulnerability</span> / <b>SQL Injection</b></>}>
      <SqliView />
    </Shell>
  );
}
