import Shell from "@/components/Shell";
import DalfoxView from "@/components/DalfoxView";

export default function Page() {
  return (
    <Shell crumb={<><span>Vulnerability</span> / <b>Dalfox (XSS)</b></>}>
      <DalfoxView />
    </Shell>
  );
}
