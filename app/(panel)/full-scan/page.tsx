import { Suspense } from "react";
import Shell from "@/components/Shell";
import FullScanView from "@/components/FullScanView";

export default function Page() {
  return (
    <Shell crumb={<b>Full Scan</b>}>
      <Suspense fallback={null}>
        <FullScanView />
      </Suspense>
    </Shell>
  );
}
