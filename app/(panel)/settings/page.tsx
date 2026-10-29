import Shell from "@/components/Shell";
import SettingsView from "@/components/SettingsView";

export default function Page() {
  return (
    <Shell crumb={<b>Settings</b>}>
      <SettingsView />
    </Shell>
  );
}
