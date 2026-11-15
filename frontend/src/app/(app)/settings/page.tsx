"use client";

import { useEffect, useState } from "react";
import { AgentsTab } from "@/components/settings/agents-tab";
import { AuditTab } from "@/components/settings/audit-tab";
import { NotificationsTab } from "@/components/settings/notifications-tab";
import { RulesTab } from "@/components/settings/rules-tab";
import { SimulatorTab } from "@/components/settings/simulator-tab";
import { UsersTab } from "@/components/settings/users-tab";
import { Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/panel";

type TabKey = "agents" | "rules" | "notifications" | "users" | "simulator" | "audit";

const TABS: { value: TabKey; label: string }[] = [
  { value: "agents", label: "Agents" },
  { value: "rules", label: "Detection rules" },
  { value: "notifications", label: "Alerts and notifications" },
  { value: "users", label: "Users" },
  { value: "simulator", label: "Simulator" },
  { value: "audit", label: "Audit log" },
];

export default function SettingsPage() {
  const [tab, setTab] = useState<TabKey>("agents");

  // Links like /settings#users open that tab.
  useEffect(() => {
    const fromHash = window.location.hash.replace("#", "") as TabKey;
    if (TABS.some((t) => t.value === fromHash)) setTab(fromHash);
  }, []);

  function choose(next: TabKey) {
    setTab(next);
    window.history.replaceState(null, "", `#${next}`);
  }

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader title="Settings" description="Connect systems, tune detection, and manage who can use SentinelX." />
      <Tabs<TabKey> value={tab} tabs={TABS} onChange={choose} />
      <div className="pt-5">
        {tab === "agents" ? <AgentsTab /> : null}
        {tab === "rules" ? <RulesTab /> : null}
        {tab === "notifications" ? <NotificationsTab /> : null}
        {tab === "users" ? <UsersTab /> : null}
        {tab === "simulator" ? <SimulatorTab /> : null}
        {tab === "audit" ? <AuditTab /> : null}
      </div>
    </div>
  );
}
