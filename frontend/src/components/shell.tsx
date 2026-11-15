"use client";

import { Activity, Briefcase, FileText, Globe, LayoutDashboard, LogOut, Menu, Settings, ShieldAlert, TrendingUp, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { useAuth } from "@/lib/auth";
import { useDetail } from "@/lib/detail";
import { timeAgo } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import { useLive, type LiveStatus } from "@/lib/live";
import { useOrigin } from "@/lib/origin";
import type { Alert, OriginFilter, Page } from "@/lib/types";
import { cn } from "@/lib/utils";
import { SeverityBadge } from "./badges";
import { Beacon, POSTURE_TEXT, type Posture } from "./beacon";
import { Button } from "./ui/button";
import { Segmented } from "./ui/misc";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/live", label: "Live events", icon: Activity },
  { href: "/alerts", label: "Alerts", icon: ShieldAlert },
  { href: "/incidents", label: "Incidents", icon: Briefcase },
  { href: "/ips", label: "IP intelligence", icon: Globe },
  { href: "/analytics", label: "AI analytics", icon: TrendingUp },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
] as const;

const ORIGIN_OPTIONS: { value: OriginFilter; label: string }[] = [
  { value: "all", label: "All data" },
  { value: "real", label: "Real" },
  { value: "simulated", label: "Simulated" },
];

/** Highest-risk active alert decides the colour of the beacon; the total feeds the Alerts badge. */
function usePosture(): { posture: Posture; active: number } {
  const { param } = useOrigin();
  const { refreshKey } = useDetail();
  const { data } = useApi<Page<Alert>>(
    "/api/alerts",
    { status: "active", sort: "risk", page_size: 1, origin: param },
    { refreshKey, every: 60_000 },
  );
  const top = data?.items[0];
  let posture: Posture = "calm";
  if (top) {
    if (top.severity === "critical") posture = "critical";
    else if (top.severity === "high") posture = "high";
    else posture = "attention";
  }
  return { posture, active: data?.total ?? 0 };
}

function SidebarContent({ onNavigate, posture, active }: { onNavigate?: () => void; posture: Posture; active: number }) {
  const pathname = usePathname() ?? "";
  const { alertVersion } = useLive();
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 px-4 py-4">
        <Beacon posture={posture} pulseKey={alertVersion} />
        <div className="min-w-0">
          <p className="text-base font-semibold leading-tight text-ink">SentinelX</p>
          <p className="truncate text-xs text-ink-3">{POSTURE_TEXT[posture]}</p>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 px-2 py-2" aria-label="Main">
        {NAV.map((item) => {
          const selected = pathname === item.href || pathname.startsWith(`${item.href}/`);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={onNavigate}
              aria-current={selected ? "page" : undefined}
              className={cn(
                "flex items-center gap-3 rounded px-3 py-2 text-sm transition-colors",
                selected ? "bg-raised text-ink" : "text-ink-2 hover:bg-raised/60 hover:text-ink",
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              <span className="flex-1">{item.label}</span>
              {item.href === "/alerts" && active > 0 ? <span className="num rounded bg-line px-1.5 py-0.5 text-xs text-ink">{active > 99 ? "99+" : active}</span> : null}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-line px-4 py-3">
        <p className="text-xs font-medium text-ink-2">SentinelX</p>
        <p className="mt-0.5 text-[11px] text-ink-3">Developed by Kumar Subodh</p>
      </div>
    </div>
  );
}

const LIVE_STYLE: Record<LiveStatus, { dot: string; text: string }> = {
  live: { dot: "bg-good", text: "Live" },
  connecting: { dot: "bg-sev-medium", text: "Connecting" },
  offline: { dot: "bg-sev-critical", text: "Offline, retrying" },
};

function LivePill() {
  const { status } = useLive();
  const style = LIVE_STYLE[status];
  return (
    <span className="inline-flex items-center gap-2 rounded border border-line px-2.5 py-1 text-xs text-ink-2" role="status">
      <span className={cn("h-2 w-2 rounded-full", style.dot)} />
      {style.text}
    </span>
  );
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const { user, logout } = useAuth();
  const { origin, setOrigin } = useOrigin();
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-page/95 backdrop-blur">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 sm:px-6">
        <Button variant="ghost" size="icon" className="lg:hidden" onClick={onMenu} aria-label="Open menu">
          <Menu className="h-5 w-5" />
        </Button>
        <LivePill />
        <div className="ml-auto flex flex-wrap items-center gap-3">
          <Segmented<OriginFilter> label="Data shown" value={origin} options={ORIGIN_OPTIONS} onChange={setOrigin} />
          <div className="flex items-center gap-2">
            <div className="hidden text-right sm:block">
              <p className="text-sm leading-tight text-ink">{user?.full_name || user?.username}</p>
              <p className="text-xs capitalize text-ink-3">{user?.role}</p>
            </div>
            <Button variant="ghost" size="icon" onClick={logout} aria-label="Sign out" title="Sign out">
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
      {origin === "simulated" ? (
        <p className="border-t border-sim/40 bg-sim/10 px-4 py-1.5 text-xs text-ink sm:px-6">
          Showing simulated test data only. Nothing here comes from a real system.
        </p>
      ) : null}
    </header>
  );
}

function Toasts() {
  const { toasts, dismissToast } = useLive();
  const { openAlert } = useDetail();
  if (toasts.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
      {toasts.map(({ id, alert }) => (
        <div key={id} className="pointer-events-auto animate-slidein rounded-lg border border-line bg-raised p-3">
          <div className="flex items-start justify-between gap-2">
            <SeverityBadge severity={alert.severity} />
            <button type="button" aria-label="Dismiss" className="text-ink-3 hover:text-ink" onClick={() => dismissToast(id)}>
              <X className="h-4 w-4" />
            </button>
          </div>
          <button
            type="button"
            className="mt-2 block w-full text-left"
            onClick={() => {
              dismissToast(id);
              openAlert(alert.id);
            }}
          >
            <span className="block text-sm font-medium text-ink">{alert.title}</span>
            <span className="mt-0.5 block text-xs text-ink-3">
              {alert.source_ip ? `${alert.source_ip}, ` : ""}
              {timeAgo(alert.last_seen)}
            </span>
          </button>
        </div>
      ))}
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const pathname = usePathname() ?? "";
  const { posture, active } = usePosture();

  useEffect(() => setMenuOpen(false), [pathname]);

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[232px_minmax(0,1fr)]">
      <aside className="sticky top-0 hidden h-screen border-r border-line bg-panel lg:block">
        <SidebarContent posture={posture} active={active} />
      </aside>

      {menuOpen ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMenuOpen(false)} aria-hidden="true" />
          <aside className="relative h-full w-[260px] animate-slidein border-r border-line bg-panel">
            <SidebarContent posture={posture} active={active} onNavigate={() => setMenuOpen(false)} />
          </aside>
        </div>
      ) : null}

      <div className="flex min-w-0 flex-col">
        <Topbar onMenu={() => setMenuOpen(true)} />
        <main className="flex-1 px-4 py-5 sm:px-6">{children}</main>
      </div>
      <Toasts />
    </div>
  );
}
