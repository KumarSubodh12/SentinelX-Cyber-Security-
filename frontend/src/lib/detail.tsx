"use client";

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { useLive } from "./live";

export type DetailTarget = { kind: "alert"; id: number } | { kind: "incident"; id: number } | { kind: "ip"; ip: string };

interface DetailState {
  current: DetailTarget | null;
  canBack: boolean;
  openAlert: (id: number) => void;
  openIncident: (id: number) => void;
  openIp: (ip: string) => void;
  back: () => void;
  close: () => void;
  /** Call after a change made from a detail panel so lists refetch even when the WebSocket is down. */
  bump: () => void;
  /** Add to a useApi refreshKey: changes on live alert updates AND on local changes. */
  refreshKey: number;
}

const DetailContext = createContext<DetailState | null>(null);

/** One shared detail panel (alert / incident / IP) that any page can open. Keeps a small back stack. */
export function DetailProvider({ children }: { children: ReactNode }) {
  const { alertVersion } = useLive();
  const [stack, setStack] = useState<DetailTarget[]>([]);
  const [version, setVersion] = useState(0);

  const push = useCallback((target: DetailTarget) => setStack((s) => [...s, target].slice(-6)), []);
  const openAlert = useCallback((id: number) => push({ kind: "alert", id }), [push]);
  const openIncident = useCallback((id: number) => push({ kind: "incident", id }), [push]);
  const openIp = useCallback((ip: string) => push({ kind: "ip", ip }), [push]);
  const back = useCallback(() => setStack((s) => s.slice(0, -1)), []);
  const close = useCallback(() => setStack([]), []);
  const bump = useCallback(() => setVersion((v) => v + 1), []);

  const value = useMemo<DetailState>(
    () => ({
      current: stack.length > 0 ? stack[stack.length - 1] : null,
      canBack: stack.length > 1,
      openAlert,
      openIncident,
      openIp,
      back,
      close,
      bump,
      refreshKey: alertVersion + version,
    }),
    [stack, openAlert, openIncident, openIp, back, close, bump, alertVersion, version],
  );
  return <DetailContext.Provider value={value}>{children}</DetailContext.Provider>;
}

export function useDetail(): DetailState {
  const ctx = useContext(DetailContext);
  if (!ctx) throw new Error("useDetail must be used inside DetailProvider");
  return ctx;
}
