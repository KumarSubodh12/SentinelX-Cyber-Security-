"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { getToken, wsUrl } from "./api";
import type { Alert, EventRow } from "./types";

export type LiveStatus = "connecting" | "live" | "offline";

interface Toast {
  id: number;
  alert: Alert;
}

interface LiveState {
  status: LiveStatus;
  /** Newest first, capped at 300. */
  events: EventRow[];
  /** Increments whenever an alert or incident changes, so pages can refetch. */
  alertVersion: number;
  /** Increments whenever new events arrive. */
  eventVersion: number;
  toasts: Toast[];
  dismissToast: (id: number) => void;
}

const LiveContext = createContext<LiveState | null>(null);
const MAX_EVENTS = 300;

export function LiveProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const [events, setEvents] = useState<EventRow[]>([]);
  const [alertVersion, setAlertVersion] = useState(0);
  const [eventVersion, setEventVersion] = useState(0);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastId = useRef(0);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retry = 1000;
    let closed = false;
    let pingTimer: number | undefined;
    let retryTimer: number | undefined;
    let bumpTimer: number | undefined;

    const bumpAlerts = () => {
      // Several alert messages can arrive in one burst: refetch once.
      window.clearTimeout(bumpTimer);
      bumpTimer = window.setTimeout(() => setAlertVersion((v) => v + 1), 400);
    };

    const connect = () => {
      const token = getToken();
      if (!token || closed) return;
      setStatus("connecting");
      socket = new WebSocket(wsUrl(token));

      socket.onopen = () => {
        retry = 1000;
        pingTimer = window.setInterval(() => socket?.readyState === WebSocket.OPEN && socket.send("ping"), 25_000);
      };

      socket.onmessage = (message) => {
        let payload: { type: string; data?: unknown };
        try {
          payload = JSON.parse(message.data as string);
        } catch {
          return;
        }
        switch (payload.type) {
          case "hello":
            setStatus("live");
            break;
          case "events": {
            const rows = payload.data as EventRow[];
            setEvents((prev) => [...[...rows].reverse(), ...prev].slice(0, MAX_EVENTS));
            setEventVersion((v) => v + 1);
            break;
          }
          case "alert": {
            const alert = payload.data as Alert;
            bumpAlerts();
            if (alert.severity === "critical" || alert.severity === "high") {
              const id = ++toastId.current;
              setToasts((t) => [...t.slice(-3), { id, alert }]);
              window.setTimeout(() => dismissToast(id), 9000);
            }
            break;
          }
          case "alert_update":
          case "incident":
          case "agent_status":
            bumpAlerts();
            break;
          default:
            break;
        }
      };

      socket.onclose = () => {
        window.clearInterval(pingTimer);
        if (closed) return;
        setStatus("offline");
        retryTimer = window.setTimeout(connect, retry);
        retry = Math.min(retry * 2, 15_000);
      };
      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      closed = true;
      window.clearInterval(pingTimer);
      window.clearTimeout(retryTimer);
      window.clearTimeout(bumpTimer);
      socket?.close();
    };
  }, [dismissToast]);

  const value = useMemo(
    () => ({ status, events, alertVersion, eventVersion, toasts, dismissToast }),
    [status, events, alertVersion, eventVersion, toasts, dismissToast],
  );
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveState {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive must be used inside LiveProvider");
  return ctx;
}
