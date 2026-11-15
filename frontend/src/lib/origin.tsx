"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Origin, OriginFilter } from "./types";

const KEY = "sentinelx.origin";

interface OriginState {
  origin: OriginFilter;
  setOrigin: (value: OriginFilter) => void;
  /** Value to send as the `origin` query parameter (undefined = both). */
  param: Origin | undefined;
}

const OriginContext = createContext<OriginState | null>(null);

export function OriginProvider({ children }: { children: ReactNode }) {
  const [origin, setOriginState] = useState<OriginFilter>("all");

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(KEY);
      if (saved === "real" || saved === "simulated" || saved === "all") setOriginState(saved);
    } catch {
      /* ignore */
    }
  }, []);

  const setOrigin = useCallback((value: OriginFilter) => {
    setOriginState(value);
    try {
      window.localStorage.setItem(KEY, value);
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo(
    () => ({ origin, setOrigin, param: origin === "all" ? undefined : origin }),
    [origin, setOrigin],
  );
  return <OriginContext.Provider value={value}>{children}</OriginContext.Provider>;
}

export function useOrigin(): OriginState {
  const ctx = useContext(OriginContext);
  if (!ctx) throw new Error("useOrigin must be used inside OriginProvider");
  return ctx;
}
