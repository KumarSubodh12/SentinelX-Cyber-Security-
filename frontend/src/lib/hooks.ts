"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";

type Query = Record<string, string | number | boolean | null | undefined>;

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

interface UseApiOptions {
  /** Poll every N milliseconds. */
  every?: number;
  /** Change this value to force a refetch (for example a live-update counter). */
  refreshKey?: number;
  /** Pass false to skip fetching (for example while a sheet is closed). */
  enabled?: boolean;
}

/** Fetches `path` with `query`, refetching when they change. Keeps old data visible while reloading. */
export function useApi<T>(path: string, query: Query = {}, options: UseApiOptions = {}): ApiState<T> {
  const { every, refreshKey = 0, enabled = true } = options;
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [counter, setCounter] = useState(0);
  const queryKey = JSON.stringify(query);
  const first = useRef(true);

  // A different query is a different dataset: show the loading state again.
  useEffect(() => {
    first.current = true;
  }, [path, queryKey]);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    if (first.current) setLoading(true);

    const run = async () => {
      try {
        const result = await api<T>(path, { query: JSON.parse(queryKey) as Query });
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Something went wrong");
      } finally {
        if (!cancelled) {
          setLoading(false);
          first.current = false;
        }
      }
    };

    void run();
    const timer = every ? window.setInterval(run, every) : undefined;
    return () => {
      cancelled = true;
      if (timer) window.clearInterval(timer);
    };
  }, [path, queryKey, every, refreshKey, counter, enabled]);

  const reload = useCallback(() => setCounter((c) => c + 1), []);
  return { data, error, loading, reload };
}

/** Returns a value that only changes after `delay` ms without further changes (for search boxes). */
export function useDebounced<T>(value: T, delay = 350): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}
