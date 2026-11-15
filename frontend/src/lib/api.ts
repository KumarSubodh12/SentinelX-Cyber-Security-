const TOKEN_KEY = "sentinelx.token";

declare global {
  interface Window {
    __SENTINELX_CONFIG__?: { apiUrl?: string };
  }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Backend base URL. Empty string = same origin (production behind the reverse proxy). */
export function apiBase(): string {
  if (typeof window !== "undefined") {
    const runtime = window.__SENTINELX_CONFIG__?.apiUrl;
    if (runtime) return runtime.replace(/\/$/, "");
  }
  return (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/$/, "");
}

export function wsUrl(token: string): string {
  const base = apiBase() || window.location.origin;
  return `${base.replace(/^http/, "ws")}/ws?token=${encodeURIComponent(token)}`;
}

export function getToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (private mode) - the session simply will not persist */
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

export function qs(params: Query = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

interface Options {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Query;
}

function messageFrom(payload: unknown, fallback: string): string {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      const first = detail[0] as { msg?: string; loc?: unknown[] };
      const field = Array.isArray(first.loc) ? String(first.loc[first.loc.length - 1]) : "";
      return field ? `${field}: ${first.msg ?? "invalid value"}` : first.msg ?? fallback;
    }
  }
  return fallback;
}

function handleUnauthorized(): void {
  setToken(null);
  if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
    window.location.href = "/login?expired=1";
  }
}

export async function api<T>(path: string, options: Options = {}): Promise<T> {
  // A sign-in request must not carry an old token, and a 401 on it means "wrong password", not "expired".
  const isLogin = path === "/api/auth/login";
  const token = isLogin ? null : getToken();
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(`${apiBase()}${path}${qs(options.query)}`, {
      method: options.method ?? "GET",
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "Cannot reach the SentinelX server. Check that the backend is running.");
  }

  if (response.status === 401 && token) {
    handleUnauthorized();
    throw new ApiError(401, "Your session has expired. Please sign in again.");
  }
  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!response.ok) {
    throw new ApiError(response.status, messageFrom(payload, `Request failed (${response.status})`));
  }
  return payload as T;
}

/** Downloads an authenticated file (CSV / HTML report) through the browser. */
export async function downloadFile(path: string, query: Query, filename: string): Promise<void> {
  const token = getToken();
  const response = await fetch(`${apiBase()}${path}${qs(query)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    cache: "no-store",
  });
  if (!response.ok) throw new ApiError(response.status, `Download failed (${response.status})`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
