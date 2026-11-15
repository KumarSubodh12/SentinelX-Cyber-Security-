// Serves window.__SENTINELX_CONFIG__ at request time.
//
// NEXT_PUBLIC_* variables are baked into the bundle when `next build` runs, which would force a new image
// for every environment. This route reads API_PUBLIC_URL when the container starts instead.
//
//   API_PUBLIC_URL=""                      -> same origin (production behind Caddy: /api and /ws)
//   API_PUBLIC_URL="https://api.example"   -> backend on another domain (Render, split hosting)
//   API_PUBLIC_URL not set                 -> "next dev": http://localhost:8000, "next start": same origin

export const dynamic = "force-dynamic";

export function GET(): Response {
  const fallback = process.env.NODE_ENV === "production" ? "" : "http://localhost:8000";
  const apiUrl = (process.env.API_PUBLIC_URL ?? fallback).trim().replace(/\/+$/, "");
  // "<" is escaped so the value can never close the script element.
  const payload = JSON.stringify({ apiUrl }).replace(/</g, "\\u003c");
  return new Response(`window.__SENTINELX_CONFIG__ = ${payload};\n`, {
    headers: {
      "Content-Type": "application/javascript; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
