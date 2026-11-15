"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { Beacon } from "@/components/beacon";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/form";
import { Notice } from "@/components/ui/misc";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const router = useRouter();
  const { user, loading, login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [expired, setExpired] = useState(false);

  useEffect(() => {
    setExpired(new URLSearchParams(window.location.search).get("expired") === "1");
  }, []);

  useEffect(() => {
    if (!loading && user) router.replace("/dashboard");
  }, [loading, user, router]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(username.trim(), password);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign in");
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-3">
          <Beacon posture="calm" size={36} />
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-ink">SentinelX</h1>
            <p className="text-sm text-ink-2">Sign in to the security console</p>
          </div>
        </div>

        <form onSubmit={onSubmit} className="space-y-4 rounded-lg border border-line bg-panel p-5">
          {expired && !error ? <Notice tone="warn">Your session ended. Sign in again to continue.</Notice> : null}
          {error ? (
            <div role="alert" className="rounded border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-ink">
              {error}
            </div>
          ) : null}
          <Field label="Username">
            <Input
              autoFocus
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              maxLength={64}
            />
          </Field>
          <Field label="Password">
            <Input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              maxLength={256}
            />
          </Field>
          <Button type="submit" variant="primary" className="w-full" disabled={busy || !username || !password}>
            {busy ? "Signing in..." : "Sign in"}
          </Button>
        </form>

        <p className="mt-4 text-xs text-ink-3">
          First time? The admin account is created from <span className="font-mono">FIRST_ADMIN_USERNAME</span> and{" "}
          <span className="font-mono">FIRST_ADMIN_PASSWORD</span> in your <span className="font-mono">.env</span> file.
        </p>
      </div>
    </main>
  );
}
