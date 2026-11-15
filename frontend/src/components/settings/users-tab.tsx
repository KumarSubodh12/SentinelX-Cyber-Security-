"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/form";
import { ErrorNote, Skeleton, TableWrap } from "@/components/ui/misc";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import { useApi } from "@/lib/hooks";
import type { Role, User } from "@/lib/types";

const ROLES: { value: Role; label: string; hint: string }[] = [
  { value: "viewer", label: "Viewer", hint: "Can look at everything, cannot change anything" },
  { value: "analyst", label: "Analyst", hint: "Can triage alerts, manage incidents and run simulations" },
  { value: "admin", label: "Admin", hint: "Full control, including agents, rules and users" },
];

function NewUser({ onCreated }: { onCreated: () => void }) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api("/api/users", {
        method: "POST",
        body: { username: username.trim(), email: email.trim(), full_name: fullName.trim() || null, password, role },
      });
      setUsername("");
      setEmail("");
      setFullName("");
      setPassword("");
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the user");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel>
      <PanelHeader title="Add a user" />
      <form
        className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="Username" hint="Letters, numbers, dot, dash, underscore">
          <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" maxLength={64} />
        </Field>
        <Field label="Email">
          <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" maxLength={255} />
        </Field>
        <Field label="Full name (optional)">
          <Input value={fullName} onChange={(e) => setFullName(e.target.value)} maxLength={128} />
        </Field>
        <Field label="Temporary password" hint="At least 10 characters, with upper and lower case letters and a digit">
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" maxLength={256} />
        </Field>
        <Field label="Role" hint={ROLES.find((r) => r.value === role)?.hint}>
          <Select value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </Select>
        </Field>
        <div className="flex items-start pt-6">
          <Button type="submit" variant="primary" disabled={busy || username.trim().length < 3 || !email.includes("@") || password.length < 10}>
            Create user
          </Button>
        </div>
        {error ? (
          <div className="sm:col-span-2 lg:col-span-3">
            <ErrorNote message={error} />
          </div>
        ) : null}
      </form>
    </Panel>
  );
}

export function UsersTab() {
  const { user: me, can } = useAuth();
  const { data, error, loading, reload } = useApi<User[]>("/api/users", {}, { enabled: can("admin") });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await action();
      reload();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  if (!can("admin")) {
    return (
      <Panel>
        <div className="p-4 text-sm text-ink-2">Only admins can manage users.</div>
      </Panel>
    );
  }

  return (
    <div className="space-y-4">
      <NewUser onCreated={reload} />
      <Panel>
        <PanelHeader title="Users" />
        {error ? (
          <div className="p-3">
            <ErrorNote message={error} onRetry={reload} />
          </div>
        ) : null}
        {actionError ? (
          <div className="p-3">
            <ErrorNote message={actionError} />
          </div>
        ) : null}
        {loading && !data ? (
          <div className="p-4">
            <Skeleton className="h-24 w-full" />
          </div>
        ) : (
          <TableWrap>
            <table className="w-full min-w-[760px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">User</th>
                  <th className="th">Role</th>
                  <th className="th">Status</th>
                  <th className="th">Last sign-in</th>
                  <th className="th text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data?.map((user) => {
                  const self = user.id === me?.id;
                  return (
                    <tr key={user.id}>
                      <td className="td">
                        <span className="font-medium text-ink">{user.full_name || user.username}</span>
                        <span className="block text-xs text-ink-3">
                          {user.username}, {user.email}
                        </span>
                      </td>
                      <td className="td">
                        <Select
                          className="h-8 w-32"
                          value={user.role}
                          disabled={busy || self}
                          aria-label={`Role for ${user.username}`}
                          onChange={(e) => void run(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { role: e.target.value } }))}
                        >
                          {ROLES.map((r) => (
                            <option key={r.value} value={r.value}>
                              {r.label}
                            </option>
                          ))}
                        </Select>
                      </td>
                      <td className="td">{user.is_active ? "Active" : <span className="text-ink-3">Disabled</span>}</td>
                      <td className="td whitespace-nowrap text-ink-2">{timeAgo(user.last_login)}</td>
                      <td className="td">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={busy || self}
                            onClick={() => void run(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { is_active: !user.is_active } }))}
                          >
                            {user.is_active ? "Disable" : "Enable"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={busy}
                            onClick={() => {
                              const password = window.prompt(`New password for ${user.username} (10+ characters, upper and lower case, a digit):`);
                              if (password) void run(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { password } }));
                            }}
                          >
                            Reset password
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={busy || self}
                            onClick={() => {
                              if (window.confirm(`Delete ${user.username}? This cannot be undone.`)) void run(() => api(`/api/users/${user.id}`, { method: "DELETE" }));
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>
    </div>
  );
}
