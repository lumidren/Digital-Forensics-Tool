"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Mono, PageHeader, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, NativeSelect } from "@/components/ui/input";
import { Field, Label } from "@/components/ui/label";
import { Alert, EmptyState } from "@/components/ui/misc";
import { Checkbox, Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useMe } from "@/hooks/use-session";
import { api } from "@/lib/api-instance";
import { formatDate } from "@/lib/format";
import { CASE_ROLES, type CaseRole } from "@/lib/types";

function UsersTab() {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["admin-users"], queryFn: () => api.listUsers() });
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [unmask, setUnmask] = useState(false);
  const patch = useMutation({
    mutationFn: ({ userId, body }: { userId: string; body: Parameters<typeof api.patchUser>[1] }) =>
      api.patchUser(userId, body),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["admin-users"] }),
  });
  const create = useMutation({
    mutationFn: () =>
      api.createUser({
        id: id.trim(),
        display_name: name.trim(),
        email: email.trim() || null,
        password: password || null,
        is_admin: isAdmin,
        can_unmask_pii: unmask,
      }),
    onSuccess: (r) => {
      toast.success(`User ${r.id} created (key ${r.signing_key_id})`);
      setId("");
      setName("");
      setEmail("");
      setPassword("");
      setIsAdmin(false);
      setUnmask(false);
      void qc.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });
  const idValid = /^[A-Za-z0-9_.@-]{2,64}$/.test(id.trim());
  const pwValid = password === "" || password.length >= 12;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (idValid && name.trim() && pwValid) create.mutate();
  };
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <Card>
        <QueryStatus isLoading={users.isLoading} error={users.error}>
          <Table aria-label="Users">
            <TableHeader>
              <TableRow>
                <TableHead scope="col">User</TableHead>
                <TableHead scope="col">Email</TableHead>
                <TableHead scope="col">Active</TableHead>
                <TableHead scope="col">Admin</TableHead>
                <TableHead scope="col">May unmask PII</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(users.data ?? []).map((u) => (
                <TableRow key={u.id}>
                  <TableCell>
                    <span className="font-medium">{u.display_name}</span>{" "}
                    <span className="text-muted-foreground font-mono text-xs">{u.id}</span>
                  </TableCell>
                  <TableCell className="text-xs">{u.email ?? "—"}</TableCell>
                  <TableCell>
                    <Switch
                      checked={u.active}
                      aria-label={`${u.id} active`}
                      onCheckedChange={(v) => patch.mutate({ userId: u.id, body: { active: v } })}
                    />
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={u.is_admin}
                      aria-label={`${u.id} administrator`}
                      onCheckedChange={(v) => patch.mutate({ userId: u.id, body: { is_admin: v } })}
                    />
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={u.can_unmask_pii}
                      aria-label={`${u.id} may unmask PII`}
                      onCheckedChange={(v) => patch.mutate({ userId: u.id, body: { can_unmask_pii: v } })}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </QueryStatus>
        <p className="text-muted-foreground border-t px-3 py-2 text-xs">
          Disabling a user also revokes their signing key.
        </p>
      </Card>
      <Card aria-labelledby="new-user">
        <CardHeader>
          <CardTitle id="new-user">Create user</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={submit}>
            <Field label="User id" htmlFor="nu-id">
              <Input
                id="nu-id"
                value={id}
                onChange={(e) => setId(e.target.value)}
                aria-invalid={(id !== "" && !idValid) || undefined}
                autoComplete="off"
              />
            </Field>
            <Field label="Display name" htmlFor="nu-name">
              <Input id="nu-name" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Email" htmlFor="nu-email">
              <Input id="nu-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </Field>
            <Field label="Password (12+ characters; empty for OIDC-only)" htmlFor="nu-pw">
              <Input
                id="nu-pw"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-invalid={!pwValid || undefined}
              />
            </Field>
            <div className="flex items-center gap-2">
              <Checkbox id="nu-admin" checked={isAdmin} onCheckedChange={(v) => setIsAdmin(v === true)} />
              <Label htmlFor="nu-admin">Administrator</Label>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox id="nu-unmask" checked={unmask} onCheckedChange={(v) => setUnmask(v === true)} />
              <Label htmlFor="nu-unmask">May unmask PII</Label>
            </div>
            <Button type="submit" disabled={!idValid || !name.trim() || !pwValid || create.isPending}>
              Create user
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

function KeysTab() {
  const qc = useQueryClient();
  const keys = useQuery({ queryKey: ["admin-keys"], queryFn: () => api.keys() });
  const revoke = useMutation({
    mutationFn: (holder: string) => api.revokeKey(holder),
    onSuccess: (r) => {
      toast.success(r.revoked_key_id ? `Revoked key ${r.revoked_key_id}` : "No active key to revoke");
      void qc.invalidateQueries({ queryKey: ["admin-keys"] });
    },
  });
  return (
    <Card>
      <QueryStatus isLoading={keys.isLoading} error={keys.error}>
        <Table aria-label="Signing key registry">
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Key id</TableHead>
              <TableHead scope="col">Holder</TableHead>
              <TableHead scope="col">Role</TableHead>
              <TableHead scope="col">Valid from</TableHead>
              <TableHead scope="col">Valid to</TableHead>
              <TableHead scope="col">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(keys.data?.keys ?? []).map((k) => (
              <TableRow key={k.key_id}>
                <TableCell>
                  <Mono>{k.key_id}</Mono>
                </TableCell>
                <TableCell>{k.holder}</TableCell>
                <TableCell>{k.role}</TableCell>
                <TableCell className="text-xs">{k.valid_from ?? "—"}</TableCell>
                <TableCell className="text-xs">
                  {k.valid_to ? (
                    <Badge variant="destructive">revoked {k.valid_to}</Badge>
                  ) : (
                    <Badge variant="success">active</Badge>
                  )}
                </TableCell>
                <TableCell>
                  {!k.valid_to && k.holder !== "veritas-pipeline" ? (
                    <Button variant="outline" size="sm" onClick={() => revoke.mutate(k.holder)}>
                      Revoke
                    </Button>
                  ) : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </QueryStatus>
    </Card>
  );
}

function MembershipTab() {
  const qc = useQueryClient();
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.listCases() });
  const users = useQuery({ queryKey: ["admin-users"], queryFn: () => api.listUsers() });
  const [caseId, setCaseId] = useState("");
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState<CaseRole>("examiner");
  const effectiveCase = caseId || cases.data?.[0]?.id || "";
  const kase = useQuery({
    queryKey: ["case", effectiveCase],
    queryFn: () => api.getCase(effectiveCase),
    enabled: effectiveCase !== "",
  });
  const set = useMutation({
    mutationFn: (b: { user_id: string; role: CaseRole }) => api.setMember(effectiveCase, b),
    onSuccess: () => {
      toast.success("Membership updated");
      void qc.invalidateQueries({ queryKey: ["case", effectiveCase] });
    },
  });
  const remove = useMutation({
    mutationFn: (u: string) => api.removeMember(effectiveCase, u),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case", effectiveCase] }),
  });
  return (
    <div className="grid gap-4">
      <Field label="Case" htmlFor="mb-case" className="max-w-md">
        <NativeSelect id="mb-case" value={effectiveCase} onChange={(e) => setCaseId(e.target.value)}>
          {(cases.data ?? []).map((c) => (
            <option key={c.id} value={c.id}>
              {c.id} · {c.name}
            </option>
          ))}
        </NativeSelect>
      </Field>
      {effectiveCase ? (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
          <Card>
            <QueryStatus isLoading={kase.isLoading} error={kase.error}>
              <Table aria-label="Case members">
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">User</TableHead>
                    <TableHead scope="col">Role</TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(kase.data?.members ?? []).map((m) => (
                    <TableRow key={m.user_id}>
                      <TableCell>{m.user_id}</TableCell>
                      <TableCell>
                        <label className="sr-only" htmlFor={`role-${m.user_id}`}>
                          Role for {m.user_id}
                        </label>
                        <NativeSelect
                          id={`role-${m.user_id}`}
                          className="h-8 w-36"
                          value={m.role}
                          onChange={(e) =>
                            set.mutate({ user_id: m.user_id, role: e.target.value as CaseRole })
                          }
                        >
                          {CASE_ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </NativeSelect>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Remove ${m.user_id} from case`}
                          onClick={() => remove.mutate(m.user_id)}
                        >
                          <Trash2Icon aria-hidden />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </QueryStatus>
          </Card>
          <Card aria-labelledby="add-member">
            <CardHeader>
              <CardTitle id="add-member">Add member</CardTitle>
            </CardHeader>
            <CardContent>
              <form
                className="grid gap-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (userId) set.mutate({ user_id: userId, role });
                }}
              >
                <Field label="User" htmlFor="mb-user">
                  <NativeSelect id="mb-user" value={userId} onChange={(e) => setUserId(e.target.value)}>
                    <option value="">Choose…</option>
                    {(users.data ?? []).map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.id} · {u.display_name}
                      </option>
                    ))}
                  </NativeSelect>
                </Field>
                <Field label="Role" htmlFor="mb-role">
                  <NativeSelect
                    id="mb-role"
                    value={role}
                    onChange={(e) => setRole(e.target.value as CaseRole)}
                  >
                    {CASE_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </NativeSelect>
                </Field>
                <Button type="submit" disabled={!userId || set.isPending}>
                  Add or update
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      ) : (
        <EmptyState title="No cases" />
      )}
    </div>
  );
}

function RetentionTab() {
  const sweep = useMutation({ mutationFn: () => api.retentionSweep() });
  return (
    <Card>
      <CardContent className="grid gap-3">
        <p className="text-sm">
          Lists cases past their retention date that are not on legal hold. Disposal is a separate, explicit
          action outside this console.
        </p>
        <Button className="justify-self-start" onClick={() => sweep.mutate()} disabled={sweep.isPending}>
          Run retention sweep
        </Button>
        <div role="status" aria-live="polite">
          {sweep.data ? (
            sweep.data.due_for_disposal.length ? (
              <Alert variant="warning">
                Due for disposal: <span className="font-mono">{sweep.data.due_for_disposal.join(", ")}</span>
              </Alert>
            ) : (
              <Alert variant="success">No cases are due for disposal.</Alert>
            )
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

function AuditTab() {
  const [actor, setActor] = useState("");
  const [caseFilter, setCaseFilter] = useState("");
  const [offset, setOffset] = useState(0);
  const [applied, setApplied] = useState({ actor: "", case_id: "" });
  const rows = useQuery({
    queryKey: ["audit", applied, offset],
    queryFn: () =>
      api.audit({
        actor: applied.actor || undefined,
        case_id: applied.case_id || undefined,
        limit: 100,
        offset,
      }),
    placeholderData: (p) => p,
  });
  const verify = useMutation({ mutationFn: () => api.verifyAudit() });
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-end gap-2">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setApplied({ actor: actor.trim(), case_id: caseFilter.trim() });
          }}
        >
          <Field label="Actor" htmlFor="au-actor">
            <Input id="au-actor" value={actor} onChange={(e) => setActor(e.target.value)} className="w-40" />
          </Field>
          <Field label="Case" htmlFor="au-case">
            <Input
              id="au-case"
              value={caseFilter}
              onChange={(e) => setCaseFilter(e.target.value)}
              className="w-48"
            />
          </Field>
          <Button type="submit" variant="secondary">
            Filter
          </Button>
        </form>
        <Button className="ml-auto" onClick={() => verify.mutate()} disabled={verify.isPending}>
          <ShieldCheckIcon aria-hidden /> Verify audit chain
        </Button>
      </div>
      <div role="status" aria-live="polite">
        {verify.data ? (
          <Alert variant={verify.data.ok ? "success" : "destructive"} data-testid="audit-verdict">
            <span className="font-semibold">{verify.data.ok ? "PASS" : "FAIL"}</span>: audit log hash chain{" "}
            {verify.data.ok ? "is intact" : `has ${verify.data.failures.length} failure(s)`}.
          </Alert>
        ) : null}
      </div>
      <Card>
        <QueryStatus isLoading={rows.isLoading} error={rows.error}>
          <Table aria-label="Audit log">
            <TableHeader>
              <TableRow>
                <TableHead scope="col">#</TableHead>
                <TableHead scope="col">Time</TableHead>
                <TableHead scope="col">Actor</TableHead>
                <TableHead scope="col">Action</TableHead>
                <TableHead scope="col">Case</TableHead>
                <TableHead scope="col">Detail</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(rows.data ?? []).map((r) => (
                <TableRow key={r.seq}>
                  <TableCell className="tabular">{r.seq}</TableCell>
                  <TableCell className="font-mono text-xs whitespace-nowrap">{formatDate(r.ts)}</TableCell>
                  <TableCell className="text-xs">{r.actor}</TableCell>
                  <TableCell className="font-mono text-xs">{r.action}</TableCell>
                  <TableCell className="font-mono text-xs">{r.case_id ?? "—"}</TableCell>
                  <TableCell
                    className="max-w-[24rem] truncate font-mono text-xs"
                    title={JSON.stringify(r.detail)}
                  >
                    {JSON.stringify(r.detail)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </QueryStatus>
        <div className="flex items-center justify-end gap-1 border-t px-3 py-2">
          <Button
            variant="outline"
            size="sm"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - 100))}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={(rows.data ?? []).length < 100}
            onClick={() => setOffset(offset + 100)}
          >
            Next
          </Button>
        </div>
      </Card>
    </div>
  );
}

function StoreTab() {
  const verify = useMutation({ mutationFn: () => api.verifyStore() });
  return (
    <Card>
      <CardContent className="grid gap-3">
        <p className="text-sm">
          Re-hashes every object in the evidence store and compares it with its content address.
        </p>
        <Button className="justify-self-start" onClick={() => verify.mutate()} disabled={verify.isPending}>
          {verify.isPending ? "Verifying…" : "Verify store integrity"}
        </Button>
        <div role="status" aria-live="polite">
          {verify.data ? (
            <Alert
              variant={verify.data.failed.length ? "destructive" : "success"}
              data-testid="store-verdict"
            >
              <span className="font-semibold">{verify.data.failed.length ? "FAIL" : "PASS"}</span>:{" "}
              {verify.data.objects} object(s) checked
              {verify.data.failed.length
                ? `, ${verify.data.failed.length} failed: ${verify.data.failed.map((f) => f.address).join(", ")}`
                : ""}
              .
            </Alert>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

export function AdminPage() {
  const me = useMe();
  if (me.data && !me.data.is_admin) {
    return (
      <>
        <PageHeader title="Administration" />
        <Alert variant="destructive" role="alert">
          Administration requires a global administrator account.
        </Alert>
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Administration"
        description="Users, signing keys, case membership, retention, audit log and store integrity."
      />
      <Tabs defaultValue="users">
        <TabsList>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="keys">Keys</TabsTrigger>
          <TabsTrigger value="members">Case membership</TabsTrigger>
          <TabsTrigger value="retention">Retention</TabsTrigger>
          <TabsTrigger value="audit">Audit log</TabsTrigger>
          <TabsTrigger value="store">Store</TabsTrigger>
        </TabsList>
        <TabsContent value="users">
          <UsersTab />
        </TabsContent>
        <TabsContent value="keys">
          <KeysTab />
        </TabsContent>
        <TabsContent value="members">
          <MembershipTab />
        </TabsContent>
        <TabsContent value="retention">
          <RetentionTab />
        </TabsContent>
        <TabsContent value="audit">
          <AuditTab />
        </TabsContent>
        <TabsContent value="store">
          <StoreTab />
        </TabsContent>
      </Tabs>
    </>
  );
}
