"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeftIcon, ArrowRightIcon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { GateNote, QueryStatus } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, NativeSelect, Textarea } from "@/components/ui/input";
import { Field } from "@/components/ui/label";
import { api } from "@/lib/api-instance";
import { formatDate } from "@/lib/format";
import { gate, type Access } from "@/lib/roles";
import type { CaseMember, Task, TaskBody } from "@/lib/types";

const COLUMNS: { status: Task["status"]; label: string }[] = [
  { status: "todo", label: "To do" },
  { status: "doing", label: "In progress" },
  { status: "done", label: "Done" },
];

function toBody(t: Task, patch: Partial<TaskBody>): TaskBody {
  return { title: t.title, detail: t.detail, assignee: t.assignee, status: t.status, due: t.due, ...patch };
}

export function TasksBoard({
  caseId,
  access,
  members,
}: {
  caseId: string;
  access: Access;
  members: CaseMember[];
}) {
  const qc = useQueryClient();
  const tasks = useQuery({ queryKey: ["tasks", caseId], queryFn: () => api.listTasks(caseId) });
  const canEdit = gate(access, "examiner");
  const [title, setTitle] = useState("");
  const [detail, setDetail] = useState("");
  const [assignee, setAssignee] = useState("");
  const [due, setDue] = useState("");

  const update = useMutation({
    mutationFn: ({ t, patch }: { t: Task; patch: Partial<TaskBody> }) =>
      api.updateTask(caseId, t.id, toBody(t, patch)),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["tasks", caseId] }),
  });
  const create = useMutation({
    mutationFn: () =>
      api.createTask(caseId, {
        title: title.trim(),
        detail: detail.trim(),
        assignee: assignee || null,
        status: "todo",
        due: due ? new Date(`${due}T00:00:00Z`).toISOString() : null,
      }),
    onSuccess: () => {
      setTitle("");
      setDetail("");
      setAssignee("");
      setDue("");
      void qc.invalidateQueries({ queryKey: ["tasks", caseId] });
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (title.trim()) create.mutate();
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
      <QueryStatus isLoading={tasks.isLoading} error={tasks.error}>
        <div className="grid gap-3 md:grid-cols-3">
          {COLUMNS.map((col, ci) => {
            const items = (tasks.data ?? []).filter((t) => t.status === col.status);
            return (
              <section
                key={col.status}
                aria-labelledby={`col-${col.status}`}
                className="bg-muted/40 rounded-lg border p-2"
              >
                <h3 id={`col-${col.status}`} className="mb-2 px-1 text-sm font-semibold">
                  {col.label} <span className="text-muted-foreground">({items.length})</span>
                </h3>
                <ul className="grid gap-2">
                  {items.map((t) => (
                    <li key={t.id} className="bg-card rounded-md border p-2 text-sm">
                      <p className="font-medium">{t.title}</p>
                      {t.detail ? (
                        <p className="text-muted-foreground mt-0.5 text-xs whitespace-pre-wrap">{t.detail}</p>
                      ) : null}
                      {t.due ? <p className="mt-0.5 text-xs">Due {formatDate(t.due).slice(0, 10)}</p> : null}
                      <div className="mt-2 flex flex-wrap items-center gap-1">
                        <label className="sr-only" htmlFor={`assignee-${t.id}`}>
                          Assignee for {t.title}
                        </label>
                        <NativeSelect
                          id={`assignee-${t.id}`}
                          className="h-8 w-auto min-w-0 flex-1"
                          value={t.assignee ?? ""}
                          disabled={!canEdit.allowed}
                          onChange={(e) => update.mutate({ t, patch: { assignee: e.target.value || null } })}
                        >
                          <option value="">Unassigned</option>
                          {members.map((m) => (
                            <option key={m.user_id} value={m.user_id}>
                              {m.user_id} ({m.role})
                            </option>
                          ))}
                        </NativeSelect>
                        {canEdit.allowed ? (
                          <>
                            <Button
                              variant="outline"
                              size="icon-sm"
                              disabled={ci === 0}
                              aria-label={`Move ${t.title} to ${COLUMNS[ci - 1]?.label ?? ""}`}
                              onClick={() => {
                                const prev = COLUMNS[ci - 1];
                                if (prev) update.mutate({ t, patch: { status: prev.status } });
                              }}
                            >
                              <ArrowLeftIcon aria-hidden />
                            </Button>
                            <Button
                              variant="outline"
                              size="icon-sm"
                              disabled={ci === COLUMNS.length - 1}
                              aria-label={`Move ${t.title} to ${COLUMNS[ci + 1]?.label ?? ""}`}
                              onClick={() => {
                                const next = COLUMNS[ci + 1];
                                if (next) update.mutate({ t, patch: { status: next.status } });
                              }}
                            >
                              <ArrowRightIcon aria-hidden />
                            </Button>
                          </>
                        ) : null}
                      </div>
                    </li>
                  ))}
                </ul>
              </section>
            );
          })}
        </div>
      </QueryStatus>
      <Card aria-labelledby="new-task">
        <CardHeader>
          <CardTitle id="new-task">New task</CardTitle>
        </CardHeader>
        <CardContent>
          {canEdit.allowed ? (
            <form className="grid gap-3" onSubmit={submit}>
              <Field label="Title" htmlFor="task-title">
                <Input id="task-title" value={title} onChange={(e) => setTitle(e.target.value)} />
              </Field>
              <Field label="Detail" htmlFor="task-detail">
                <Textarea
                  id="task-detail"
                  value={detail}
                  onChange={(e) => setDetail(e.target.value)}
                  className="min-h-14"
                />
              </Field>
              <Field label="Assignee" htmlFor="task-assignee">
                <NativeSelect
                  id="task-assignee"
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                >
                  <option value="">Unassigned</option>
                  {members.map((m) => (
                    <option key={m.user_id} value={m.user_id}>
                      {m.user_id} ({m.role})
                    </option>
                  ))}
                </NativeSelect>
              </Field>
              <Field label="Due date" htmlFor="task-due">
                <Input id="task-due" type="date" value={due} onChange={(e) => setDue(e.target.value)} />
              </Field>
              <Button type="submit" disabled={!title.trim() || create.isPending}>
                Add task
              </Button>
            </form>
          ) : (
            <GateNote reason={canEdit.reason} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
