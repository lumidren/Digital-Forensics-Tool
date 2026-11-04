"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { GateNote, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, NativeSelect, Textarea } from "@/components/ui/input";
import { Field } from "@/components/ui/label";
import { EmptyState } from "@/components/ui/misc";
import { api } from "@/lib/api-instance";
import { parseIdList } from "@/lib/findings";
import { gate, type Access } from "@/lib/roles";
import type { Hypothesis } from "@/lib/types";

const STATUS_VARIANT = { open: "outline", supported: "success", refuted: "secondary" } as const;

function EventLinks({ caseId, ids, label }: { caseId: string; ids: number[]; label: string }) {
  if (!ids.length) return <span className="text-muted-foreground text-xs">none</span>;
  return (
    <ul className="flex flex-wrap gap-1" aria-label={label}>
      {ids.map((id) => (
        <li key={id}>
          <Link
            href={`/cases/${encodeURIComponent(caseId)}/timeline?event=${id}`}
            className="text-primary font-mono text-xs underline"
          >
            #{id}
          </Link>
        </li>
      ))}
    </ul>
  );
}

function HypothesisCard({ caseId, h, canEdit }: { caseId: string; h: Hypothesis; canEdit: boolean }) {
  const qc = useQueryClient();
  const [support, setSupport] = useState("");
  const [refute, setRefute] = useState("");
  const update = useMutation({
    mutationFn: (patch: Partial<Hypothesis>) =>
      api.updateHypothesis(caseId, h.id, {
        title: h.title,
        statement: h.statement,
        status: patch.status ?? h.status,
        supporting_event_ids: patch.supporting_event_ids ?? h.supporting_event_ids,
        refuting_event_ids: patch.refuting_event_ids ?? h.refuting_event_ids,
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["hypotheses", caseId] }),
  });
  const addLinks = (e: FormEvent) => {
    e.preventDefault();
    const s = parseIdList(support);
    const r = parseIdList(refute);
    if (s === null || r === null) {
      toast.error("Event ids must be numbers separated by commas or spaces.");
      return;
    }
    update.mutate({
      supporting_event_ids: [...new Set([...h.supporting_event_ids, ...s])],
      refuting_event_ids: [...new Set([...h.refuting_event_ids, ...r])],
    });
    setSupport("");
    setRefute("");
  };
  return (
    <li className="rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-medium">{h.title}</h3>
        <Badge variant={STATUS_VARIANT[h.status]}>{h.status}</Badge>
        <span className="text-muted-foreground text-xs">by {h.user_id}</span>
        {canEdit ? (
          <div className="ml-auto">
            <label className="sr-only" htmlFor={`h-status-${h.id}`}>
              Status of {h.title}
            </label>
            <NativeSelect
              id={`h-status-${h.id}`}
              className="h-8 w-32"
              value={h.status}
              onChange={(e) => update.mutate({ status: e.target.value as Hypothesis["status"] })}
            >
              <option value="open">open</option>
              <option value="supported">supported</option>
              <option value="refuted">refuted</option>
            </NativeSelect>
          </div>
        ) : null}
      </div>
      <p className="mt-1 text-sm whitespace-pre-wrap">{h.statement}</p>
      <div className="mt-2 grid gap-1 text-sm sm:grid-cols-2">
        <div>
          <p className="text-muted-foreground text-xs">Supporting events</p>
          <EventLinks
            caseId={caseId}
            ids={h.supporting_event_ids}
            label={`Supporting events for ${h.title}`}
          />
        </div>
        <div>
          <p className="text-muted-foreground text-xs">Refuting events</p>
          <EventLinks caseId={caseId} ids={h.refuting_event_ids} label={`Refuting events for ${h.title}`} />
        </div>
      </div>
      {canEdit ? (
        <form onSubmit={addLinks} className="mt-2 grid gap-2 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
          <Field label="Add supporting event ids" htmlFor={`h-sup-${h.id}`}>
            <Input
              id={`h-sup-${h.id}`}
              value={support}
              onChange={(e) => setSupport(e.target.value)}
              inputMode="numeric"
            />
          </Field>
          <Field label="Add refuting event ids" htmlFor={`h-ref-${h.id}`}>
            <Input
              id={`h-ref-${h.id}`}
              value={refute}
              onChange={(e) => setRefute(e.target.value)}
              inputMode="numeric"
            />
          </Field>
          <Button type="submit" variant="secondary" disabled={!support.trim() && !refute.trim()}>
            Link events
          </Button>
        </form>
      ) : null}
    </li>
  );
}

export function Hypotheses({ caseId, access }: { caseId: string; access: Access }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["hypotheses", caseId], queryFn: () => api.listHypotheses(caseId) });
  const [title, setTitle] = useState("");
  const [statement, setStatement] = useState("");
  const [support, setSupport] = useState("");
  const canEdit = gate(access, "examiner");
  const create = useMutation({
    mutationFn: (ids: number[]) =>
      api.createHypothesis(caseId, {
        title: title.trim(),
        statement: statement.trim(),
        status: "open",
        supporting_event_ids: ids,
        refuting_event_ids: [],
      }),
    onSuccess: () => {
      setTitle("");
      setStatement("");
      setSupport("");
      void qc.invalidateQueries({ queryKey: ["hypotheses", caseId] });
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const ids = parseIdList(support);
    if (ids === null) {
      toast.error("Event ids must be numbers separated by commas or spaces.");
      return;
    }
    if (title.trim() && statement.trim()) create.mutate(ids);
  };
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
      <QueryStatus isLoading={list.isLoading} error={list.error}>
        {(list.data ?? []).length ? (
          <ul className="grid gap-3">
            {(list.data ?? []).map((h) => (
              <HypothesisCard key={h.id} caseId={caseId} h={h} canEdit={canEdit.allowed} />
            ))}
          </ul>
        ) : (
          <EmptyState title="No hypotheses">
            State what you believe happened and link the events that support or refute it.
          </EmptyState>
        )}
      </QueryStatus>
      <Card aria-labelledby="new-hyp">
        <CardHeader>
          <CardTitle id="new-hyp">New hypothesis</CardTitle>
        </CardHeader>
        <CardContent>
          {canEdit.allowed ? (
            <form className="grid gap-3" onSubmit={submit}>
              <Field label="Title" htmlFor="hyp-title">
                <Input id="hyp-title" value={title} onChange={(e) => setTitle(e.target.value)} />
              </Field>
              <Field label="Statement" htmlFor="hyp-statement">
                <Textarea
                  id="hyp-statement"
                  value={statement}
                  onChange={(e) => setStatement(e.target.value)}
                />
              </Field>
              <Field label="Supporting event ids" htmlFor="hyp-support">
                <Input
                  id="hyp-support"
                  value={support}
                  onChange={(e) => setSupport(e.target.value)}
                  inputMode="numeric"
                />
              </Field>
              <Button type="submit" disabled={!title.trim() || !statement.trim() || create.isPending}>
                Add hypothesis
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
