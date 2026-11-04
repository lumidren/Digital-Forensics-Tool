"use client";

import { useMutation, useQueries, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, CircleDotIcon, ExternalLinkIcon, ListTreeIcon, XIcon } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { GateNote, SeverityBadge, StateBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api-instance";
import { attackUrl, techniqueInfo } from "@/lib/attack";
import { dataTypeCategory } from "@/lib/data-types";
import { MIN_RATIONALE } from "@/lib/findings";
import { formatDate, formatNs } from "@/lib/format";
import { canExamine, canReopen, canReturn, canReview, type Access } from "@/lib/roles";
import type { Finding, FindingActionBody, FindingState, TimelineEvent } from "@/lib/types";
import { cn } from "@/lib/utils";

const MAX_EVENTS = 25;

const STEPS: { state: FindingState; label: string }[] = [
  { state: "proposed", label: "Proposed" },
  { state: "confirmed", label: "Confirmed" },
  { state: "approved", label: "Approved" },
];

/** proposed -> confirmed -> approved, with rejection shown as a terminal branch. */
export function WorkflowStepper({ finding }: { finding: Finding }) {
  const rejected = finding.state === "rejected";
  const reached = rejected ? 0 : STEPS.findIndex((s) => s.state === finding.state);
  const who: Record<string, string | null> = {
    proposed: finding.origin === "manual" ? "manual" : "rule",
    confirmed: finding.confirmed_by,
    approved: finding.approved_by,
  };
  return (
    <ol className="flex flex-wrap items-center gap-y-2" aria-label="Review workflow">
      {STEPS.map((s, i) => {
        const done = !rejected && i <= reached;
        const current = !rejected && i === reached;
        return (
          <li key={s.state} className="flex items-center" aria-current={current ? "step" : undefined}>
            {i > 0 ? (
              <span aria-hidden className={cn("mx-2 h-px w-6 sm:w-10", done ? "bg-success" : "bg-border")} />
            ) : null}
            <span className="flex items-center gap-1.5">
              <span
                aria-hidden
                className={cn(
                  "grid size-5 place-items-center rounded-full border text-[10px] font-semibold",
                  done ? "border-success bg-success text-background" : "text-muted-foreground bg-card",
                  current && "ring-success/30 ring-4",
                )}
              >
                {done ? <CheckIcon className="size-3" /> : i + 1}
              </span>
              <span className={cn("text-xs", done ? "font-medium" : "text-muted-foreground")}>
                {s.label}
                {done && who[s.state] ? (
                  <span className="text-muted-foreground font-normal"> · {who[s.state]}</span>
                ) : null}
                <span className="sr-only">{done ? " (done)" : " (pending)"}</span>
              </span>
            </span>
          </li>
        );
      })}
      {rejected ? (
        <li className="flex items-center" aria-current="step">
          <span aria-hidden className="bg-destructive/60 mx-2 h-px w-6 sm:w-10" />
          <span className="text-destructive flex items-center gap-1.5 text-xs font-medium">
            <span
              aria-hidden
              className="border-destructive bg-destructive-soft grid size-5 place-items-center rounded-full border"
            >
              <XIcon className="size-3" />
            </span>
            Rejected
          </span>
        </li>
      ) : null}
    </ol>
  );
}

/** Supporting events on a shared time axis, one tick per event, coloured by data-type category. */
export function EventStrip({ events }: { events: TimelineEvent[] }) {
  const timed = events.filter((e): e is TimelineEvent & { timestamp: number } => e.timestamp !== null);
  if (timed.length === 0) return null;
  const lo = Math.min(...timed.map((e) => e.timestamp));
  const hi = Math.max(...timed.map((e) => e.timestamp));
  const span = hi - lo;
  return (
    <div className="grid gap-1" aria-hidden>
      <div className="bg-muted/50 relative h-7 rounded-md border">
        <span className="bg-border absolute inset-x-2 top-1/2 h-px" />
        {timed.map((e) => {
          const pct = span ? ((e.timestamp - lo) / span) * 100 : 50;
          return (
            <span
              key={e.id}
              className="border-card absolute top-1/2 size-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 shadow-xs"
              style={{
                left: `calc(0.5rem + (100% - 1rem) * ${pct / 100})`,
                background: dataTypeCategory(e.data_type).color,
              }}
              title={`#${e.id} ${formatNs(e.timestamp)} ${e.data_type}`}
            />
          );
        })}
      </div>
      <div className="text-muted-foreground flex justify-between font-mono text-[10px]">
        <span>{formatNs(lo)}</span>
        {span ? <span>{formatNs(hi)}</span> : null}
      </div>
    </div>
  );
}

export function FindingDetail({
  caseId,
  finding,
  access,
}: {
  caseId: string;
  finding: Finding;
  access: Access;
}) {
  const qc = useQueryClient();
  const [text, setText] = useState("");
  const enc = encodeURIComponent(caseId);
  const examine = canExamine(access, finding);
  const review = canReview(access, finding);
  const ret = canReturn(access, finding);
  const reopen = canReopen(access, finding);
  const events = useQueries({
    queries: finding.event_ids.slice(0, MAX_EVENTS).map((id) => ({
      queryKey: ["event", caseId, id, false],
      queryFn: () => api.getEvent(caseId, id),
      staleTime: 60_000,
      meta: { silent: true },
    })),
  });

  const act = useMutation({
    mutationFn: (action: FindingActionBody["action"]) =>
      api.findingAction(caseId, finding.id, { action, text: text.trim() }),
    onSuccess: (f, action) => {
      toast.success(
        `Finding ${action === "return" ? "returned" : `${action}${action.endsWith("e") ? "d" : "ed"}`}; now ${f.state}`,
      );
      setText("");
      void qc.invalidateQueries({ queryKey: ["findings", caseId] });
    },
  });

  const rationaleOk = text.trim().length >= MIN_RATIONALE;
  const showForm =
    examine.allowed ||
    review.allowed ||
    ret.allowed ||
    reopen.allowed ||
    (finding.state === "confirmed" && access.role !== null);

  return (
    <article
      aria-labelledby="finding-title"
      className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4"
      data-testid="finding-detail"
    >
      <header className="grid gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <StateBadge state={finding.state} />
          <Badge variant="outline">{finding.rule}</Badge>
          <Badge variant="outline">{finding.category}</Badge>
          <span className="text-muted-foreground ml-auto flex items-center gap-1.5 text-xs">
            confidence
            <span aria-hidden className="bg-muted relative h-1.5 w-14 overflow-hidden rounded-full">
              <span
                className="bg-primary absolute inset-y-0 left-0 rounded-full"
                style={{ width: `${Math.round(finding.confidence * 100)}%` }}
              />
            </span>
            <span className="tabular text-foreground font-medium">
              {Math.round(finding.confidence * 100)}%
            </span>
          </span>
        </div>
        <h2
          id="finding-title"
          tabIndex={-1}
          className="focus-visible:ring-ring text-lg leading-snug font-semibold tracking-tight outline-none focus-visible:ring-2"
        >
          {finding.title}
        </h2>
        <p className="text-sm">{finding.description}</p>
        <div className="bg-muted/40 rounded-lg border px-3 py-2.5">
          <WorkflowStepper finding={finding} />
        </div>
        {finding.attack_techniques.length ? (
          <ul className="flex flex-wrap gap-1.5" aria-label="ATT&CK techniques">
            {finding.attack_techniques.map((t) => {
              const info = techniqueInfo(t);
              return (
                <li key={t}>
                  <a
                    href={attackUrl(t)}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="bg-card hover:bg-accent focus-visible:ring-ring inline-flex max-w-full items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors focus-visible:ring-2 focus-visible:outline-none"
                    title={`${info.name}${info.tactics.length ? ` (${info.tactics.join(", ")})` : ""}`}
                  >
                    <span className="text-primary font-mono font-semibold">{info.id}</span>
                    <span className="truncate">{info.known ? info.name : "Unknown technique"}</span>
                    <ExternalLinkIcon aria-hidden className="text-muted-foreground size-3 shrink-0" />
                    <span className="sr-only">(opens MITRE ATT&amp;CK in a new tab)</span>
                  </a>
                </li>
              );
            })}
          </ul>
        ) : null}
        <p className="text-muted-foreground text-xs">
          Window <span className="font-mono">{formatNs(finding.first_ns)}</span> –{" "}
          <span className="font-mono">{formatNs(finding.last_ns)}</span> · {finding.origin} ·{" "}
          <span className="font-mono">{finding.id}</span>
        </p>
      </header>

      <section aria-labelledby="f-history" className="grid gap-1 text-sm">
        <h3 id="f-history" className="text-sm font-semibold">
          Review trail
        </h3>
        <dl className="grid grid-cols-[8rem_1fr] gap-x-2 gap-y-1">
          <dt className="text-muted-foreground">Examiner</dt>
          <dd data-testid="confirmed-by">
            {finding.confirmed_by ? `${finding.confirmed_by} · ${formatDate(finding.confirmed_at)}` : "—"}
          </dd>
          <dt className="text-muted-foreground">Rationale</dt>
          <dd className="whitespace-pre-wrap">{finding.examiner_rationale || "—"}</dd>
          <dt className="text-muted-foreground">Reviewer</dt>
          <dd data-testid="approved-by">
            {finding.approved_by ? `${finding.approved_by} · ${formatDate(finding.approved_at)}` : "—"}
          </dd>
          <dt className="text-muted-foreground">Comment</dt>
          <dd className="whitespace-pre-wrap">{finding.reviewer_comment || "—"}</dd>
        </dl>
      </section>

      {showForm ? (
        <section aria-labelledby="f-decide" className="bg-surface-raised grid gap-2 rounded-lg border p-3">
          <h3 id="f-decide" className="flex items-center gap-2 text-sm font-semibold">
            <CircleDotIcon aria-hidden className="text-primary size-4" /> Decision
          </h3>
          <Label htmlFor="f-text">
            {finding.state === "confirmed" ? "Reviewer comment" : "Rationale (at least 10 characters)"}
          </Label>
          <Textarea
            id="f-text"
            value={text}
            onChange={(e) => setText(e.target.value)}
            aria-describedby="f-gates"
          />
          <div className="flex flex-wrap gap-2">
            {finding.state === "proposed" ? (
              <>
                <Button
                  disabled={!examine.allowed || !rationaleOk || act.isPending}
                  onClick={() => act.mutate("confirm")}
                >
                  Confirm
                </Button>
                <Button
                  variant="outline"
                  disabled={!examine.allowed || !rationaleOk || act.isPending}
                  onClick={() => act.mutate("reject")}
                >
                  Reject
                </Button>
              </>
            ) : null}
            {finding.state === "confirmed" ? (
              <>
                <Button
                  disabled={!review.allowed || act.isPending}
                  aria-describedby="f-gates"
                  onClick={() => act.mutate("approve")}
                >
                  Approve
                </Button>
                <Button
                  variant="outline"
                  disabled={!ret.allowed || act.isPending}
                  onClick={() => act.mutate("return")}
                >
                  Return to examiner
                </Button>
              </>
            ) : null}
            {finding.state === "rejected" ? (
              <Button
                variant="outline"
                disabled={!reopen.allowed || act.isPending}
                onClick={() => act.mutate("reopen")}
              >
                Reopen
              </Button>
            ) : null}
          </div>
          <div id="f-gates" data-testid="gate-reason">
            {finding.state === "proposed" ? <GateNote reason={examine.reason} /> : null}
            {finding.state === "confirmed" ? <GateNote reason={review.reason} /> : null}
            {finding.state === "rejected" ? <GateNote reason={reopen.reason} /> : null}
            {finding.state === "proposed" && examine.allowed && !rationaleOk ? (
              <p className="text-muted-foreground text-xs">
                Enter a rationale of at least {MIN_RATIONALE} characters to confirm or reject.
              </p>
            ) : null}
          </div>
        </section>
      ) : null}

      <section aria-labelledby="f-events" className="grid gap-1.5">
        <h3 id="f-events" className="flex items-center gap-2 text-sm font-semibold">
          <ListTreeIcon aria-hidden className="text-muted-foreground size-4" /> Supporting events (
          {finding.event_ids.length})
        </h3>
        <EventStrip events={events.flatMap((q) => (q.data ? [q.data] : []))} />
        <ul className="grid gap-0.5 text-sm">
          {finding.event_ids.slice(0, MAX_EVENTS).map((id, i) => {
            const e = events[i]?.data;
            return (
              <li
                key={id}
                className="hover:bg-muted/50 flex min-w-0 items-center gap-2 rounded-md px-1 py-0.5"
              >
                <span
                  aria-hidden
                  className="size-2 shrink-0 rounded-full"
                  style={{ background: e ? dataTypeCategory(e.data_type).color : "var(--border)" }}
                />
                <Link
                  href={`/cases/${enc}/timeline?event=${id}`}
                  className="text-primary shrink-0 font-mono text-xs underline"
                >
                  #{id}
                </Link>
                <span className="text-muted-foreground shrink-0 font-mono text-xs">
                  {e ? formatNs(e.timestamp) : ""}
                </span>
                <span className="min-w-0 truncate">{e ? e.message : "…"}</span>
              </li>
            );
          })}
        </ul>
        {finding.event_ids.length > MAX_EVENTS ? (
          <p className="text-muted-foreground text-xs">Showing the first {MAX_EVENTS} events.</p>
        ) : null}
      </section>

      {Object.keys(finding.details).length ? (
        <details className="text-sm">
          <summary className="cursor-pointer font-semibold">Rule details</summary>
          <pre className="bg-muted/40 mt-2 max-h-72 overflow-auto rounded-md border p-2 text-xs">
            {JSON.stringify(finding.details, null, 2)}
          </pre>
        </details>
      ) : null}
    </article>
  );
}
