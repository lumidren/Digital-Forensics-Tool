"use client";

import { useMutation, useQueries, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";
import { GateNote, SeverityBadge, StateBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api-instance";
import { MIN_RATIONALE } from "@/lib/findings";
import { formatDate, formatNs } from "@/lib/format";
import { canExamine, canReopen, canReturn, canReview, type Access } from "@/lib/roles";
import type { Finding, FindingActionBody } from "@/lib/types";

const MAX_EVENTS = 25;

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
      <header className="grid gap-1.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <StateBadge state={finding.state} />
          <Badge variant="outline">{finding.rule}</Badge>
          <Badge variant="outline">{finding.category}</Badge>
          <span className="text-muted-foreground text-xs">
            confidence {Math.round(finding.confidence * 100)}%
          </span>
        </div>
        <h2
          id="finding-title"
          tabIndex={-1}
          className="focus-visible:ring-ring text-lg font-semibold outline-none focus-visible:ring-2"
        >
          {finding.title}
        </h2>
        <p className="text-sm">{finding.description}</p>
        {finding.attack_techniques.length ? (
          <p className="flex flex-wrap gap-1 text-xs">
            <span className="text-muted-foreground">ATT&amp;CK:</span>
            {finding.attack_techniques.map((t) => (
              <a
                key={t}
                href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer noopener"
                className="text-primary font-mono underline"
              >
                {t}
              </a>
            ))}
          </p>
        ) : null}
        <p className="text-muted-foreground text-xs">
          Window {formatNs(finding.first_ns)} – {formatNs(finding.last_ns)} · {finding.origin} ·{" "}
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
        <section aria-labelledby="f-decide" className="grid gap-2 rounded-md border p-3">
          <h3 id="f-decide" className="text-sm font-semibold">
            Decision
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
        <h3 id="f-events" className="text-sm font-semibold">
          Supporting events ({finding.event_ids.length})
        </h3>
        <ul className="grid gap-1 text-sm">
          {finding.event_ids.slice(0, MAX_EVENTS).map((id, i) => {
            const e = events[i]?.data;
            return (
              <li key={id} className="flex min-w-0 items-baseline gap-2">
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
