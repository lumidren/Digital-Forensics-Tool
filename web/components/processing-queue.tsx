"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckIcon,
  ChevronRightIcon,
  CircleIcon,
  Clock3Icon,
  InboxIcon,
  LoaderCircleIcon,
  MinusIcon,
  XIcon,
} from "lucide-react";
import { useMemo, useState } from "react";
import { QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/misc";
import { Progress } from "@/components/ui/progress";
import { useCaseSocket } from "@/hooks/use-case-socket";
import { useToken } from "@/hooks/use-session";
import { api } from "@/lib/api-instance";
import { formatPercent } from "@/lib/format";
import { isActive, jobFraction, mergeJobs } from "@/lib/progress";
import type { Evidence, Job, ProgressMessage } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATE_VARIANT: Record<string, "outline" | "warning" | "success" | "destructive-soft" | "muted"> = {
  pending: "outline",
  running: "warning",
  done: "success",
  failed: "destructive-soft",
  skipped: "muted",
};

const STATE_ICON: Record<string, typeof CircleIcon> = {
  pending: Clock3Icon,
  running: LoaderCircleIcon,
  done: CheckIcon,
  failed: XIcon,
  skipped: MinusIcon,
};

export function JobState({ state }: { state: string }) {
  const Icon = STATE_ICON[state] ?? CircleIcon;
  return (
    <Badge variant={STATE_VARIANT[state] ?? "outline"}>
      <Icon aria-hidden className={cn(state === "running" && "motion-safe:animate-spin")} />
      {state}
    </Badge>
  );
}

/** One chip per pipeline step: icon + name, coloured by state; the state is in the accessible name. */
export function StepChips({ steps }: { steps: Job["steps"] }) {
  if (!steps.length) return null;
  return (
    <ol className="flex flex-wrap items-center gap-1" aria-label="Pipeline steps">
      {steps.map((s, i) => {
        const Icon = STATE_ICON[s.state] ?? CircleIcon;
        return (
          <li key={s.name} className="flex items-center gap-1">
            {i > 0 ? <ChevronRightIcon aria-hidden className="text-muted-foreground size-3" /> : null}
            <Badge
              variant={STATE_VARIANT[s.state] ?? "outline"}
              className="font-mono text-[11px]"
              title={s.message ?? `${s.name}: ${s.state}`}
            >
              <Icon aria-hidden className={cn(s.state === "running" && "motion-safe:animate-spin")} />
              {s.name}
              <span className="sr-only">: {s.state}</span>
            </Badge>
          </li>
        );
      })}
    </ol>
  );
}

export function ProcessingQueue({
  caseId,
  evidence,
  compact = false,
}: {
  caseId: string;
  evidence: Evidence[];
  compact?: boolean;
}) {
  const qc = useQueryClient();
  const token = useToken();
  const [announcement, setAnnouncement] = useState("");
  const jobs = useQuery({
    queryKey: ["jobs", caseId],
    queryFn: () => api.listJobs(caseId),
    refetchInterval: (q) => ((q.state.data ?? []).some(isActive) ? 3000 : false),
  });

  const onMessage = (msg: ProgressMessage) => {
    if (msg.state === "done" || msg.state === "failed") {
      void qc.invalidateQueries({ queryKey: ["jobs", caseId] });
      void qc.invalidateQueries({ queryKey: ["evidence", caseId] });
      setAnnouncement(`Step ${msg.step} ${msg.state === "done" ? "completed" : "failed"}`);
    }
  };
  const { live, status } = useCaseSocket({ url: token ? () => api.wsUrl(caseId) : null, onMessage });

  const names = useMemo(() => new Map(evidence.map((e) => [e.sha256, e.name])), [evidence]);
  const merged: Job[] = mergeJobs(jobs.data ?? [], live);
  const shown = compact ? [...merged].reverse().slice(0, 5) : [...merged].reverse();

  return (
    <div>
      <p className="text-muted-foreground mb-2 flex items-center gap-1.5 text-xs">
        <span
          aria-hidden
          className={cn(
            "relative grid size-2 place-items-center rounded-full",
            status === "open" ? "bg-success" : "bg-muted-foreground/60",
          )}
        >
          {status === "open" ? (
            <span className="bg-success absolute inset-0 rounded-full opacity-60 motion-safe:animate-ping" />
          ) : null}
        </span>
        Live updates:{" "}
        <span data-testid="ws-status">
          {status === "open" ? "connected" : status === "denied" ? "not permitted" : status}
        </span>
      </p>
      <p className="sr-only" role="status" aria-live="polite">
        {announcement}
      </p>
      <QueryStatus isLoading={jobs.isLoading} error={jobs.error}>
        {shown.length === 0 ? (
          <EmptyState title="No processing jobs" icon={InboxIcon}>
            Upload evidence to start processing.
          </EmptyState>
        ) : (
          <ul className="grid gap-3" aria-label="Processing jobs">
            {shown.map((job) => {
              const name = names.get(job.evidence_sha256) ?? job.evidence_sha256.slice(0, 12);
              const frac = jobFraction(job);
              return (
                <li
                  key={job.job_id}
                  className={cn(
                    "bg-card rounded-lg border p-3 transition-colors",
                    job.state === "failed" && "border-destructive/40",
                    job.state === "running" && "border-warning/50",
                  )}
                  data-testid="job"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{name}</span>
                    <span className="text-muted-foreground font-mono text-xs">{job.job_id}</span>
                    <Badge variant="outline">{job.kind}</Badge>
                    <span className="ml-auto" data-testid="job-state">
                      <JobState state={job.state} />
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <Progress
                      value={frac * 100}
                      aria-label={`${name} overall progress`}
                      className="h-2"
                      indicatorClassName={cn(
                        job.state === "failed" && "bg-destructive",
                        job.state === "done" && "bg-success",
                      )}
                    />
                    <span className="tabular w-10 text-right text-xs">{formatPercent(frac)}</span>
                  </div>
                  {compact ? (
                    <div className="mt-2">
                      <StepChips steps={job.steps} />
                    </div>
                  ) : null}
                  {job.error ? <p className="text-destructive mt-1.5 text-xs">{job.error}</p> : null}
                  {!compact && job.steps.length ? (
                    <ol className="mt-2 grid gap-1.5" aria-label={`Steps for ${name}`}>
                      {job.steps.map((s) => (
                        <li
                          key={s.name}
                          className="grid grid-cols-[minmax(6rem,10rem)_1fr_auto] items-center gap-2 text-xs"
                        >
                          <span className="truncate font-mono" title={s.name}>
                            {s.name}
                          </span>
                          <Progress
                            value={(s.state === "done" || s.state === "skipped" ? 1 : s.progress) * 100}
                            aria-label={`${s.name}: ${s.state}`}
                            indicatorClassName={s.state === "failed" ? "bg-destructive" : undefined}
                          />
                          <JobState state={s.state} />
                          {s.message ? (
                            <span className="text-muted-foreground col-span-3 truncate" title={s.message}>
                              {s.message}
                            </span>
                          ) : null}
                        </li>
                      ))}
                    </ol>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </QueryStatus>
    </div>
  );
}
