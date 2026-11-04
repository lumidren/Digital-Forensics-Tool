"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
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

const STATE_VARIANT: Record<string, "outline" | "warning" | "success" | "destructive" | "secondary"> = {
  pending: "outline",
  running: "warning",
  done: "success",
  failed: "destructive",
  skipped: "secondary",
};

export function JobState({ state }: { state: string }) {
  return <Badge variant={STATE_VARIANT[state] ?? "outline"}>{state}</Badge>;
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
      <p className="text-muted-foreground mb-2 text-xs">
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
          <EmptyState title="No processing jobs">Upload evidence to start processing.</EmptyState>
        ) : (
          <ul className="grid gap-3" aria-label="Processing jobs">
            {shown.map((job) => {
              const name = names.get(job.evidence_sha256) ?? job.evidence_sha256.slice(0, 12);
              const frac = jobFraction(job);
              return (
                <li key={job.job_id} className="rounded-md border p-3" data-testid="job">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{name}</span>
                    <span className="text-muted-foreground font-mono text-xs">{job.job_id}</span>
                    <Badge variant="outline">{job.kind}</Badge>
                    <span className="ml-auto" data-testid="job-state">
                      <JobState state={job.state} />
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <Progress value={frac * 100} aria-label={`${name} overall progress`} className="h-2.5" />
                    <span className="tabular w-10 text-right text-xs">{formatPercent(frac)}</span>
                  </div>
                  {job.error ? <p className="text-destructive mt-1 text-xs">{job.error}</p> : null}
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
