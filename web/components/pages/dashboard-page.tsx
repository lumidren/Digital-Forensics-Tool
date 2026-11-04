"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { PageHeader, QueryStatus, Stat } from "@/components/common";
import { ProcessingQueue } from "@/components/processing-queue";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/misc";
import { useCase } from "@/hooks/use-case";
import { api } from "@/lib/api-instance";
import { formatDate } from "@/lib/format";
import { FINDING_STATES, SEVERITIES } from "@/lib/types";

export function countBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const it of items) out[key(it)] = (out[key(it)] ?? 0) + 1;
  return out;
}

export function DashboardPage() {
  const { caseId, data: kase, query } = useCase();
  const enc = encodeURIComponent(caseId);
  const evidence = useQuery({ queryKey: ["evidence", caseId], queryFn: () => api.listEvidence(caseId) });
  const findings = useQuery({ queryKey: ["findings", caseId], queryFn: () => api.listFindings(caseId) });
  const head = useQuery({
    queryKey: ["custody-total", caseId],
    queryFn: () => api.custody(caseId, { limit: 1 }),
  });
  const total = head.data?.total ?? 0;
  const recent = useQuery({
    queryKey: ["custody-recent", caseId, total],
    queryFn: () => api.custody(caseId, { offset: Math.max(0, total - 8), limit: 8 }),
    enabled: head.isSuccess,
  });

  const byState = countBy(findings.data ?? [], (f) => f.state);
  const bySeverity = countBy(findings.data ?? [], (f) => f.severity);

  return (
    <>
      <PageHeader
        title={kase?.name ?? "Case"}
        description={
          kase ? (
            <>
              <span className="font-mono">{kase.id}</span> · {kase.status} · your role: {kase.my_role}
              {kase.legal_hold ? " · legal hold" : ""}
            </>
          ) : null
        }
      />
      <QueryStatus isLoading={query.isLoading} error={query.error}>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Evidence items" value={evidence.data?.length ?? "…"} />
          <Stat label="Timeline events" value={(kase?.event_count ?? 0).toLocaleString()} />
          <Stat
            label="Findings"
            value={findings.data?.length ?? "…"}
            hint={`${byState.approved ?? 0} approved`}
          />
          <Stat label="Custody entries" value={head.data?.total ?? "…"} />
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <Card aria-labelledby="dash-findings">
            <CardHeader>
              <CardTitle id="dash-findings">Findings</CardTitle>
              <Link href={`/cases/${enc}/findings`} className="text-primary ml-auto text-xs underline">
                Open findings
              </Link>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div>
                <h3 className="text-muted-foreground mb-1 text-xs font-medium">By state</h3>
                <dl className="grid gap-1 text-sm">
                  {FINDING_STATES.map((s) => (
                    <div key={s} className="flex justify-between">
                      <dt>{s}</dt>
                      <dd className="tabular" data-testid={`state-${s}`}>
                        {byState[s] ?? 0}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
              <div>
                <h3 className="text-muted-foreground mb-1 text-xs font-medium">By severity</h3>
                <dl className="grid gap-1 text-sm">
                  {SEVERITIES.map((s) => (
                    <div key={s} className="flex justify-between">
                      <dt>
                        <Badge variant={s}>{s}</Badge>
                      </dt>
                      <dd className="tabular">{bySeverity[s] ?? 0}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            </CardContent>
          </Card>
          <Card aria-labelledby="dash-activity">
            <CardHeader>
              <CardTitle id="dash-activity">Recent activity</CardTitle>
              <Link href={`/cases/${enc}/custody`} className="text-primary ml-auto text-xs underline">
                Custody ledger
              </Link>
            </CardHeader>
            <CardContent>
              <QueryStatus isLoading={recent.isLoading} error={recent.error}>
                {recent.data?.entries.length ? (
                  <ol className="grid gap-1.5 text-sm" reversed>
                    {[...recent.data.entries].reverse().map((e) => (
                      <li key={e.entry_hash} className="flex flex-wrap items-baseline gap-x-2">
                        <span className="text-muted-foreground font-mono text-xs">#{e.seq}</span>
                        <Badge variant="outline">{e.kind}</Badge>
                        <span className="min-w-0 flex-1 truncate">{e.purpose}</span>
                        <span className="text-muted-foreground text-xs">
                          {e.actor} · {formatDate(typeof e.timestamp === "string" ? e.timestamp : null)}
                        </span>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <EmptyState title="No activity yet" />
                )}
              </QueryStatus>
            </CardContent>
          </Card>
        </div>
        <Card className="mt-4" aria-labelledby="dash-queue">
          <CardHeader>
            <CardTitle id="dash-queue">Processing queue</CardTitle>
            <Link href={`/cases/${enc}/evidence`} className="text-primary ml-auto text-xs underline">
              Evidence intake
            </Link>
          </CardHeader>
          <CardContent>
            <ProcessingQueue caseId={caseId} evidence={evidence.data ?? []} compact />
          </CardContent>
        </Card>
      </QueryStatus>
    </>
  );
}
