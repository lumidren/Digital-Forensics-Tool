"use client";

import { useQuery } from "@tanstack/react-query";
import {
  ActivityIcon,
  ArrowRightIcon,
  ChartAreaIcon,
  ClipboardListIcon,
  CrosshairIcon,
  FlagIcon,
  HardDriveIcon,
  LayoutDashboardIcon,
  LinkIcon,
  ListOrderedIcon,
  ServerIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  UsersIcon,
} from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";
import { AttackMatrix } from "@/components/attack-matrix";
import { AreaChart, BarList, Donut, Sparkline } from "@/components/charts";
import { CopyButton, Mono, PageHeader, QueryStatus, SEVERITY_COLOR, Stat } from "@/components/common";
import { CustodyKindIcon } from "@/components/custody-kind";
import { ProcessingQueue } from "@/components/processing-queue";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, EmptyState, Skeleton } from "@/components/ui/misc";
import { useCase } from "@/hooks/use-case";
import { ApiError } from "@/lib/api";
import { api } from "@/lib/api-instance";
import { cumulativeSeries, downsample, topWithOther } from "@/lib/charts";
import { formatDate, formatDuration, formatNsShort } from "@/lib/format";
import { fillBuckets } from "@/lib/histogram";
import { FINDING_STATES, SEVERITIES, type FindingState } from "@/lib/types";
import { cn } from "@/lib/utils";

export function countBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const it of items) out[key(it)] = (out[key(it)] ?? 0) + 1;
  return out;
}

const STATE_STYLE: Record<FindingState, string> = {
  proposed: "text-sev-low",
  confirmed: "text-warning",
  approved: "text-success",
  rejected: "text-muted-foreground",
};

const NO_FILTER = {};

function linkLabel(text: string) {
  return (
    <>
      {text} <ArrowRightIcon aria-hidden className="size-3" />
    </>
  );
}

const headerLink = "text-primary ml-auto inline-flex items-center gap-1 text-xs font-medium hover:underline";

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
  const custodyAll = useQuery({
    queryKey: ["custody-spark", caseId, total],
    queryFn: () => api.custody(caseId, { limit: 1000 }),
    enabled: head.isSuccess,
    meta: { silent: true },
  });
  const verify = useQuery({
    queryKey: ["custody-verify", caseId],
    queryFn: () => api.verifyCustody(caseId),
    staleTime: 30_000,
    meta: { silent: true },
  });
  const histogram = useQuery({
    queryKey: ["histogram", caseId, NO_FILTER],
    queryFn: () => api.histogram(caseId, NO_FILTER),
  });
  const hosts = useQuery({
    queryKey: ["facets", caseId, "host", NO_FILTER],
    queryFn: () => api.facets(caseId, "host", NO_FILTER),
    staleTime: 15_000,
  });
  const users = useQuery({
    queryKey: ["facets", caseId, "user", NO_FILTER],
    queryFn: () => api.facets(caseId, "user", NO_FILTER),
    staleTime: 15_000,
  });

  const all = useMemo(() => findings.data ?? [], [findings.data]);
  const live = all.filter((f) => f.state !== "rejected");
  const byState = countBy(all, (f) => f.state);
  const bySeverity = countBy(live, (f) => f.severity);
  const urgent = (bySeverity.critical ?? 0) + (bySeverity.high ?? 0);

  const bucketNs = histogram.data?.bucket_ns ?? 0;
  const dense = useMemo(
    () => fillBuckets(histogram.data?.buckets ?? [], bucketNs),
    [histogram.data, bucketNs],
  );
  const series = useMemo(() => downsample(dense, 96), [dense]);
  const seriesWidth = dense.length && series.length ? (bucketNs * dense.length) / series.length : bucketNs;
  const points = series.map((b) => ({ label: formatNsShort(b.start_ns), value: b.count }));
  const evSpark = downsample(dense, 24).map((b) => b.count);
  const evidenceSpark = cumulativeSeries(
    (evidence.data ?? []).map((e) => Date.parse(e.ingested)),
    12,
  );
  const custodySpark = cumulativeSeries(
    (custodyAll.data?.entries ?? []).map((e) => Date.parse(String(e.timestamp ?? ""))),
    16,
  );
  const findingSpark = cumulativeSeries(
    all.map((f) => f.first_ns ?? Number.NaN),
    16,
  );

  const barItems = (rows: { value: string; count: number }[] | undefined, param: string) =>
    topWithOther(rows ?? [], 6).map((r) => ({
      label: r.label,
      value: r.count,
      muted: r.other,
      href: r.other ? undefined : `/cases/${enc}/timeline?${param}=${encodeURIComponent(r.label)}`,
    }));

  const v = verify.data;
  const evStatus = countBy(evidence.data ?? [], (e) => e.status);
  const evidenceHint = [
    `${evStatus.processed ?? 0} processed`,
    ...(evStatus.failed ? [`${evStatus.failed} failed`] : []),
  ].join(" · ");

  return (
    <>
      <PageHeader
        icon={LayoutDashboardIcon}
        eyebrow="Case overview"
        title={kase?.name ?? "Case"}
        description={
          kase ? (
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-mono text-xs">{kase.id}</span>
              <Badge variant={kase.status === "open" ? "success" : "muted"}>{kase.status}</Badge>
              <span>your role: {kase.my_role}</span>
              {kase.legal_hold ? <Badge variant="warning">legal hold</Badge> : null}
            </span>
          ) : null
        }
      />
      <QueryStatus isLoading={query.isLoading} error={query.error}>
        <div className="grid grid-cols-1 gap-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Stat
              icon={HardDriveIcon}
              label="Evidence items"
              value={evidence.data?.length ?? "…"}
              hint={evidenceHint}
              chart={<Sparkline values={evidenceSpark} />}
            />
            <Stat
              icon={ActivityIcon}
              label="Timeline events"
              value={(kase?.event_count ?? 0).toLocaleString()}
              hint={bucketNs ? `${formatDuration(bucketNs)} buckets` : "No timed events"}
              chart={<Sparkline values={evSpark} />}
            />
            <Stat
              icon={FlagIcon}
              tone={urgent ? "critical" : "primary"}
              label="Findings"
              value={findings.data?.length ?? "…"}
              hint={`${urgent} critical or high · ${byState.approved ?? 0} approved`}
              chart={<Sparkline values={findingSpark} color="var(--sev-high)" />}
            />
            <Stat
              icon={LinkIcon}
              tone={v?.verdict === "FAIL" ? "critical" : "success"}
              label="Custody entries"
              value={head.data?.total ?? "…"}
              hint={v ? `Chain ${v.verdict === "PASS" ? "verified" : "broken"}` : "Verifying…"}
              chart={<Sparkline values={custodySpark} color="var(--success)" />}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Card className="min-w-0 xl:col-span-2" aria-labelledby="dash-events">
              <CardHeader>
                <CardTitle id="dash-events">
                  <ChartAreaIcon aria-hidden /> Events over time
                </CardTitle>
                <Link href={`/cases/${enc}/timeline`} className={headerLink}>
                  {linkLabel("Open timeline")}
                </Link>
              </CardHeader>
              <CardContent>
                {histogram.isLoading ? (
                  <Skeleton className="h-[180px] w-full" />
                ) : points.length ? (
                  <AreaChart
                    points={points}
                    label="Events per period across the case timeline"
                    footer={
                      dense[0] && seriesWidth
                        ? `${formatNsShort(dense[0].start_ns)} to ${formatNsShort(
                            (dense[dense.length - 1]?.start_ns ?? 0) + bucketNs,
                          )} UTC · ${formatDuration(seriesWidth)} per point`
                        : null
                    }
                  />
                ) : (
                  <EmptyState title="No timed events yet" icon={ChartAreaIcon}>
                    Events appear here once evidence has been parsed.
                  </EmptyState>
                )}
              </CardContent>
            </Card>

            <Card className="min-w-0" aria-labelledby="dash-findings">
              <CardHeader>
                <CardTitle id="dash-findings">
                  <FlagIcon aria-hidden /> Findings
                </CardTitle>
                <Link href={`/cases/${enc}/findings`} className={headerLink}>
                  {linkLabel("Open findings")}
                </Link>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4">
                <Donut
                  label="Findings by severity"
                  centerLabel="live findings"
                  slices={SEVERITIES.map((s) => ({
                    key: s,
                    label: s,
                    value: bySeverity[s] ?? 0,
                    color: SEVERITY_COLOR[s],
                  }))}
                  legendExtra={(s) => <span className="capitalize">{s.label}</span>}
                />
                <div>
                  <h3 className="eyebrow text-muted-foreground mb-1.5">Review workflow</h3>
                  <dl className="grid grid-cols-4 gap-1.5">
                    {FINDING_STATES.map((s) => (
                      <div
                        key={s}
                        className={cn(
                          "bg-muted/50 rounded-md border px-2 py-1.5",
                          s === "rejected" && "border-dashed",
                        )}
                      >
                        <dt className="text-muted-foreground truncate text-[11px] capitalize">{s}</dt>
                        <dd
                          className={cn("tabular text-lg leading-tight font-semibold", STATE_STYLE[s])}
                          data-testid={`state-${s}`}
                        >
                          {byState[s] ?? 0}
                        </dd>
                      </div>
                    ))}
                  </dl>
                  <p className="text-muted-foreground mt-1.5 text-xs">
                    Rules propose, an examiner confirms, a second reviewer approves. Rejected findings are
                    excluded from the chart.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card className="min-w-0" aria-labelledby="dash-attack">
            <CardHeader>
              <CardTitle id="dash-attack">
                <CrosshairIcon aria-hidden /> MITRE ATT&amp;CK coverage
              </CardTitle>
              <CardDescription>Techniques in proposed, confirmed and approved findings</CardDescription>
            </CardHeader>
            <CardContent>
              {findings.isLoading ? (
                <Skeleton className="h-28 w-full" />
              ) : live.some((f) => f.attack_techniques.length) ? (
                <AttackMatrix findings={all} caseId={caseId} />
              ) : (
                <EmptyState title="No techniques mapped yet" icon={CrosshairIcon}>
                  Techniques appear once analytics propose findings with ATT&amp;CK references.
                </EmptyState>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            <Card className="min-w-0" aria-labelledby="dash-hosts">
              <CardHeader>
                <CardTitle id="dash-hosts">
                  <ServerIcon aria-hidden /> Top hosts
                </CardTitle>
                <CardDescription className="ml-auto">by event count</CardDescription>
              </CardHeader>
              <CardContent>
                {hosts.isLoading ? (
                  <Skeleton className="h-40 w-full" />
                ) : (
                  <BarList
                    label="Top hosts by event count"
                    items={barItems(hosts.data, "host")}
                    empty={<EmptyState title="No host values" icon={ServerIcon} />}
                  />
                )}
              </CardContent>
            </Card>
            <Card className="min-w-0" aria-labelledby="dash-users">
              <CardHeader>
                <CardTitle id="dash-users">
                  <UsersIcon aria-hidden /> Top users
                </CardTitle>
                <CardDescription className="ml-auto">by event count</CardDescription>
              </CardHeader>
              <CardContent>
                {users.isLoading ? (
                  <Skeleton className="h-40 w-full" />
                ) : (
                  <BarList
                    label="Top users by event count"
                    items={barItems(users.data, "user").map((i) => ({ ...i, color: "var(--cat-7)" }))}
                    empty={<EmptyState title="No user values" icon={UsersIcon} />}
                  />
                )}
              </CardContent>
            </Card>
            <Card className="min-w-0 md:col-span-2 xl:col-span-1" aria-labelledby="dash-integrity">
              <CardHeader>
                <CardTitle id="dash-integrity">
                  <ShieldCheckIcon aria-hidden /> Custody integrity
                </CardTitle>
                <Link href={`/cases/${enc}/custody`} className={headerLink}>
                  {linkLabel("Ledger")}
                </Link>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-3">
                {verify.isLoading ? (
                  <Skeleton className="h-24 w-full" />
                ) : verify.error ? (
                  <Alert variant="destructive" role="alert">
                    {verify.error instanceof ApiError ? verify.error.detail : "Verification failed to run."}
                  </Alert>
                ) : v ? (
                  <>
                    <div
                      className={cn(
                        "flex items-center gap-3 rounded-lg border p-3",
                        v.verdict === "PASS"
                          ? "border-success/40 bg-success-soft"
                          : "border-destructive/40 bg-destructive-soft",
                      )}
                      data-testid="dashboard-custody-verdict"
                    >
                      {v.verdict === "PASS" ? (
                        <ShieldCheckIcon className="text-success size-8 shrink-0" aria-hidden />
                      ) : (
                        <ShieldAlertIcon className="text-destructive size-8 shrink-0" aria-hidden />
                      )}
                      <div className="min-w-0">
                        <p
                          className={cn(
                            "text-lg leading-tight font-semibold tracking-wide",
                            v.verdict === "PASS" ? "text-success" : "text-destructive",
                          )}
                        >
                          {v.verdict}
                        </p>
                        <p className="text-xs">
                          {v.entries.toLocaleString()} signed entries
                          {v.failures.length ? ` · ${v.failures.length} failure(s)` : " · hash chain intact"}
                        </p>
                      </div>
                    </div>
                    <dl className="grid grid-cols-1 gap-1 text-xs">
                      <dt className="text-muted-foreground">Ledger head hash</dt>
                      <dd className="bg-muted/50 flex items-center gap-1 rounded-md border py-0.5 pr-0.5 pl-2">
                        <Mono className="min-w-0 flex-1 truncate">{v.head_hash ?? "—"}</Mono>
                        {v.head_hash ? <CopyButton text={v.head_hash} label="ledger head hash" /> : null}
                      </dd>
                      <dt className="text-muted-foreground mt-1">Checked</dt>
                      <dd>{formatDate(new Date(verify.dataUpdatedAt).toISOString())}</dd>
                    </dl>
                  </>
                ) : null}
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Card className="min-w-0" aria-labelledby="dash-activity">
              <CardHeader>
                <CardTitle id="dash-activity">
                  <ListOrderedIcon aria-hidden /> Recent activity
                </CardTitle>
                <Link href={`/cases/${enc}/custody`} className={headerLink}>
                  {linkLabel("Custody ledger")}
                </Link>
              </CardHeader>
              <CardContent>
                <QueryStatus isLoading={recent.isLoading} error={recent.error}>
                  {recent.data?.entries.length ? (
                    <div className="relative">
                      <span aria-hidden className="bg-border absolute top-4 bottom-4 left-[13px] w-px" />
                      <ol className="relative grid gap-0.5 text-sm" reversed>
                        {[...recent.data.entries].reverse().map((e) => (
                          <li key={e.entry_hash} className="relative flex items-center gap-2.5 py-1">
                            <CustodyKindIcon kind={e.kind} className="ring-card ring-2" />
                            <div className="min-w-0 flex-1">
                              <p className="flex min-w-0 items-baseline gap-2">
                                <span className="truncate">{e.purpose}</span>
                                <Badge variant="outline" className="text-[10px]">
                                  {e.kind}
                                </Badge>
                              </p>
                              <p className="text-muted-foreground text-xs">
                                <span className="font-mono">#{e.seq}</span> · {e.actor} ·{" "}
                                {formatDate(typeof e.timestamp === "string" ? e.timestamp : null)}
                              </p>
                            </div>
                          </li>
                        ))}
                      </ol>
                    </div>
                  ) : (
                    <EmptyState title="No activity yet" icon={ListOrderedIcon} />
                  )}
                </QueryStatus>
              </CardContent>
            </Card>
            <Card className="min-w-0" aria-labelledby="dash-queue">
              <CardHeader>
                <CardTitle id="dash-queue">
                  <ClipboardListIcon aria-hidden /> Processing queue
                </CardTitle>
                <Link href={`/cases/${enc}/evidence`} className={headerLink}>
                  {linkLabel("Evidence intake")}
                </Link>
              </CardHeader>
              <CardContent>
                <ProcessingQueue caseId={caseId} evidence={evidence.data ?? []} compact />
              </CardContent>
            </Card>
          </div>
        </div>
      </QueryStatus>
    </>
  );
}
