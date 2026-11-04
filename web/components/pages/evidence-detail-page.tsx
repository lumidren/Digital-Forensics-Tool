"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCwIcon, ShieldCheckIcon } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { GateNote, HashLine, Mono, PageHeader, QueryStatus } from "@/components/common";
import { HexViewer } from "@/components/hex-viewer";
import { JobState } from "@/components/processing-queue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/misc";
import { useCase } from "@/hooks/use-case";
import { api } from "@/lib/api-instance";
import { formatBytes, formatDate } from "@/lib/format";
import { gate } from "@/lib/roles";

export function EvidenceDetailPage() {
  const { caseId, access } = useCase();
  const params = useParams<{ evidenceId: string }>();
  const evidenceId = decodeURIComponent(params.evidenceId);
  const qc = useQueryClient();
  const [verdict, setVerdict] = useState<{ ok: boolean; at: string } | null>(null);
  const ev = useQuery({
    queryKey: ["evidence", caseId, evidenceId],
    queryFn: () => api.getEvidence(caseId, evidenceId),
  });
  const ledger = useQuery({
    queryKey: ["custody", caseId, { evidence_id: evidenceId, kind: "ingest" }],
    queryFn: () => api.custody(caseId, { evidence_id: evidenceId, kind: "ingest" }),
  });
  const examiner = gate(access, "examiner");

  const verify = useMutation({
    mutationFn: () => api.verifyEvidence(caseId, evidenceId),
    onSuccess: (r) => {
      setVerdict({ ok: r.ok, at: new Date().toISOString() });
      if (r.ok) toast.success("Stored object matches its acquisition hash");
      else toast.error("INTEGRITY MISMATCH: stored object differs from its hash");
      void qc.invalidateQueries({ queryKey: ["custody", caseId] });
    },
  });
  const reprocess = useMutation({
    mutationFn: () => api.reprocessEvidence(caseId, evidenceId),
    onSuccess: (r) => {
      toast.success(`Job ${r.job_id} queued`);
      void qc.invalidateQueries({ queryKey: ["evidence", caseId, evidenceId] });
      void qc.invalidateQueries({ queryKey: ["jobs", caseId] });
    },
  });

  const entry = ledger.data?.entries[0];
  const e = ev.data;

  return (
    <QueryStatus isLoading={ev.isLoading} error={ev.error}>
      {e ? (
        <>
          <PageHeader
            title={e.name}
            description={
              <>
                <span className="font-mono">{e.id}</span> · {e.kind} · {formatBytes(e.size)} · status{" "}
                <span data-testid="evidence-status">{e.status}</span>
              </>
            }
            actions={
              <>
                <Button variant="outline" asChild>
                  <Link href={`/cases/${encodeURIComponent(caseId)}/evidence`}>All evidence</Link>
                </Button>
                {examiner.allowed ? (
                  <>
                    <Button
                      variant="outline"
                      onClick={() => reprocess.mutate()}
                      disabled={reprocess.isPending}
                    >
                      <RefreshCwIcon aria-hidden /> Reprocess
                    </Button>
                    <Button onClick={() => verify.mutate()} disabled={verify.isPending}>
                      <ShieldCheckIcon aria-hidden /> {verify.isPending ? "Verifying…" : "Verify integrity"}
                    </Button>
                  </>
                ) : null}
              </>
            }
          />
          <div role="status" aria-live="polite">
            {verdict ? (
              <Alert
                variant={verdict.ok ? "success" : "destructive"}
                className="mb-4"
                data-testid="integrity-verdict"
              >
                {verdict.ok ? "PASS" : "FAIL"}: the stored object {verdict.ok ? "matches" : "does NOT match"}{" "}
                SHA-256 {e.sha256} (checked {formatDate(verdict.at)}; recorded in custody).
              </Alert>
            ) : null}
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <Card aria-labelledby="ev-hashes">
              <CardHeader>
                <CardTitle id="ev-hashes">Hashes and metadata</CardTitle>
              </CardHeader>
              <CardContent>
                <dl>
                  <HashLine label="SHA-256" value={e.sha256} />
                  <HashLine label="SHA3-256" value={e.sha3_256} />
                  <HashLine label="MD5" value={e.md5} />
                  <HashLine label="Ingest entry" value={e.ingest_entry_hash} />
                </dl>
                <dl className="mt-3 grid grid-cols-[8rem_1fr] gap-x-2 gap-y-1 text-sm">
                  <dt className="text-muted-foreground">Size</dt>
                  <dd className="tabular">
                    {e.size.toLocaleString()} bytes ({formatBytes(e.size)})
                  </dd>
                  <dt className="text-muted-foreground">Host</dt>
                  <dd>{e.host ?? "—"}</dd>
                  <dt className="text-muted-foreground">Timezone</dt>
                  <dd>{e.tz_name ?? "—"}</dd>
                  <dt className="text-muted-foreground">Clock skew</dt>
                  <dd className="tabular">{e.clock_skew_ms} ms</dd>
                  <dt className="text-muted-foreground">Acquired by</dt>
                  <dd>{e.acquired_by ?? "—"}</dd>
                  <dt className="text-muted-foreground">Ingested</dt>
                  <dd>{formatDate(e.ingested)}</dd>
                  <dt className="text-muted-foreground">Description</dt>
                  <dd>{e.description || "—"}</dd>
                </dl>
              </CardContent>
            </Card>
            <Card aria-labelledby="ev-ledger">
              <CardHeader>
                <CardTitle id="ev-ledger">Ingest ledger entry</CardTitle>
                <Link
                  href={`/cases/${encodeURIComponent(caseId)}/custody?evidence=${encodeURIComponent(e.id)}`}
                  className="text-primary ml-auto text-xs underline"
                >
                  All custody entries for this item
                </Link>
              </CardHeader>
              <CardContent>
                <QueryStatus isLoading={ledger.isLoading} error={ledger.error}>
                  {entry ? (
                    <dl className="grid grid-cols-[7rem_1fr] gap-x-2 gap-y-1 text-sm">
                      <dt className="text-muted-foreground">Sequence</dt>
                      <dd className="tabular">#{entry.seq}</dd>
                      <dt className="text-muted-foreground">Actor</dt>
                      <dd>{entry.actor}</dd>
                      <dt className="text-muted-foreground">Signed by key</dt>
                      <dd>
                        <Mono>{String(entry.actor_key_id ?? "—")}</Mono>
                      </dd>
                      <dt className="text-muted-foreground">Time</dt>
                      <dd>{String(entry.timestamp ?? "—")}</dd>
                      <dt className="text-muted-foreground">Purpose</dt>
                      <dd>{entry.purpose}</dd>
                      <dt className="text-muted-foreground">Entry hash</dt>
                      <dd>
                        <Mono>{entry.entry_hash}</Mono>
                      </dd>
                      <dt className="text-muted-foreground">Previous</dt>
                      <dd>
                        <Mono>{String(entry.prev_hash ?? "—")}</Mono>
                      </dd>
                    </dl>
                  ) : (
                    <p className="text-muted-foreground text-sm">No ingest entry found.</p>
                  )}
                </QueryStatus>
              </CardContent>
            </Card>
          </div>
          <Card className="mt-4" aria-labelledby="ev-jobs">
            <CardHeader>
              <CardTitle id="ev-jobs">Processing jobs</CardTitle>
            </CardHeader>
            <CardContent>
              {e.jobs.length ? (
                <ul className="grid gap-2 text-sm">
                  {e.jobs.map((j) => (
                    <li key={j.job_id} className="flex flex-wrap items-center gap-2">
                      <Mono>{j.job_id}</Mono>
                      <Badge variant="outline">{j.kind}</Badge>
                      <JobState state={j.state} />
                      <span className="text-muted-foreground text-xs">
                        {j.steps.filter((s) => s.state === "done").length}/{j.steps.length} steps
                      </span>
                      {j.error ? <span className="text-destructive text-xs">{j.error}</span> : null}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted-foreground text-sm">No jobs.</p>
              )}
            </CardContent>
          </Card>
          <Card className="mt-4" aria-labelledby="ev-hex">
            <CardHeader>
              <CardTitle id="ev-hex">Byte browser</CardTitle>
            </CardHeader>
            <CardContent>
              {examiner.allowed ? (
                <HexViewer caseId={caseId} evidenceId={e.id} size={e.size} />
              ) : (
                <GateNote reason={examiner.reason} />
              )}
            </CardContent>
          </Card>
        </>
      ) : null}
    </QueryStatus>
  );
}
