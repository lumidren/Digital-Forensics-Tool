"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnchorIcon, ChevronLeftIcon, ChevronRightIcon, FileDownIcon, ShieldCheckIcon } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { Fragment, useState } from "react";
import { toast } from "sonner";
import { CopyButton, Mono, PageHeader, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect } from "@/components/ui/input";
import { Field } from "@/components/ui/label";
import { Alert, EmptyState } from "@/components/ui/misc";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useCase } from "@/hooks/use-case";
import { ApiError } from "@/lib/api";
import { api } from "@/lib/api-instance";
import { saveBlob, verifyCommand } from "@/lib/download";
import { gate } from "@/lib/roles";

export const CUSTODY_KINDS = [
  "genesis",
  "acquire",
  "ingest",
  "access",
  "export",
  "transform",
  "key_enrolled",
  "key_revoked",
  "anchor",
  "note",
];
const PAGE = 50;

export function CustodyPage() {
  const { caseId, access } = useCase();
  const params = useSearchParams();
  const qc = useQueryClient();
  const [kind, setKind] = useState("");
  const [evidenceId, setEvidenceId] = useState(params.get("evidence") ?? "");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [exported, setExported] = useState<string | null>(null);
  const evidence = useQuery({ queryKey: ["evidence", caseId], queryFn: () => api.listEvidence(caseId) });
  const page = useQuery({
    queryKey: ["custody", caseId, { kind, evidenceId, offset }],
    queryFn: () =>
      api.custody(caseId, {
        kind: kind || undefined,
        evidence_id: evidenceId || undefined,
        offset,
        limit: PAGE,
      }),
    placeholderData: (prev) => prev,
  });
  const verify = useMutation({ mutationFn: () => api.verifyCustody(caseId) });
  const anchor = useMutation({
    mutationFn: () => api.anchorCustody(caseId),
    onSuccess: (a) => {
      toast.success(`Ledger head #${a.seq} anchored`);
      void qc.invalidateQueries({ queryKey: ["custody", caseId] });
    },
  });
  const lead = gate(access, "lead");
  const examiner = gate(access, "examiner");
  const total = page.data?.total ?? 0;

  const doExport = async () => {
    try {
      const d = await api.exportCustody(caseId);
      saveBlob(d.blob, d.filename);
      setExported(d.filename);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : "Export failed");
    }
  };

  const v = verify.data;
  const cmd = verifyCommand(exported ?? `${caseId}-custody.json`);

  return (
    <>
      <PageHeader
        title="Chain of custody"
        description="Hash-chained, Ed25519-signed ledger of every acquisition, access, export and transformation."
        actions={
          <>
            <Button onClick={() => verify.mutate()} disabled={verify.isPending}>
              <ShieldCheckIcon aria-hidden /> {verify.isPending ? "Verifying…" : "Verify chain"}
            </Button>
            {examiner.allowed ? (
              <Button variant="outline" onClick={() => void doExport()}>
                <FileDownIcon aria-hidden /> Export signed JSON
              </Button>
            ) : null}
            {lead.allowed ? (
              <Button variant="outline" onClick={() => anchor.mutate()} disabled={anchor.isPending}>
                <AnchorIcon aria-hidden /> Anchor head
              </Button>
            ) : null}
          </>
        }
      />
      <div role="status" aria-live="polite">
        {v ? (
          <Alert
            variant={v.verdict === "PASS" ? "success" : "destructive"}
            className="mb-4"
            data-testid="custody-verdict"
          >
            <p className="text-base font-semibold">{v.verdict}</p>
            <p className="text-xs">
              {v.entries} entries verified; head <Mono>{v.head_hash ?? "—"}</Mono>
            </p>
            {v.failures.length ? (
              <ul className="mt-1 list-disc pl-4 text-xs">
                {v.failures.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            ) : null}
          </Alert>
        ) : null}
      </div>
      <Card className="mb-4" aria-labelledby="indep-verify">
        <CardHeader>
          <CardTitle id="indep-verify">Independent verification</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm">
          <p>
            Export the signed custody JSON, then verify it offline with the standalone verifier (no platform
            dependencies):
          </p>
          <div className="bg-muted/40 flex items-center gap-2 rounded-md border px-2 py-1">
            <code className="flex-1 font-mono text-xs break-all" data-testid="verify-command">
              {cmd}
            </code>
            <CopyButton text={cmd} label="verification command" />
          </div>
        </CardContent>
      </Card>
      <div className="mb-3 grid gap-3 sm:grid-cols-3">
        <Field label="Kind" htmlFor="cu-kind">
          <NativeSelect
            id="cu-kind"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All kinds</option>
            {CUSTODY_KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </NativeSelect>
        </Field>
        <Field label="Evidence" htmlFor="cu-ev">
          <NativeSelect
            id="cu-ev"
            value={evidenceId}
            onChange={(e) => {
              setEvidenceId(e.target.value);
              setOffset(0);
            }}
          >
            <option value="">All evidence</option>
            {(evidence.data ?? []).map((e) => (
              <option key={e.id} value={e.id}>
                {e.id} · {e.name}
              </option>
            ))}
          </NativeSelect>
        </Field>
      </div>
      <Card>
        <QueryStatus isLoading={page.isLoading} error={page.error}>
          {total === 0 ? (
            <CardContent>
              <EmptyState title="No entries match" />
            </CardContent>
          ) : (
            <>
              <Table aria-label="Custody entries">
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">#</TableHead>
                    <TableHead scope="col">Time</TableHead>
                    <TableHead scope="col">Kind</TableHead>
                    <TableHead scope="col">Actor</TableHead>
                    <TableHead scope="col">Evidence</TableHead>
                    <TableHead scope="col">Purpose</TableHead>
                    <TableHead scope="col">Entry hash</TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Details</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(page.data?.entries ?? []).map((e) => (
                    <Fragment key={e.entry_hash}>
                      <TableRow data-testid="custody-row">
                        <TableCell className="tabular">{e.seq}</TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap">
                          {String(e.timestamp ?? "")}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{e.kind}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{e.actor}</TableCell>
                        <TableCell className="font-mono text-xs">{e.evidence_id ?? "—"}</TableCell>
                        <TableCell className="max-w-[22rem] text-xs">{e.purpose}</TableCell>
                        <TableCell>
                          <Mono title={e.entry_hash}>{e.entry_hash.slice(0, 16)}…</Mono>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            aria-expanded={expanded === e.seq}
                            aria-controls={`cu-detail-${e.seq}`}
                            onClick={() => setExpanded(expanded === e.seq ? null : e.seq)}
                          >
                            {expanded === e.seq ? "Hide" : "Details"}
                            <span className="sr-only"> for entry {e.seq}</span>
                          </Button>
                        </TableCell>
                      </TableRow>
                      {expanded === e.seq ? (
                        <TableRow id={`cu-detail-${e.seq}`}>
                          <TableCell colSpan={8}>
                            <pre className="bg-muted/40 max-h-80 overflow-auto rounded-md p-2 text-xs">
                              {JSON.stringify(e, null, 2)}
                            </pre>
                          </TableCell>
                        </TableRow>
                      ) : null}
                    </Fragment>
                  ))}
                </TableBody>
              </Table>
              <div className="flex items-center justify-between border-t px-3 py-2 text-sm">
                <span className="tabular" role="status">
                  {offset + 1}–{Math.min(total, offset + PAGE)} of {total}
                </span>
                <div className="flex gap-1">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - PAGE))}
                  >
                    <ChevronLeftIcon aria-hidden /> Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={offset + PAGE >= total}
                    onClick={() => setOffset(offset + PAGE)}
                  >
                    Next <ChevronRightIcon aria-hidden />
                  </Button>
                </div>
              </div>
            </>
          )}
        </QueryStatus>
      </Card>
    </>
  );
}
