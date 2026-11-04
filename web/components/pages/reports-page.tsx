"use client";

import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  FileCheck2Icon,
  FileDownIcon,
  FilePenLineIcon,
  FileSignatureIcon,
  FileTextIcon,
  PlusIcon,
  XIcon,
} from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { GateNote, Mono, PageHeader, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, NativeSelect } from "@/components/ui/input";
import { Field, Label } from "@/components/ui/label";
import { Alert, EmptyState } from "@/components/ui/misc";
import { useCase } from "@/hooks/use-case";
import { ApiError } from "@/lib/api";
import { api } from "@/lib/api-instance";
import { saveBlob, sha256Hex } from "@/lib/download";
import { formatBytes, formatDate } from "@/lib/format";
import { gate } from "@/lib/roles";
import type { ReportCreated, ReportListItem } from "@/lib/types";

interface DownloadCheck {
  reportId: string;
  computed: string;
  expected: string;
}

export function ReportsPage() {
  const { caseId, access } = useCase();
  const qc = useQueryClient();
  const reports = useQuery({ queryKey: ["reports", caseId], queryFn: () => api.listReports(caseId) });
  const approved = useQuery({
    queryKey: ["findings", caseId, "approved"],
    queryFn: () => api.listFindings(caseId, "approved"),
  });
  const signatures = useQueries({
    queries: (reports.data ?? []).map((r) => ({
      queryKey: ["report-sig", caseId, r.id],
      queryFn: () => api.reportSignature(caseId, r.id),
      staleTime: Number.POSITIVE_INFINITY,
      meta: { silent: true },
    })),
  });
  const [format, setFormat] = useState<"pdf" | "docx">("pdf");
  const [template, setTemplate] = useState("default");
  const [limitation, setLimitation] = useState("");
  const [limitations, setLimitations] = useState<string[]>([]);
  const [last, setLast] = useState<ReportCreated | null>(null);
  const [check, setCheck] = useState<DownloadCheck | null>(null);
  const examiner = gate(access, "examiner");

  const generate = useMutation({
    mutationFn: () =>
      api.createReport(caseId, { format, template: template.trim() || "default", limitations }),
    onSuccess: (r) => {
      setLast(r);
      toast.success(`Report ${r.id} generated and signed`);
      void qc.invalidateQueries({ queryKey: ["reports", caseId] });
    },
  });

  const addLimitation = (e: FormEvent) => {
    e.preventDefault();
    const v = limitation.trim();
    if (v && !limitations.includes(v)) setLimitations([...limitations, v]);
    setLimitation("");
  };

  const download = async (r: ReportListItem, part: "document" | "signature") => {
    try {
      const d = await api.downloadReport(caseId, r.id, part);
      if (part === "document") {
        const computed = await sha256Hex(d.blob);
        setCheck({ reportId: r.id, computed, expected: r.sha256 });
        if (computed !== r.sha256) toast.error("Downloaded report does not match its recorded SHA-256");
      }
      saveBlob(d.blob, d.filename);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : "Download failed");
    }
  };

  return (
    <>
      <PageHeader
        icon={FileTextIcon}
        title="Reports"
        description="Deterministic PDF/DOCX reports of approved findings, signed with your examiner key and recorded in custody."
      />
      <div className="grid gap-4 lg:grid-cols-[24rem_minmax(0,1fr)]">
        <Card aria-labelledby="rb-title">
          <CardHeader>
            <CardTitle id="rb-title">
              <FilePenLineIcon aria-hidden /> Report builder
            </CardTitle>
          </CardHeader>
          <CardContent>
            {examiner.allowed ? (
              <div className="grid gap-3">
                <p className="text-sm">
                  <span className="tabular font-semibold">{approved.data?.length ?? "…"}</span> approved
                  finding(s) will be included.
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Format" htmlFor="rep-format">
                    <NativeSelect
                      id="rep-format"
                      value={format}
                      onChange={(e) => setFormat(e.target.value as "pdf" | "docx")}
                    >
                      <option value="pdf">PDF</option>
                      <option value="docx">DOCX</option>
                    </NativeSelect>
                  </Field>
                  <Field label="Template" htmlFor="rep-template">
                    <Input id="rep-template" value={template} onChange={(e) => setTemplate(e.target.value)} />
                  </Field>
                </div>
                <form onSubmit={addLimitation} className="grid gap-1.5">
                  <Label htmlFor="rep-limit">Limitations</Label>
                  <div className="flex gap-2">
                    <Input
                      id="rep-limit"
                      value={limitation}
                      onChange={(e) => setLimitation(e.target.value)}
                      placeholder="e.g. Volume shadow copies not examined"
                    />
                    <Button
                      type="submit"
                      variant="secondary"
                      size="icon"
                      aria-label="Add limitation"
                      disabled={!limitation.trim()}
                    >
                      <PlusIcon aria-hidden />
                    </Button>
                  </div>
                </form>
                {limitations.length ? (
                  <ul className="grid gap-1 text-sm" aria-label="Limitations to include">
                    {limitations.map((l) => (
                      <li key={l} className="flex items-start gap-1">
                        <span className="flex-1">{l}</span>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Remove limitation: ${l}`}
                          onClick={() => setLimitations(limitations.filter((x) => x !== l))}
                        >
                          <XIcon aria-hidden />
                        </Button>
                      </li>
                    ))}
                  </ul>
                ) : null}
                <Button onClick={() => generate.mutate()} disabled={generate.isPending}>
                  <FileSignatureIcon aria-hidden /> {generate.isPending ? "Generating…" : "Generate and sign"}
                </Button>
                <div role="status" aria-live="polite">
                  {last ? (
                    <Alert variant="success" data-testid="report-created">
                      <p className="font-medium">
                        Report {last.id} ({formatBytes(last.size)})
                      </p>
                      <p className="mt-1 text-xs">
                        SHA-256 <Mono>{last.report_sha256}</Mono>
                      </p>
                      <p className="text-xs">
                        Signed by {last.signer} with key <Mono>{last.signer_key_id}</Mono>
                      </p>
                    </Alert>
                  ) : null}
                </div>
              </div>
            ) : (
              <GateNote reason={examiner.reason} />
            )}
          </CardContent>
        </Card>
        <Card aria-labelledby="rep-list">
          <CardHeader>
            <CardTitle id="rep-list">
              <FileCheck2Icon aria-hidden /> Generated reports
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div role="status" aria-live="polite">
              {check ? (
                <Alert
                  variant={check.computed === check.expected ? "success" : "destructive"}
                  className="mb-3"
                  data-testid="hash-check"
                >
                  {check.computed === check.expected ? "Hash matches" : "HASH MISMATCH"}: downloaded{" "}
                  {check.reportId} SHA-256 <Mono>{check.computed}</Mono>
                </Alert>
              ) : null}
            </div>
            <QueryStatus isLoading={reports.isLoading} error={reports.error}>
              {(reports.data ?? []).length === 0 ? (
                <EmptyState title="No reports yet" icon={FileTextIcon} />
              ) : (
                <ul className="grid gap-3">
                  {(reports.data ?? []).map((r, i) => {
                    const sig = signatures[i]?.data;
                    return (
                      <li key={r.id} className="rounded-md border p-3 text-sm" data-testid="report-row">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono font-medium">{r.id}</span>
                          <Badge variant="outline">{r.format.toUpperCase()}</Badge>
                          <span className="text-muted-foreground text-xs">
                            {r.created_by} · {formatDate(r.created)}
                          </span>
                          <span className="ml-auto flex gap-1">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => void download(r, "document")}
                              aria-label={`Download document ${r.id}`}
                            >
                              <FileDownIcon aria-hidden /> Document
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => void download(r, "signature")}
                              aria-label={`Download signature ${r.id}`}
                            >
                              <FileSignatureIcon aria-hidden /> Signature
                            </Button>
                          </span>
                        </div>
                        <dl className="mt-2 grid grid-cols-[7rem_1fr] gap-x-2 gap-y-0.5 text-xs">
                          <dt className="text-muted-foreground">SHA-256</dt>
                          <dd>
                            <Mono>{r.sha256}</Mono>
                          </dd>
                          <dt className="text-muted-foreground">State hash</dt>
                          <dd>
                            <Mono>{r.state_hash}</Mono>
                          </dd>
                          <dt className="text-muted-foreground">Signer key</dt>
                          <dd>
                            <Mono>{sig?.signer_key_id ?? "…"}</Mono>
                          </dd>
                          <dt className="text-muted-foreground">Ledger entry</dt>
                          <dd>
                            <Mono>{r.ledger_entry_hash}</Mono>
                          </dd>
                        </dl>
                      </li>
                    );
                  })}
                </ul>
              )}
            </QueryStatus>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
