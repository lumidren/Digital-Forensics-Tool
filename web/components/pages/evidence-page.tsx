"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { UploadIcon, XIcon } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, type DragEvent, type FormEvent } from "react";
import { toast } from "sonner";
import { GateNote, Mono, PageHeader, QueryStatus } from "@/components/common";
import { ProcessingQueue } from "@/components/processing-queue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, NativeSelect, Textarea } from "@/components/ui/input";
import { Field } from "@/components/ui/label";
import { Alert, EmptyState } from "@/components/ui/misc";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useCase } from "@/hooks/use-case";
import { useTableNav } from "@/hooks/use-table-nav";
import { ApiError, type UploadHandle } from "@/lib/api";
import { api } from "@/lib/api-instance";
import { formatBytes, formatDate, formatPercent, shortHash } from "@/lib/format";
import { gate } from "@/lib/roles";
import { cn } from "@/lib/utils";

export const EVIDENCE_KINDS = [
  { value: "file", label: "Single file / artifact" },
  { value: "triage", label: "Triage bundle (ZIP)" },
  { value: "disk", label: "Disk image (raw, E01, VHD)" },
  { value: "memory", label: "Memory image" },
  { value: "pcap", label: "Packet capture" },
  { value: "cloud", label: "Cloud audit log" },
  { value: "mobile", label: "Mobile backup" },
];

export function validSha256(v: string): boolean {
  return v === "" || /^[0-9a-fA-F]{64}$/.test(v);
}

interface UploadState {
  name: string;
  loaded: number;
  total: number;
  phase: "uploading" | "hashing" | "done" | "error";
  message?: string;
}

export function EvidencePage() {
  const { caseId, access } = useCase();
  const router = useRouter();
  const qc = useQueryClient();
  const evidence = useQuery({ queryKey: ["evidence", caseId], queryFn: () => api.listEvidence(caseId) });
  const canUpload = gate(access, "examiner");

  const fileInput = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [kind, setKind] = useState("file");
  const [expected, setExpected] = useState("");
  const [tz, setTz] = useState("");
  const [skew, setSkew] = useState("0");
  const [host, setHost] = useState("");
  const [description, setDescription] = useState("");
  const [upload, setUpload] = useState<UploadState | null>(null);
  const handle = useRef<UploadHandle | null>(null);

  const rows = evidence.data ?? [];
  const rowRefs = useRef<(HTMLTableRowElement | null)[]>([]);
  const open = (i: number) => {
    const ev = rows[i];
    if (ev) router.push(`/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(ev.id)}`);
  };
  const { selected, setSelected } = useTableNav(rows.length, {
    onOpen: open,
    onSelect: (i) => rowRefs.current[i]?.focus(),
  });

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  };

  const skewValid = /^-?\d+$/.test(skew.trim());
  const shaValid = validSha256(expected.trim());

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!file || !shaValid || !skewValid) return;
    setUpload({ name: file.name, loaded: 0, total: file.size, phase: "uploading" });
    const h = api.uploadEvidence(
      caseId,
      file,
      {
        kind,
        description: description.trim(),
        host: host.trim(),
        tz_name: tz.trim(),
        clock_skew_ms: Number(skew.trim()),
        expected_sha256: expected.trim().toLowerCase(),
      },
      (loaded, total) =>
        setUpload((u) => (u ? { ...u, loaded, total, phase: loaded >= total ? "hashing" : "uploading" } : u)),
    );
    handle.current = h;
    h.promise
      .then(async (ev) => {
        setUpload((u) =>
          u
            ? {
                ...u,
                loaded: u.total,
                phase: "done",
                message: `Stored as ${ev.id}; job ${ev.job_id} (${ev.classified_as}) queued.`,
              }
            : u,
        );
        toast.success(`Evidence ${ev.id} ingested`);
        setFile(null);
        setExpected("");
        if (fileInput.current) fileInput.current.value = "";
        await qc.invalidateQueries({ queryKey: ["evidence", caseId] });
        await qc.invalidateQueries({ queryKey: ["jobs", caseId] });
      })
      .catch((err: unknown) => {
        const message = err instanceof ApiError ? err.detail : "Upload failed";
        setUpload((u) => (u ? { ...u, phase: "error", message } : u));
      })
      .finally(() => {
        handle.current = null;
      });
  };

  const pct = upload && upload.total > 0 ? upload.loaded / upload.total : 0;

  return (
    <>
      <PageHeader
        title="Evidence"
        description="Intake, hashing, processing status and integrity verification."
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,26rem)_1fr]">
        <Card aria-labelledby="intake-title">
          <CardHeader>
            <CardTitle id="intake-title">Upload evidence</CardTitle>
          </CardHeader>
          <CardContent>
            {!canUpload.allowed ? (
              <GateNote reason={canUpload.reason} />
            ) : (
              <form className="grid gap-3" onSubmit={submit}>
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={onDrop}
                  className={cn(
                    "grid place-items-center gap-2 rounded-md border-2 border-dashed p-4 text-center text-sm",
                    dragging ? "border-primary bg-accent" : "border-input",
                  )}
                  data-testid="dropzone"
                >
                  <UploadIcon className="text-muted-foreground size-6" aria-hidden />
                  <p>{file ? <strong>{file.name}</strong> : "Drop a file here, or"}</p>
                  {file ? <p className="text-muted-foreground text-xs">{formatBytes(file.size)}</p> : null}
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => fileInput.current?.click()}>
                      Choose file…
                    </Button>
                    {file ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setFile(null);
                          if (fileInput.current) fileInput.current.value = "";
                        }}
                      >
                        <XIcon aria-hidden /> Clear
                      </Button>
                    ) : null}
                  </div>
                  <input
                    ref={fileInput}
                    id="evidence-file"
                    type="file"
                    className="sr-only"
                    aria-label="Evidence file"
                    onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                  />
                </div>
                <Field label="Kind" htmlFor="ev-kind">
                  <NativeSelect id="ev-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
                    {EVIDENCE_KINDS.map((k) => (
                      <option key={k.value} value={k.value}>
                        {k.label}
                      </option>
                    ))}
                  </NativeSelect>
                </Field>
                <Field
                  label="Expected SHA-256 (optional)"
                  htmlFor="ev-sha"
                  hint="The upload is rejected if the stored hash differs."
                >
                  <Input
                    id="ev-sha"
                    value={expected}
                    onChange={(e) => setExpected(e.target.value)}
                    className="font-mono text-xs"
                    spellCheck={false}
                    aria-invalid={!shaValid || undefined}
                    aria-describedby="ev-sha-hint"
                  />
                </Field>
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Source timezone" htmlFor="ev-tz">
                    <Input id="ev-tz" value={tz} onChange={(e) => setTz(e.target.value)} placeholder="UTC" />
                  </Field>
                  <Field label="Clock skew (ms)" htmlFor="ev-skew">
                    <Input
                      id="ev-skew"
                      inputMode="numeric"
                      value={skew}
                      onChange={(e) => setSkew(e.target.value)}
                      aria-invalid={!skewValid || undefined}
                    />
                  </Field>
                </div>
                <Field label="Host" htmlFor="ev-host">
                  <Input id="ev-host" value={host} onChange={(e) => setHost(e.target.value)} />
                </Field>
                <Field label="Description" htmlFor="ev-desc">
                  <Textarea
                    id="ev-desc"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="min-h-14"
                  />
                </Field>
                {!shaValid ? (
                  <p className="text-destructive text-xs">SHA-256 must be 64 hexadecimal characters.</p>
                ) : null}
                <div className="flex gap-2">
                  <Button
                    type="submit"
                    disabled={!file || !shaValid || !skewValid || upload?.phase === "uploading"}
                  >
                    Upload and hash
                  </Button>
                  {upload?.phase === "uploading" ? (
                    <Button variant="outline" onClick={() => handle.current?.abort()}>
                      Cancel
                    </Button>
                  ) : null}
                </div>
                {upload ? (
                  <div className="grid gap-1.5" data-testid="upload-progress">
                    <div className="flex justify-between text-xs">
                      <span className="truncate">{upload.name}</span>
                      <span className="tabular">
                        {formatBytes(upload.loaded)} / {formatBytes(upload.total)} ({formatPercent(pct)})
                      </span>
                    </div>
                    <Progress value={pct * 100} aria-label={`Upload of ${upload.name}`} />
                    <p role="status" aria-live="polite" className="text-xs">
                      {upload.phase === "uploading"
                        ? "Uploading…"
                        : upload.phase === "hashing"
                          ? "Upload complete; server is hashing and storing…"
                          : upload.phase === "done"
                            ? upload.message
                            : null}
                    </p>
                    {upload.phase === "error" ? (
                      <Alert variant="destructive" role="alert">
                        {upload.message}
                      </Alert>
                    ) : null}
                  </div>
                ) : null}
              </form>
            )}
          </CardContent>
        </Card>
        <Card aria-labelledby="queue-title">
          <CardHeader>
            <CardTitle id="queue-title">Processing queue</CardTitle>
          </CardHeader>
          <CardContent>
            <ProcessingQueue caseId={caseId} evidence={rows} />
          </CardContent>
        </Card>
      </div>
      <Card className="mt-4" aria-labelledby="ev-list-title">
        <CardHeader>
          <CardTitle id="ev-list-title">Evidence items</CardTitle>
        </CardHeader>
        <QueryStatus isLoading={evidence.isLoading} error={evidence.error}>
          {rows.length === 0 ? (
            <CardContent>
              <EmptyState title="No evidence yet" />
            </CardContent>
          ) : (
            <Table aria-label="Evidence items">
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">ID</TableHead>
                  <TableHead scope="col">Name</TableHead>
                  <TableHead scope="col">Kind</TableHead>
                  <TableHead scope="col" className="text-right">
                    Size
                  </TableHead>
                  <TableHead scope="col">SHA-256</TableHead>
                  <TableHead scope="col">Status</TableHead>
                  <TableHead scope="col">Ingested</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((ev, i) => (
                  <TableRow
                    key={ev.id}
                    ref={(el) => {
                      rowRefs.current[i] = el;
                    }}
                    tabIndex={-1}
                    aria-selected={selected === i}
                    onClick={() => setSelected(i)}
                  >
                    <TableCell className="font-mono text-xs">
                      <Link
                        href={`/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(ev.id)}`}
                        className="text-primary hover:underline"
                      >
                        {ev.id}
                      </Link>
                    </TableCell>
                    <TableCell className="max-w-[16rem] truncate">{ev.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{ev.kind}</Badge>
                    </TableCell>
                    <TableCell className="tabular text-right">{formatBytes(ev.size)}</TableCell>
                    <TableCell>
                      <Mono title={ev.sha256}>{shortHash(ev.sha256, 16)}</Mono>
                    </TableCell>
                    <TableCell data-testid="evidence-status">{ev.status}</TableCell>
                    <TableCell className="text-xs whitespace-nowrap">{formatDate(ev.ingested)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryStatus>
      </Card>
    </>
  );
}
