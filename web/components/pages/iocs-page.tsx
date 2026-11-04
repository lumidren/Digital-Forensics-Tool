"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DownloadIcon, RadarIcon, Trash2Icon } from "lucide-react";
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { GateNote, PageHeader, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { EmptyState } from "@/components/ui/misc";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useCase } from "@/hooks/use-case";
import { ApiError } from "@/lib/api";
import { api } from "@/lib/api-instance";
import { saveBlob } from "@/lib/download";
import { gate } from "@/lib/roles";

export function IocsPage() {
  const { caseId, access } = useCase();
  const qc = useQueryClient();
  const iocs = useQuery({ queryKey: ["iocs", caseId], queryFn: () => api.listIocs(caseId) });
  const [text, setText] = useState("");
  const [filter, setFilter] = useState("");
  const [sweepSummary, setSweepSummary] = useState<string | null>(null);
  const examiner = gate(access, "examiner");

  const importIocs = useMutation({
    mutationFn: () => api.importIocs(caseId, text),
    onSuccess: (r) => {
      toast.success(`Imported ${r.added} new of ${r.total} indicators`);
      setText("");
      void qc.invalidateQueries({ queryKey: ["iocs", caseId] });
    },
  });
  const sweep = useMutation({
    mutationFn: () => api.sweepIocs(caseId),
    onSuccess: (r) => {
      const msg = `Sweep complete: ${r.total} hit${r.total === 1 ? "" : "s"} across ${Object.keys(r.by_ioc).length} indicator(s).`;
      setSweepSummary(msg);
      void qc.invalidateQueries({ queryKey: ["iocs", caseId] });
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.deleteIoc(caseId, id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["iocs", caseId] }),
  });

  const downloadStix = async () => {
    try {
      const d = await api.stix(caseId);
      saveBlob(d.blob, d.filename);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : "STIX export failed");
    }
  };

  const onImport = (e: FormEvent) => {
    e.preventDefault();
    if (text.trim()) importIocs.mutate();
  };

  const rows = (iocs.data ?? []).filter(
    (i) =>
      !filter || `${i.ioc_type} ${i.value} ${i.tags.join(" ")}`.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <>
      <PageHeader
        title="Indicators of compromise"
        description="Import indicators, sweep the case timeline, and export a STIX 2.1 bundle."
        actions={
          <>
            <Button variant="outline" onClick={() => void downloadStix()}>
              <DownloadIcon aria-hidden /> STIX bundle
            </Button>
            {examiner.allowed ? (
              <Button onClick={() => sweep.mutate()} disabled={sweep.isPending || !(iocs.data ?? []).length}>
                <RadarIcon aria-hidden /> {sweep.isPending ? "Sweeping…" : "Sweep timeline"}
              </Button>
            ) : null}
          </>
        }
      />
      <p role="status" aria-live="polite" className="mb-3 text-sm" data-testid="sweep-summary">
        {sweepSummary}
      </p>
      <div className="grid gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
        <Card aria-labelledby="ioc-import">
          <CardHeader>
            <CardTitle id="ioc-import">Import</CardTitle>
          </CardHeader>
          <CardContent>
            {examiner.allowed ? (
              <form onSubmit={onImport} className="grid gap-2">
                <Label htmlFor="ioc-text">Indicators</Label>
                <Textarea
                  id="ioc-text"
                  className="min-h-40 font-mono text-xs"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder={"mimikatz.exe\nsha256:…\nipv4:203.0.113.7\nevil.example.com"}
                  aria-describedby="ioc-help"
                />
                <p id="ioc-help" className="text-muted-foreground text-xs">
                  One per line as <code>type:value</code> or a bare value (type inferred), or a JSON list of{" "}
                  <code>{"{ioc_type, value}"}</code> objects. Lines starting with # are ignored.
                </p>
                <Button type="submit" disabled={!text.trim() || importIocs.isPending}>
                  Import
                </Button>
              </form>
            ) : (
              <GateNote reason={examiner.reason} />
            )}
          </CardContent>
        </Card>
        <Card aria-labelledby="ioc-list">
          <CardHeader>
            <CardTitle id="ioc-list">Indicators ({iocs.data?.length ?? 0})</CardTitle>
            <div className="ml-auto w-full sm:w-56">
              <Label htmlFor="ioc-filter" className="sr-only">
                Filter indicators
              </Label>
              <Input
                id="ioc-filter"
                data-search
                placeholder="Filter…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            </div>
          </CardHeader>
          <QueryStatus isLoading={iocs.isLoading} error={iocs.error}>
            {rows.length === 0 ? (
              <CardContent>
                <EmptyState title="No indicators" />
              </CardContent>
            ) : (
              <Table aria-label="Indicators">
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Type</TableHead>
                    <TableHead scope="col">Value</TableHead>
                    <TableHead scope="col">Source</TableHead>
                    <TableHead scope="col">Tags</TableHead>
                    <TableHead scope="col" className="text-right">
                      Hits
                    </TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((i) => (
                    <TableRow key={i.id} data-testid="ioc-row">
                      <TableCell>
                        <Badge variant="outline">{i.ioc_type}</Badge>
                      </TableCell>
                      <TableCell className="max-w-[28rem] font-mono text-xs break-all">{i.value}</TableCell>
                      <TableCell className="text-xs">{i.source}</TableCell>
                      <TableCell>
                        {i.tags.map((t) => (
                          <Badge key={t} variant="secondary" className="mr-1">
                            {t}
                          </Badge>
                        ))}
                      </TableCell>
                      <TableCell className="tabular text-right" data-testid="ioc-hits">
                        {i.hits > 0 ? (
                          <a
                            className="text-primary underline"
                            href={`/cases/${encodeURIComponent(caseId)}/timeline?q=${encodeURIComponent(`"${i.value}"`)}`}
                          >
                            {i.hits}
                          </a>
                        ) : (
                          i.hits
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        {examiner.allowed ? (
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={`Delete indicator ${i.value}`}
                            onClick={() => remove.mutate(i.id)}
                          >
                            <Trash2Icon aria-hidden />
                          </Button>
                        ) : null}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </QueryStatus>
        </Card>
      </div>
    </>
  );
}
