"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FlagIcon, PlayIcon, PlusIcon, SearchXIcon } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useRef, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { PageHeader, QueryStatus, SEVERITY_COLOR, SeverityBadge } from "@/components/common";
import { FindingDetail } from "@/components/findings/finding-detail";
import { Hypotheses } from "@/components/findings/hypotheses";
import { TasksBoard } from "@/components/findings/tasks-board";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input, NativeSelect, Textarea } from "@/components/ui/input";
import { Field, Label } from "@/components/ui/label";
import { EmptyState } from "@/components/ui/misc";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCase } from "@/hooks/use-case";
import { useTableNav } from "@/hooks/use-table-nav";
import { api } from "@/lib/api-instance";
import {
  distinct,
  filterFindings,
  groupByState,
  NO_FINDING_FILTER,
  parseIdList,
  parseTechniques,
  type FindingFilter,
} from "@/lib/findings";
import { gate } from "@/lib/roles";
import { SEVERITIES, type Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

export function FindingsPage() {
  const { caseId, access, data: kase } = useCase();
  const qc = useQueryClient();
  const findings = useQuery({ queryKey: ["findings", caseId], queryFn: () => api.listFindings(caseId) });
  const params = useSearchParams();
  const [filter, setFilter] = useState<FindingFilter>(() => ({
    ...NO_FINDING_FILTER,
    technique: params.get("technique") ?? "",
  }));
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [manualOpen, setManualOpen] = useState(false);
  const examiner = gate(access, "examiner");
  const all = findings.data ?? [];
  const filtered = filterFindings(all, filter);
  const groups = groupByState(filtered);
  const flat = groups.flatMap((g) => g.items);
  // Never show an empty detail panel: fall back to the first finding in the filtered list.
  const selected = all.find((f) => f.id === selectedId) ?? flat[0] ?? null;
  const itemRefs = useRef(new Map<string, HTMLButtonElement>());

  const { selected: navIndex, setSelected: setNavIndex } = useTableNav(flat.length, {
    onSelect: (i) => {
      const f = flat[i];
      if (f) {
        setSelectedId(f.id);
        itemRefs.current.get(f.id)?.focus();
      }
    },
    onOpen: (i) => {
      const f = flat[i];
      if (f) setSelectedId(f.id);
      document.getElementById("finding-title")?.focus();
    },
  });

  const run = useMutation({
    mutationFn: () => api.runFindings(caseId),
    onSuccess: (r) => {
      toast.success(`Analytics ran: ${r.proposed} new proposal${r.proposed === 1 ? "" : "s"}`);
      void qc.invalidateQueries({ queryKey: ["findings", caseId] });
    },
  });

  const [mTitle, setMTitle] = useState("");
  const [mDesc, setMDesc] = useState("");
  const [mSev, setMSev] = useState<Severity>("medium");
  const [mCat, setMCat] = useState("manual");
  const [mTech, setMTech] = useState("");
  const [mEvents, setMEvents] = useState("");
  const manual = useMutation({
    mutationFn: (ids: number[]) =>
      api.createFinding(caseId, {
        title: mTitle.trim(),
        description: mDesc.trim(),
        severity: mSev,
        category: mCat.trim() || "manual",
        attack_techniques: parseTechniques(mTech),
        event_ids: ids,
      }),
    onSuccess: (r) => {
      toast.success("Manual finding proposed");
      setManualOpen(false);
      setMTitle("");
      setMDesc("");
      setMTech("");
      setMEvents("");
      setSelectedId(r.id);
      void qc.invalidateQueries({ queryKey: ["findings", caseId] });
    },
  });
  const submitManual = (e: FormEvent) => {
    e.preventDefault();
    const ids = parseIdList(mEvents);
    if (ids === null) {
      toast.error("Event ids must be numbers separated by commas or spaces.");
      return;
    }
    if (mTitle.trim() && mDesc.trim()) manual.mutate(ids);
  };

  const rules = distinct(all, (f) => [f.rule]);
  const techniques = distinct(all, (f) => f.attack_techniques);

  return (
    <>
      <PageHeader
        icon={FlagIcon}
        title="Findings"
        description="Rules propose; an examiner confirms with a rationale; a different reviewer approves. Only approved findings reach reports."
        actions={
          examiner.allowed ? (
            <>
              <Button variant="outline" onClick={() => setManualOpen(true)}>
                <PlusIcon aria-hidden /> Manual finding
              </Button>
              <Button onClick={() => run.mutate()} disabled={run.isPending}>
                <PlayIcon aria-hidden /> {run.isPending ? "Running…" : "Run analytics"}
              </Button>
            </>
          ) : null
        }
      />
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings ({all.length})</TabsTrigger>
          <TabsTrigger value="hypotheses">Hypotheses</TabsTrigger>
          <TabsTrigger value="tasks">Tasks</TabsTrigger>
        </TabsList>
        <TabsContent value="findings">
          <div className="mb-3 grid gap-2 sm:grid-cols-3" role="group" aria-label="Finding filters">
            <Field label="Severity" htmlFor="ff-sev">
              <NativeSelect
                id="ff-sev"
                value={filter.severity}
                onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
              >
                <option value="">All severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </NativeSelect>
            </Field>
            <Field label="Rule" htmlFor="ff-rule">
              <NativeSelect
                id="ff-rule"
                value={filter.rule}
                onChange={(e) => setFilter({ ...filter, rule: e.target.value })}
              >
                <option value="">All rules</option>
                {rules.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </NativeSelect>
            </Field>
            <Field label="ATT&CK technique" htmlFor="ff-tech">
              <Input
                id="ff-tech"
                list="ff-tech-list"
                data-search
                value={filter.technique}
                onChange={(e) => setFilter({ ...filter, technique: e.target.value })}
                placeholder="T1021"
              />
              <datalist id="ff-tech-list">
                {techniques.map((t) => (
                  <option key={t} value={t} />
                ))}
              </datalist>
            </Field>
          </div>
          <QueryStatus isLoading={findings.isLoading} error={findings.error}>
            {all.length === 0 ? (
              <EmptyState title="No findings yet" icon={FlagIcon}>
                {examiner.allowed ? "Run analytics to propose findings from the timeline." : null}
              </EmptyState>
            ) : (
              <div className="grid grid-cols-[minmax(0,1fr)] gap-4 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
                <nav aria-label="Findings by state" className="grid min-w-0 content-start gap-3">
                  {groups.map((g) => (
                    <section key={g.state} aria-labelledby={`fg-${g.state}`}>
                      <h2
                        id={`fg-${g.state}`}
                        className="text-muted-foreground mb-1.5 flex items-center gap-2 text-xs font-semibold uppercase"
                      >
                        {g.state} ({g.items.length})
                        <span aria-hidden className="bg-border h-px flex-1" />
                      </h2>
                      <ul className="grid gap-1.5">
                        {g.items.map((f) => {
                          const idx = flat.indexOf(f);
                          const isSel = f.id === selected?.id;
                          return (
                            <li key={f.id}>
                              <button
                                type="button"
                                ref={(el) => {
                                  if (el) itemRefs.current.set(f.id, el);
                                  else itemRefs.current.delete(f.id);
                                }}
                                aria-current={isSel ? "true" : undefined}
                                onClick={() => {
                                  setSelectedId(f.id);
                                  setNavIndex(idx);
                                }}
                                data-testid="finding-item"
                                className={cn(
                                  "bg-card hover:bg-muted/60 focus-visible:ring-ring relative grid w-full gap-1 overflow-hidden rounded-lg border py-2 pr-2.5 pl-3.5 text-left text-sm transition-colors focus-visible:ring-2 focus-visible:outline-none",
                                  (isSel || navIndex === idx) &&
                                    "bg-accent hover:bg-accent border-[color-mix(in_oklch,var(--primary)_55%,var(--border))]",
                                )}
                              >
                                <span
                                  aria-hidden
                                  className="absolute inset-y-0 left-0 w-1"
                                  style={{ background: SEVERITY_COLOR[f.severity] }}
                                />
                                <span className="flex min-w-0 items-center gap-1.5">
                                  <SeverityBadge severity={f.severity} />
                                  <span className="truncate font-medium">{f.title}</span>
                                </span>
                                <span className="text-muted-foreground flex min-w-0 items-center gap-1.5 text-xs">
                                  <span className="truncate">{f.rule}</span>
                                  <span aria-hidden>·</span>
                                  <span className="truncate font-mono">
                                    {f.attack_techniques.join(", ") || "no technique"}
                                  </span>
                                  <span className="tabular ml-auto shrink-0">
                                    {f.event_ids.length} event{f.event_ids.length === 1 ? "" : "s"}
                                  </span>
                                </span>
                              </button>
                            </li>
                          );
                        })}
                      </ul>
                    </section>
                  ))}
                </nav>
                <Card className="min-w-0 self-start">
                  <CardContent>
                    {selected ? (
                      <FindingDetail key={selected.id} caseId={caseId} finding={selected} access={access} />
                    ) : (
                      <EmptyState title="No findings match the filters" icon={SearchXIcon}>
                        Clear the severity, rule or technique filter to see more.
                      </EmptyState>
                    )}
                  </CardContent>
                </Card>
              </div>
            )}
          </QueryStatus>
        </TabsContent>
        <TabsContent value="hypotheses">
          <Hypotheses caseId={caseId} access={access} />
        </TabsContent>
        <TabsContent value="tasks">
          <TasksBoard caseId={caseId} access={access} members={kase?.members ?? []} />
        </TabsContent>
      </Tabs>

      <Dialog open={manualOpen} onOpenChange={setManualOpen}>
        <DialogContent className="max-w-xl">
          <form onSubmit={submitManual} className="grid gap-3">
            <DialogHeader>
              <DialogTitle>Manual finding</DialogTitle>
              <DialogDescription>
                Created as proposed; it still needs examiner confirmation and independent approval.
              </DialogDescription>
            </DialogHeader>
            <Field label="Title" htmlFor="mf-title">
              <Input id="mf-title" value={mTitle} onChange={(e) => setMTitle(e.target.value)} autoFocus />
            </Field>
            <Field label="Description" htmlFor="mf-desc">
              <Textarea id="mf-desc" value={mDesc} onChange={(e) => setMDesc(e.target.value)} />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Severity" htmlFor="mf-sev">
                <NativeSelect id="mf-sev" value={mSev} onChange={(e) => setMSev(e.target.value as Severity)}>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </NativeSelect>
              </Field>
              <Field label="Category" htmlFor="mf-cat">
                <Input id="mf-cat" value={mCat} onChange={(e) => setMCat(e.target.value)} />
              </Field>
            </div>
            <Field
              label="ATT&CK techniques"
              htmlFor="mf-tech"
              hint="Space or comma separated, e.g. T1021.002 T1078"
            >
              <Input
                id="mf-tech"
                value={mTech}
                onChange={(e) => setMTech(e.target.value)}
                aria-describedby="mf-tech-hint"
              />
            </Field>
            <div className="grid gap-1.5">
              <Label htmlFor="mf-events">Supporting event ids</Label>
              <Input
                id="mf-events"
                value={mEvents}
                onChange={(e) => setMEvents(e.target.value)}
                inputMode="numeric"
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setManualOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={!mTitle.trim() || !mDesc.trim() || manual.isPending}>
                Propose finding
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
