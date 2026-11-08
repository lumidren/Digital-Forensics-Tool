"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ActivityIcon,
  BriefcaseIcon,
  CalendarIcon,
  FlagIcon,
  FolderOpenIcon,
  HardDriveIcon,
  LockIcon,
  PlusIcon,
  UserIcon,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { PageHeader, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { Field } from "@/components/ui/label";
import { EmptyState } from "@/components/ui/misc";
import { useHotkeys } from "@/hooks/use-hotkeys";
import { useTableNav } from "@/hooks/use-table-nav";
import { api } from "@/lib/api-instance";
import { compactNumber } from "@/lib/charts";
import { formatDate } from "@/lib/format";
import type { CaseListItem } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATUS_VARIANT: Record<CaseListItem["status"], "success" | "warning" | "muted"> = {
  open: "success",
  review: "warning",
  closed: "muted",
  disposed: "muted",
};

function MiniStat({
  icon: Icon,
  label,
  value,
  title,
}: {
  icon: typeof HardDriveIcon;
  label: string;
  value: string;
  title: string;
}) {
  return (
    <div className="bg-muted/40 rounded-md border px-2 py-1.5" title={title}>
      <dt className="text-muted-foreground flex items-center gap-1 text-[11px]">
        <Icon aria-hidden className="size-3" />
        {label}
      </dt>
      <dd className="tabular text-base leading-tight font-semibold">{value}</dd>
    </div>
  );
}

export function CasesPage() {
  const router = useRouter();
  const qc = useQueryClient();
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.listCases() });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [timezone, setTimezone] = useState("");
  const rows = cases.data ?? [];
  const rowRefs = useRef<(HTMLAnchorElement | null)[]>([]);
  const openCount = rows.filter((c) => c.status === "open").length;
  const totalEvents = rows.reduce((s, c) => s + c.event_count, 0);
  const totalFindings = rows.reduce((s, c) => s + c.finding_count, 0);

  const openCase = (i: number) => {
    const c = rows[i];
    if (c) router.push(`/cases/${encodeURIComponent(c.id)}`);
  };
  const { selected } = useTableNav(rows.length, {
    onOpen: openCase,
    onSelect: (i) => rowRefs.current[i]?.focus(),
  });
  useHotkeys({ n: () => setOpen(true) });

  const create = useMutation({
    mutationFn: () =>
      api.createCase({
        name: name.trim(),
        description: description.trim(),
        timezone: timezone.trim() || null,
      }),
    onSuccess: async (c) => {
      toast.success(`Case ${c.id} created`);
      setOpen(false);
      setName("");
      setDescription("");
      setTimezone("");
      await qc.invalidateQueries({ queryKey: ["cases"] });
      await qc.invalidateQueries({ queryKey: ["me"] });
      router.push(`/cases/${encodeURIComponent(c.id)}`);
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (name.trim()) create.mutate();
  };

  return (
    <>
      <PageHeader
        icon={BriefcaseIcon}
        title="Cases"
        description="Cases you are a member of. Press J/K to move, Enter to open, N for a new case."
        actions={
          <Button onClick={() => setOpen(true)} aria-keyshortcuts="n">
            <PlusIcon aria-hidden /> New case
          </Button>
        }
      />
      <QueryStatus isLoading={cases.isLoading} error={cases.error}>
        {rows.length === 0 ? (
          <EmptyState title="No cases yet" icon={FolderOpenIcon}>
            Create a case to start intake.
          </EmptyState>
        ) : (
          <div className="grid gap-4">
            <p className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-sm">
              <span>
                <span className="text-foreground tabular font-semibold">{rows.length}</span> case
                {rows.length === 1 ? "" : "s"}
              </span>
              <span>
                <span className="text-foreground tabular font-semibold">{openCount}</span> open
              </span>
              <span>
                <span className="text-foreground tabular font-semibold">{totalEvents.toLocaleString()}</span>{" "}
                events indexed
              </span>
              <span>
                <span className="text-foreground tabular font-semibold">{totalFindings}</span> findings
              </span>
            </p>
            <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label="Cases">
              {rows.map((c, i) => (
                <li
                  key={c.id}
                  aria-current={selected === i ? "true" : undefined}
                  className={cn(
                    "bg-card group relative grid gap-3 rounded-xl border p-4 shadow-[0_1px_2px_0_rgb(0_0_0/0.04)] transition-[border-color,box-shadow] hover:border-[color-mix(in_oklch,var(--primary)_40%,var(--border))] hover:shadow-md",
                    "has-[a:focus-visible]:ring-ring has-[a:focus-visible]:ring-2",
                    selected === i && "border-primary",
                  )}
                >
                  <div className="flex items-start gap-3">
                    <span className="bg-brand-gradient grid size-9 shrink-0 place-items-center rounded-lg text-white shadow-sm">
                      <BriefcaseIcon aria-hidden className="size-4.5" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <h2 className="truncate font-semibold tracking-tight" title={c.name}>
                        {c.name}
                      </h2>
                      <Link
                        ref={(el) => {
                          rowRefs.current[i] = el;
                        }}
                        href={`/cases/${encodeURIComponent(c.id)}`}
                        className="text-primary font-mono text-xs outline-none after:absolute after:inset-0 after:rounded-xl hover:underline"
                      >
                        {c.id}
                      </Link>
                    </div>
                    <div className="relative flex flex-col items-end gap-1">
                      <Badge variant={STATUS_VARIANT[c.status]}>{c.status}</Badge>
                      {c.legal_hold ? (
                        <Badge variant="warning">
                          <LockIcon aria-hidden /> legal hold
                        </Badge>
                      ) : null}
                    </div>
                  </div>
                  {c.description ? (
                    <p className="text-muted-foreground line-clamp-2 text-sm">{c.description}</p>
                  ) : null}
                  <dl className="grid grid-cols-3 gap-2">
                    <MiniStat
                      icon={HardDriveIcon}
                      label="Evidence"
                      value={String(c.evidence_count)}
                      title={`${c.evidence_count} evidence items`}
                    />
                    <MiniStat
                      icon={ActivityIcon}
                      label="Events"
                      value={compactNumber(c.event_count)}
                      title={`${c.event_count.toLocaleString()} timeline events`}
                    />
                    <MiniStat
                      icon={FlagIcon}
                      label="Findings"
                      value={String(c.finding_count)}
                      title={`${c.finding_count} findings`}
                    />
                  </dl>
                  <p className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                    <span className="flex items-center gap-1">
                      <CalendarIcon aria-hidden className="size-3" />
                      {formatDate(c.created)}
                    </span>
                    <span className="flex items-center gap-1">
                      <UserIcon aria-hidden className="size-3" />
                      {c.created_by}
                    </span>
                    {c.timezone ? <span>{c.timezone}</span> : null}
                  </p>
                </li>
              ))}
            </ul>
          </div>
        )}
      </QueryStatus>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <form onSubmit={submit} className="grid gap-4">
            <DialogHeader>
              <DialogTitle>New case</DialogTitle>
              <DialogDescription>
                You become the case lead. A custody ledger is created and signed with your key.
              </DialogDescription>
            </DialogHeader>
            <Field label="Name" htmlFor="case-name">
              <Input
                id="case-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                maxLength={300}
                autoFocus
              />
            </Field>
            <Field label="Description" htmlFor="case-desc">
              <Textarea id="case-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
            </Field>
            <Field
              label="Case timezone (IANA, optional)"
              htmlFor="case-tz"
              hint="Display preference only; all times are stored in UTC."
            >
              <Input
                id="case-tz"
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                placeholder="Europe/Berlin"
                aria-describedby="case-tz-hint"
              />
            </Field>
            <DialogFooter>
              <Button variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={!name.trim() || create.isPending}>
                {create.isPending ? "Creating…" : "Create case"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
