"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PlusIcon } from "lucide-react";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useHotkeys } from "@/hooks/use-hotkeys";
import { useTableNav } from "@/hooks/use-table-nav";
import { api } from "@/lib/api-instance";
import { formatDate } from "@/lib/format";

export function CasesPage() {
  const router = useRouter();
  const qc = useQueryClient();
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.listCases() });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [timezone, setTimezone] = useState("");
  const rows = cases.data ?? [];
  const rowRefs = useRef<(HTMLTableRowElement | null)[]>([]);

  const openCase = (i: number) => {
    const c = rows[i];
    if (c) router.push(`/cases/${encodeURIComponent(c.id)}`);
  };
  const { selected, setSelected } = useTableNav(rows.length, {
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
          <EmptyState title="No cases yet">Create a case to start intake.</EmptyState>
        ) : (
          <div className="bg-card rounded-lg border">
            <Table aria-label="Cases" aria-rowcount={rows.length}>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Case</TableHead>
                  <TableHead scope="col">Name</TableHead>
                  <TableHead scope="col">Status</TableHead>
                  <TableHead scope="col" className="text-right">
                    Evidence
                  </TableHead>
                  <TableHead scope="col" className="text-right">
                    Events
                  </TableHead>
                  <TableHead scope="col" className="text-right">
                    Findings
                  </TableHead>
                  <TableHead scope="col">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((c, i) => (
                  <TableRow
                    key={c.id}
                    ref={(el) => {
                      rowRefs.current[i] = el;
                    }}
                    tabIndex={-1}
                    aria-selected={selected === i}
                    onClick={() => setSelected(i)}
                    onDoubleClick={() => openCase(i)}
                    className="cursor-default"
                  >
                    <TableCell className="font-mono text-xs">
                      <Link
                        href={`/cases/${encodeURIComponent(c.id)}`}
                        className="text-primary underline-offset-2 hover:underline"
                      >
                        {c.id}
                      </Link>
                    </TableCell>
                    <TableCell className="max-w-[24rem] truncate">{c.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{c.status}</Badge>
                      {c.legal_hold ? (
                        <Badge variant="warning" className="ml-1">
                          legal hold
                        </Badge>
                      ) : null}
                    </TableCell>
                    <TableCell className="tabular text-right">{c.evidence_count}</TableCell>
                    <TableCell className="tabular text-right">{c.event_count.toLocaleString()}</TableCell>
                    <TableCell className="tabular text-right">{c.finding_count}</TableCell>
                    <TableCell className="text-xs whitespace-nowrap">{formatDate(c.created)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
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
