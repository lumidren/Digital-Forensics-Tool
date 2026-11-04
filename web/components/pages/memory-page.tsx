"use client";

import { useQuery } from "@tanstack/react-query";
import { ChevronDownIcon, ChevronRightIcon } from "lucide-react";
import Link from "next/link";
import { useMemo, useState, type KeyboardEvent } from "react";
import { PageHeader, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/misc";
import { useCase } from "@/hooks/use-case";
import { api } from "@/lib/api-instance";
import { formatNs } from "@/lib/format";
import { buildProcessTree, flattenTree, type ProcessFlag } from "@/lib/memory";
import { cn } from "@/lib/utils";

const FLAG_LABEL: Record<ProcessFlag, string> = {
  malfind: "malfind",
  hollowing: "hollowing",
  hidden: "hidden",
  orphan: "orphan",
};

const MEMORY_TYPES = ["memory:process", "memory:injection", "memory:network:connection"];

export function MemoryPage() {
  const { caseId } = useCase();
  const enc = encodeURIComponent(caseId);
  const events = useQuery({
    queryKey: ["memory-events", caseId],
    queryFn: () => api.search(caseId, { data_types: MEMORY_TYPES, include_untimed: true, limit: 5000 }),
  });
  const tree = useMemo(() => buildProcessTree(events.data?.events ?? []), [events.data]);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const rows = flattenTree(tree.roots, (pid) => !collapsed.has(pid));
  const [active, setActive] = useState(0);

  const toggle = (pid: number) =>
    setCollapsed((c) => {
      const n = new Set(c);
      if (n.has(pid)) n.delete(pid);
      else n.add(pid);
      return n;
    });

  const focusRow = (i: number) => {
    const clamped = Math.max(0, Math.min(rows.length - 1, i));
    setActive(clamped);
    document.querySelector<HTMLElement>(`[data-proc-row="${clamped}"]`)?.focus();
  };

  const onKeyDown = (e: KeyboardEvent, i: number) => {
    const row = rows[i];
    if (!row) return;
    const hasKids = row.node.children.length > 0;
    const open = hasKids && !collapsed.has(row.node.pid);
    switch (e.key) {
      case "ArrowDown":
      case "j":
        e.preventDefault();
        focusRow(i + 1);
        break;
      case "ArrowUp":
      case "k":
        e.preventDefault();
        focusRow(i - 1);
        break;
      case "ArrowRight":
        e.preventDefault();
        if (hasKids && !open) toggle(row.node.pid);
        else if (open) focusRow(i + 1);
        break;
      case "ArrowLeft":
        e.preventDefault();
        if (open) toggle(row.node.pid);
        else {
          const parent = rows.findIndex((r) => r.node.pid === row.node.ppid);
          if (parent >= 0) focusRow(parent);
        }
        break;
      case "Home":
        e.preventDefault();
        focusRow(0);
        break;
      case "End":
        e.preventDefault();
        focusRow(rows.length - 1);
        break;
      default:
    }
  };

  const truncated = (events.data?.total ?? 0) > (events.data?.events.length ?? 0);

  return (
    <>
      <PageHeader
        title="Memory analysis"
        description="Process tree from Volatility process listings, with injection, hollowing and hidden-process flags."
      />
      <QueryStatus isLoading={events.isLoading} error={events.error}>
        {tree.byPid.size === 0 ? (
          <EmptyState title="No memory process events">
            Upload and process a memory image to populate this view.
          </EmptyState>
        ) : (
          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
            <Card aria-labelledby="proc-tree">
              <CardHeader>
                <CardTitle id="proc-tree">Process tree ({tree.byPid.size} processes)</CardTitle>
                {truncated ? (
                  <span className="text-warning text-xs">Showing the first 5,000 memory events.</span>
                ) : null}
              </CardHeader>
              <CardContent className="overflow-x-auto p-0">
                <div
                  role="treegrid"
                  aria-label="Process tree"
                  aria-rowcount={rows.length}
                  className="min-w-[44rem] text-sm"
                >
                  <div
                    role="row"
                    className="bg-muted text-muted-foreground grid grid-cols-[minmax(16rem,1fr)_5rem_5rem_14rem_10rem] gap-2 border-b px-3 py-1.5 text-xs"
                  >
                    <span role="columnheader">Process</span>
                    <span role="columnheader">PID</span>
                    <span role="columnheader">PPID</span>
                    <span role="columnheader">Created (UTC)</span>
                    <span role="columnheader">Flags</span>
                  </div>
                  {rows.map(({ node, depth }, i) => {
                    const hasKids = node.children.length > 0;
                    const expanded = hasKids ? !collapsed.has(node.pid) : undefined;
                    return (
                      <div
                        key={node.pid}
                        role="row"
                        aria-level={depth + 1}
                        aria-expanded={expanded}
                        aria-rowindex={i + 1}
                        tabIndex={i === active ? 0 : -1}
                        data-proc-row={i}
                        onKeyDown={(e) => onKeyDown(e, i)}
                        onFocus={() => setActive(i)}
                        className={cn(
                          "focus-visible:ring-ring grid grid-cols-[minmax(16rem,1fr)_5rem_5rem_14rem_10rem] items-center gap-2 border-b px-3 py-1 outline-none focus-visible:ring-2 focus-visible:ring-inset",
                          node.flags.some((f) => f !== "orphan") && "bg-destructive/10",
                        )}
                      >
                        <span
                          role="gridcell"
                          className="flex min-w-0 items-center gap-1"
                          style={{ paddingLeft: `${depth * 1.1}rem` }}
                        >
                          {hasKids ? (
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              className="size-6"
                              tabIndex={-1}
                              aria-label={expanded ? `Collapse ${node.name}` : `Expand ${node.name}`}
                              onClick={() => toggle(node.pid)}
                            >
                              {expanded ? <ChevronDownIcon aria-hidden /> : <ChevronRightIcon aria-hidden />}
                            </Button>
                          ) : (
                            <span className="w-6" />
                          )}
                          <span className="truncate font-mono text-xs">{node.name || "(unnamed)"}</span>
                          {node.connections ? (
                            <span className="text-muted-foreground text-xs">· {node.connections} conn</span>
                          ) : null}
                        </span>
                        <span role="gridcell" className="tabular">
                          {node.pid}
                        </span>
                        <span role="gridcell" className="tabular">
                          {node.ppid ?? "—"}
                        </span>
                        <span role="gridcell" className="font-mono text-xs">
                          {formatNs(node.createNs)}
                        </span>
                        <span role="gridcell" className="flex flex-wrap gap-1">
                          {node.flags.map((f) => (
                            <Badge key={f} variant={f === "orphan" ? "outline" : "destructive"}>
                              {FLAG_LABEL[f]}
                            </Badge>
                          ))}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
            <Card aria-labelledby="proc-flagged">
              <CardHeader>
                <CardTitle id="proc-flagged">Flagged processes</CardTitle>
              </CardHeader>
              <CardContent>
                {tree.flagged.length ? (
                  <ul className="grid gap-2 text-sm">
                    {tree.flagged.map((n) => (
                      <li key={n.pid} className="rounded-md border p-2">
                        <p className="font-mono text-xs">
                          {n.name} (PID {n.pid})
                        </p>
                        <p className="mt-1 flex flex-wrap gap-1">
                          {n.flags.map((f) => (
                            <Badge key={f} variant={f === "orphan" ? "outline" : "destructive"}>
                              {FLAG_LABEL[f]}
                            </Badge>
                          ))}
                        </p>
                        <Link
                          className="text-primary mt-1 inline-block text-xs underline"
                          href={`/cases/${enc}/timeline?attr=${encodeURIComponent(`PID=${n.pid}`)}`}
                        >
                          Events for PID {n.pid}
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-muted-foreground text-sm">
                    No injection, hollowing or hidden-process indicators.
                  </p>
                )}
                <p className="text-muted-foreground mt-3 text-xs">
                  Hidden = found by pool scanning (psscan) but not in the active process list (pslist). Orphan
                  = parent PID not observed (often benign for long-running systems).
                </p>
              </CardContent>
            </Card>
          </div>
        )}
      </QueryStatus>
    </>
  );
}
