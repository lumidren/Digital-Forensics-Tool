"use client";

import { useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useMemo, useState } from "react";
import { PageHeader, QueryStatus } from "@/components/common";
import type { FlowEdgeSpec, FlowNodeSpec } from "@/components/flow-graph";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCase } from "@/hooks/use-case";
import { api } from "@/lib/api-instance";
import { formatNs } from "@/lib/format";
import type { LateralGraph, ProvenanceNode } from "@/lib/types";

const FlowGraph = dynamic(() => import("@/components/flow-graph").then((m) => m.FlowGraph), {
  ssr: false,
  loading: () => <Skeleton className="h-[460px] w-full" />,
});

export function lateralToFlow(g: LateralGraph): { nodes: FlowNodeSpec[]; edges: FlowEdgeSpec[] } {
  const strong = new Set(g.edges.filter((e) => e.kind !== "failed_logon").flatMap((e) => [e.src, e.dst]));
  return {
    nodes: g.nodes.map((n) => ({
      id: n.id,
      label: n.id,
      tone: n.id === "remote" ? "muted" : strong.has(n.id) ? "default" : "muted",
    })),
    edges: g.edges.map((e, i) => ({
      id: `e${i}`,
      source: e.src,
      target: e.dst,
      label: `${e.kind} · ${e.technique}${e.user ? ` · ${e.user}` : ""} (${e.count})`,
    })),
  };
}

export function provenanceToFlow(n: ProvenanceNode): { nodes: FlowNodeSpec[]; edges: FlowEdgeSpec[] } {
  const nodes: FlowNodeSpec[] = [{ id: n.path, label: n.path.split("\\").pop() || n.path, tone: "danger" }];
  const edges: FlowEdgeSpec[] = [];
  if (n.origin) {
    nodes.unshift({ id: `origin:${n.origin}`, label: n.origin, tone: "muted" });
    edges.push({
      id: "origin",
      source: `origin:${n.origin}`,
      target: n.path,
      label: n.origin_kind ?? "origin",
    });
  }
  for (const [action, ids] of Object.entries(n.events)) {
    nodes.push({ id: `action:${action}`, label: `${action} (${ids.length})` });
    edges.push({ id: `a:${action}`, source: n.path, target: `action:${action}`, label: action });
  }
  return { nodes, edges };
}

export function GraphPage() {
  const { caseId } = useCase();
  const enc = encodeURIComponent(caseId);
  const lateral = useQuery({ queryKey: ["lateral", caseId], queryFn: () => api.lateral(caseId) });
  const provenance = useQuery({ queryKey: ["provenance", caseId], queryFn: () => api.provenance(caseId) });
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const lateralFlow = useMemo(() => (lateral.data ? lateralToFlow(lateral.data) : null), [lateral.data]);
  const provNodes = provenance.data ?? [];
  const selected =
    provNodes.find((p) => p.path === selectedPath) ?? provNodes.find((p) => p.origin_kind) ?? provNodes[0];
  const provFlow = useMemo(() => (selected ? provenanceToFlow(selected) : null), [selected]);
  const eventsLink = (ids: number[]) => `/cases/${enc}/timeline?event=${ids[0] ?? ""}`;

  return (
    <>
      <PageHeader
        title="Graphs"
        description="Lateral movement between hosts and file provenance, each with a table view."
      />
      <Tabs defaultValue="lateral">
        <TabsList>
          <TabsTrigger value="lateral">Lateral movement</TabsTrigger>
          <TabsTrigger value="provenance">File provenance</TabsTrigger>
        </TabsList>
        <TabsContent value="lateral">
          <QueryStatus isLoading={lateral.isLoading} error={lateral.error}>
            {!lateral.data?.edges.length || !lateralFlow ? (
              <EmptyState title="No lateral movement edges">
                Built from 4624, 4648, 7045, 4698, RDP, WMI and SMB share events.
              </EmptyState>
            ) : (
              <div className="grid gap-4">
                <FlowGraph
                  nodes={lateralFlow.nodes}
                  edges={lateralFlow.edges}
                  label="Lateral movement graph; the table below lists the same edges"
                />
                <Card>
                  <CardHeader>
                    <CardTitle>Edges</CardTitle>
                  </CardHeader>
                  <Table data-testid="lateral-table">
                    <TableCaption>
                      Directed edges from source to destination host, one row per technique and user.
                    </TableCaption>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Source</TableHead>
                        <TableHead scope="col">Destination</TableHead>
                        <TableHead scope="col">User</TableHead>
                        <TableHead scope="col">Kind</TableHead>
                        <TableHead scope="col">ATT&amp;CK</TableHead>
                        <TableHead scope="col" className="text-right">
                          Events
                        </TableHead>
                        <TableHead scope="col">First seen</TableHead>
                        <TableHead scope="col">Last seen</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {lateral.data.edges.map((e, i) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-xs">{e.src}</TableCell>
                          <TableCell className="font-mono text-xs">{e.dst}</TableCell>
                          <TableCell>{e.user || "—"}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{e.kind}</Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{e.technique}</TableCell>
                          <TableCell className="text-right">
                            <Link className="text-primary underline" href={eventsLink(e.event_ids)}>
                              {e.count}
                            </Link>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{formatNs(e.first_ns)}</TableCell>
                          <TableCell className="font-mono text-xs">{formatNs(e.last_ns)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              </div>
            )}
          </QueryStatus>
        </TabsContent>
        <TabsContent value="provenance">
          <QueryStatus isLoading={provenance.isLoading} error={provenance.error}>
            {!provNodes.length ? (
              <EmptyState title="No provenance records">
                Built from browser downloads, Zone.Identifier, email attachments, USN, prefetch and LNK.
              </EmptyState>
            ) : (
              <div className="grid gap-4">
                {provFlow && selected ? (
                  <FlowGraph
                    nodes={provFlow.nodes}
                    edges={provFlow.edges}
                    height={320}
                    label={`Provenance of ${selected.path}`}
                  />
                ) : null}
                <Card>
                  <CardHeader>
                    <CardTitle>Files</CardTitle>
                  </CardHeader>
                  <Table data-testid="provenance-table">
                    <TableCaption>Files with a known origin or more than one recorded action.</TableCaption>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Path</TableHead>
                        <TableHead scope="col">Origin</TableHead>
                        <TableHead scope="col">Actions</TableHead>
                        <TableHead scope="col">First seen</TableHead>
                        <TableHead scope="col">
                          <span className="sr-only">Graph</span>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {provNodes.map((p) => (
                        <TableRow key={p.path} aria-selected={selected?.path === p.path}>
                          <TableCell className="max-w-[24rem] font-mono text-xs break-all">
                            {p.path}
                          </TableCell>
                          <TableCell className="max-w-[20rem] text-xs break-all">
                            {p.origin_kind ? <Badge variant="warning">{p.origin_kind}</Badge> : "—"}{" "}
                            {p.origin}
                          </TableCell>
                          <TableCell>
                            <ul className="flex flex-wrap gap-1">
                              {Object.entries(p.events).map(([k, ids]) => (
                                <li key={k}>
                                  <Link href={eventsLink(ids)} className="text-primary text-xs underline">
                                    {k} ({ids.length})
                                  </Link>
                                </li>
                              ))}
                            </ul>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{formatNs(p.first_ns)}</TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setSelectedPath(p.path)}
                              aria-pressed={selected?.path === p.path}
                            >
                              Show graph
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              </div>
            )}
          </QueryStatus>
        </TabsContent>
      </Tabs>
    </>
  );
}
