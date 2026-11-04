"use client";

import { useQuery } from "@tanstack/react-query";
import { FileSearchIcon, ListIcon, NetworkIcon, WaypointsIcon } from "lucide-react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useMemo, useState } from "react";
import { PageHeader, QueryStatus } from "@/components/common";
import {
  LegendNodeKind,
  LegendSwatch,
  NODE_KIND_META,
  type FlowEdgeSpec,
  type FlowNodeSpec,
} from "@/components/graph-legend";
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
import { attackUrl, tacticColor, tacticName, techniqueInfo } from "@/lib/attack";
import { formatNs } from "@/lib/format";
import { aggregateEdges, classifyHost, edgeFamily, hostKindLabel } from "@/lib/graph";
import type { LateralGraph, ProvenanceNode } from "@/lib/types";

const FlowGraph = dynamic(() => import("@/components/flow-graph").then((m) => m.FlowGraph), {
  ssr: false,
  loading: () => <Skeleton className="h-[440px] w-full rounded-xl" />,
});

export function lateralToFlow(g: LateralGraph): { nodes: FlowNodeSpec[]; edges: FlowEdgeSpec[] } {
  const agg = aggregateEdges(g.edges);
  const strong = new Set(g.edges.filter((e) => e.kind !== "failed_logon").flatMap((e) => [e.src, e.dst]));
  const degree = new Map<string, number>();
  for (const e of agg) {
    degree.set(e.src, (degree.get(e.src) ?? 0) + 1);
    degree.set(e.dst, (degree.get(e.dst) ?? 0) + 1);
  }
  return {
    nodes: g.nodes.map((n) => {
      const kind = classifyHost(n.id);
      const d = degree.get(n.id) ?? 0;
      return {
        id: n.id,
        label: n.id,
        kind,
        sublabel: `${hostKindLabel(n.id)} · ${d} link${d === 1 ? "" : "s"}`,
        tone: kind === "remote" || !strong.has(n.id) ? "muted" : "default",
      };
    }),
    edges: agg.map((e) => ({
      id: e.id,
      source: e.src,
      target: e.dst,
      color: tacticColor(e.family),
      badge: String(e.count),
      label: `${e.src} → ${e.dst}: ${e.count} event${e.count === 1 ? "" : "s"}`,
      details: [
        e.techniques.map((t) => `${t} ${techniqueInfo(t).short}`).join(", ") || "no technique",
        `kind: ${e.kinds.join(", ")}`,
        ...(e.users.length ? [`user: ${e.users.join(", ")}`] : []),
      ],
    })),
  };
}

function originKind(origin: string, kind: string | null): FlowNodeSpec["kind"] {
  if (/mail|attachment|outlook|eml/i.test(kind ?? "") || origin.includes("@")) return "mail";
  return "origin";
}

export function provenanceToFlow(n: ProvenanceNode): { nodes: FlowNodeSpec[]; edges: FlowEdgeSpec[] } {
  const fileName = n.path.split(/[\/]/).pop() || n.path;
  const nodes: FlowNodeSpec[] = [
    { id: n.path, label: fileName, kind: "file", sublabel: "File", tone: "danger" },
  ];
  const edges: FlowEdgeSpec[] = [];
  if (n.origin) {
    const id = `origin:${n.origin}`;
    nodes.unshift({
      id,
      label: n.origin,
      kind: originKind(n.origin, n.origin_kind),
      sublabel: n.origin_kind ?? "origin",
    });
    edges.push({
      id: "origin",
      source: id,
      target: n.path,
      label: `${n.origin_kind ?? "origin"}: ${n.origin}`,
      badge: n.origin_kind ?? "origin",
      color: "var(--cat-4)",
    });
  }
  for (const [action, ids] of Object.entries(n.events)) {
    nodes.push({
      id: `action:${action}`,
      label: action,
      kind: "action",
      sublabel: `${ids.length} event${ids.length === 1 ? "" : "s"}`,
    });
    edges.push({
      id: `a:${action}`,
      source: n.path,
      target: `action:${action}`,
      label: `${action}: ${ids.length} event${ids.length === 1 ? "" : "s"}`,
      badge: String(ids.length),
      color: "var(--cat-3)",
    });
  }
  return { nodes, edges };
}

function HostCell({ id }: { id: string }) {
  const Icon = NODE_KIND_META[classifyHost(id)].icon;
  return (
    <span className="inline-flex items-center gap-1.5" title={hostKindLabel(id)}>
      <Icon aria-hidden className="text-muted-foreground size-3.5" />
      {id}
    </span>
  );
}

export function GraphPage() {
  const { caseId } = useCase();
  const enc = encodeURIComponent(caseId);
  const lateral = useQuery({ queryKey: ["lateral", caseId], queryFn: () => api.lateral(caseId) });
  const provenance = useQuery({ queryKey: ["provenance", caseId], queryFn: () => api.provenance(caseId) });
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const lateralFlow = useMemo(() => (lateral.data ? lateralToFlow(lateral.data) : null), [lateral.data]);
  const lateralKinds = [...new Set((lateralFlow?.nodes ?? []).map((n) => n.kind))];
  const lateralFamilies = [...new Set(aggregateEdges(lateral.data?.edges ?? []).map((e) => e.family))];
  const provNodes = provenance.data ?? [];
  const selected =
    provNodes.find((p) => p.path === selectedPath) ?? provNodes.find((p) => p.origin_kind) ?? provNodes[0];
  const provFlow = useMemo(() => (selected ? provenanceToFlow(selected) : null), [selected]);
  const eventsLink = (ids: number[]) => `/cases/${enc}/timeline?event=${ids[0] ?? ""}`;

  return (
    <>
      <PageHeader
        icon={WaypointsIcon}
        title="Graphs"
        description="Lateral movement between hosts and file provenance, each with a table view."
      />
      <Tabs defaultValue="lateral">
        <TabsList>
          <TabsTrigger value="lateral" className="gap-1.5">
            <NetworkIcon aria-hidden className="size-4" /> Lateral movement
          </TabsTrigger>
          <TabsTrigger value="provenance" className="gap-1.5">
            <FileSearchIcon aria-hidden className="size-4" /> File provenance
          </TabsTrigger>
        </TabsList>
        <TabsContent value="lateral">
          <QueryStatus isLoading={lateral.isLoading} error={lateral.error}>
            {!lateral.data?.edges.length || !lateralFlow ? (
              <EmptyState title="No lateral movement edges" icon={NetworkIcon}>
                Built from 4624, 4648, 7045, 4698, RDP, WMI and SMB share events.
              </EmptyState>
            ) : (
              <div className="grid gap-4">
                <FlowGraph
                  nodes={lateralFlow.nodes}
                  edges={lateralFlow.edges}
                  label="Lateral movement graph; the table below lists the same edges"
                  legend={
                    <div className="text-muted-foreground flex flex-wrap items-center gap-x-4 gap-y-1.5">
                      <span className="text-foreground font-medium">Nodes</span>
                      {lateralKinds.map((k) => (
                        <LegendNodeKind key={k} kind={k} />
                      ))}
                      <span className="text-foreground font-medium sm:ml-3">Edges by tactic</span>
                      {lateralFamilies.map((f) => (
                        <LegendSwatch key={f} color={tacticColor(f)}>
                          {tacticName(f)}
                        </LegendSwatch>
                      ))}
                      <span className="sm:ml-auto">Badge = events · hover or select an edge for details</span>
                    </div>
                  }
                />
                <Card>
                  <CardHeader>
                    <CardTitle>
                      <ListIcon aria-hidden /> Edges
                    </CardTitle>
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
                          <TableCell className="font-mono text-xs">
                            <HostCell id={e.src} />
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            <HostCell id={e.dst} />
                          </TableCell>
                          <TableCell>{e.user || "—"}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{e.kind}</Badge>
                          </TableCell>
                          <TableCell className="text-xs">
                            {e.technique ? (
                              <a
                                href={attackUrl(e.technique)}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="inline-flex items-center gap-1.5 hover:underline"
                                title={techniqueInfo(e.technique).name}
                              >
                                <span
                                  aria-hidden
                                  className="size-2 rounded-full"
                                  style={{ background: tacticColor(edgeFamily([e.technique])) }}
                                />
                                <span className="font-mono">{e.technique}</span>
                                <span className="text-muted-foreground hidden xl:inline">
                                  {techniqueInfo(e.technique).short}
                                </span>
                              </a>
                            ) : (
                              "—"
                            )}
                          </TableCell>
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
              <EmptyState title="No provenance records" icon={FileSearchIcon}>
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
                    legend={
                      <div className="text-muted-foreground flex flex-wrap items-center gap-x-4 gap-y-1.5">
                        <LegendNodeKind kind="origin" />
                        <LegendNodeKind kind="file" />
                        <LegendNodeKind kind="action" />
                        <span className="min-w-0 truncate sm:ml-auto" title={selected.path}>
                          <span className="text-foreground font-medium">Selected:</span>{" "}
                          <span className="font-mono">{selected.path}</span>
                        </span>
                      </div>
                    }
                  />
                ) : null}
                <Card>
                  <CardHeader>
                    <CardTitle>
                      <FileSearchIcon aria-hidden /> Files
                    </CardTitle>
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
