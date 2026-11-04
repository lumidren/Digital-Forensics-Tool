"use client";

import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useTheme } from "next-themes";
import { useMemo } from "react";
import { layeredLayout } from "@/lib/graph";

export interface FlowNodeSpec {
  id: string;
  label: string;
  tone?: "default" | "danger" | "muted";
}

export interface FlowEdgeSpec {
  id: string;
  source: string;
  target: string;
  label: string;
}

const TONE: Record<NonNullable<FlowNodeSpec["tone"]>, string> = {
  default: "border-primary bg-card text-card-foreground",
  danger: "border-destructive bg-card text-destructive",
  muted: "border-border bg-muted text-foreground",
};

/** Layered, keyboard-focusable directed graph (React Flow). Pair it with a table alternative. */
export function FlowGraph({
  nodes,
  edges,
  label,
  height = 460,
  onNodeActivate,
}: {
  nodes: FlowNodeSpec[];
  edges: FlowEdgeSpec[];
  label: string;
  height?: number;
  onNodeActivate?: (id: string) => void;
}) {
  const { resolvedTheme } = useTheme();
  const flow = useMemo(() => {
    const pos = layeredLayout(
      nodes.map((n) => n.id),
      edges.map((e) => ({ src: e.source, dst: e.target })),
      { layerGap: 280, nodeGap: 80 },
    );
    const rfNodes: Node[] = nodes.map((n) => {
      const p = pos.get(n.id);
      return {
        id: n.id,
        position: { x: p?.x ?? 0, y: p?.y ?? 0 },
        data: { label: n.label },
        ariaLabel: n.label,
        className: `rounded-md border-2 px-2 py-1 text-xs font-medium shadow-xs ${TONE[n.tone ?? "default"]}`,
        style: { width: 200 },
        draggable: true,
        connectable: false,
      };
    });
    const rfEdges: Edge[] = edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      ariaLabel: `${e.source} to ${e.target}: ${e.label}`,
      markerEnd: { type: MarkerType.ArrowClosed },
      labelBgPadding: [4, 2] as [number, number],
      labelStyle: { fontSize: 10 },
    }));
    return { rfNodes, rfEdges };
  }, [nodes, edges]);

  return (
    <div style={{ height }} className="rounded-md border" role="group" aria-label={label}>
      <ReactFlow
        nodes={flow.rfNodes}
        edges={flow.rfEdges}
        colorMode={resolvedTheme === "dark" ? "dark" : "light"}
        fitView
        nodesConnectable={false}
        nodesFocusable
        edgesFocusable
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_e, n) => onNodeActivate?.(n.id)}
        minZoom={0.2}
      >
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
